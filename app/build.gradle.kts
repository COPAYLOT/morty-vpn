import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.variant.FilterConfiguration

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlinxSerialization)
    alias(libs.plugins.ksp)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.grgit)
    alias(libs.plugins.licensee)
    alias(libs.plugins.aboutlibraries)
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

licensee {
    allowedLicenses().forEach { allow(it) }
    allowedLicenseUrls().forEach { allowUrl(it) }
    allowDependency("com.github.T8RIN.QuickieExtended", "quickie-foss", "1.18.1") {
        because("FOSS library, but JitPack doesn't publish license metadata")
        allow("Apache-2.0")
    }

    allowDependency("com.github.topjohnwu.libsu", "core", "6.0.0") {
        because("FOSS library, but JitPack doesn't publish license metadata")
        allow("Apache-2.0")
    }
}

configure<ApplicationExtension> {
    // Keep namespace at the original package so R/BuildConfig classes stay at
    // com.zaneschepke.wireguardautotunnel.{R,BuildConfig} (source files import from there).
    // Only the installed applicationId (Play Store identity) is changed via APP_ID.
    namespace = "com.zaneschepke.wireguardautotunnel"
    compileSdk = Constants.TARGET_SDK

    androidResources { generateLocaleConfig = true }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    // fix okhttp proguard issue
    packaging { resources { pickFirsts.add("okhttp3/internal/publicsuffix/publicsuffixes.gz") } }

    splits {
        abi {
            val noSplits = providers.gradleProperty("noSplits").isPresent
            isEnable = !noSplits
            reset()
            include("armeabi-v7a", "arm64-v8a")
            isUniversalApk = !noSplits
        }
    }

    defaultConfig {
        applicationId = Constants.APP_ID
        minSdk = Constants.MIN_SDK
        targetSdk = Constants.TARGET_SDK
        versionCode = Constants.VERSION_CODE
        versionName = Constants.VERSION_NAME

        experimentalProperties["android.experimental.disableGitVersion"] = true

        sourceSets {
            getByName("debug").assets.directories += "$projectDir/schemas"
        }

        val languagesProvider = project.languageListProvider()
        val languagesArray = buildLanguagesArray(languagesProvider.get())
        buildConfigField("String[]", "LANGUAGES", "new String[]{ $languagesArray }")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }
    }

    signingConfigs {
        create(Constants.RELEASE) {
            storeFile = file(System.getenv("KEY_STORE_PATH") ?: "keystore/android_keystore.jks")
            storePassword =
                LocalProperties.get("SIGNING_STORE_PASSWORD")
                    ?: System.getenv("SIGNING_STORE_PASSWORD")
            keyAlias =
                LocalProperties.get("SIGNING_KEY_ALIAS") ?: System.getenv("SIGNING_KEY_ALIAS")
            keyPassword =
                LocalProperties.get("SIGNING_KEY_PASSWORD") ?: System.getenv("SIGNING_KEY_PASSWORD")
        }
        // Fallback signing config used when the real release keystore is
        // not available (e.g. local / CI builds without signing secrets).
        // Reuses the AGP-generated debug keystore at the standard location
        // (~/.android/debug.keystore). The standard Android debug keystore
        // credentials are well-known: storepass=android, keypass=android,
        // alias=androiddebugkey.
        create("releaseDebugSigned") {
            storeFile = file("${System.getProperty("user.home")}/.android/debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    // When the fallback signing config is selected and the AGP debug
    // keystore does not exist (because no debug variant has ever been
    // built on this machine), generate one using keytool so validateSigning
    // does not fail. Runs lazily, idempotent — re-runs are no-ops.
    tasks.matching { it.name == "validateSigningStandaloneRelease" }.configureEach {
        doFirst {
            val signConfig = android.signingConfigs.findByName("releaseDebugSigned") ?: return@doFirst
            val sf = signConfig.storeFile
            if (sf != null && !sf.exists()) {
                sf.parentFile?.mkdirs()
                val pw = signConfig.storePassword
                val alias = signConfig.keyAlias
                val kp = signConfig.keyPassword
                project.exec {
                    commandLine(
                        "keytool",
                        "-genkey",
                        "-noprompt",
                        "-keystore", sf.absolutePath,
                        "-alias", alias,
                        "-storepass", pw,
                        "-keypass", kp,
                        "-dname", "CN=Morty VPN Debug,O=Android,C=US",
                        "-validity", "10950",
                        "-keyalg", "RSA",
                        "-keysize", "2048",
                    )
                }
                logger.lifecycle(
                    "[morty] Generated fallback debug keystore at ${sf.absolutePath}",
                )
            }
        }
    }

    buildTypes {
        packaging.jniLibs.keepDebugSymbols.addAll(
            listOf("libwg-go.so", "libwg-quick.so", "libwg.so")
        )

        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Prefer the real release keystore (set via KEYSTORE/KEYSTORE_*
            // envs); fall back to the AGP-generated debug keystore when
            // the keystore file does not actually exist on disk (e.g. local
            // builds or CI runs without signing secrets). Just checking
            // System.getenv("KEY_STORE_PATH") is not enough because CI
            // workflows typically set that env var unconditionally to a
            // path that may not exist if the keystore secret was not
            // configured. This keeps `assembleRelease` installable for
            // dev/CI testing without compromising the build path used by
            // production builds that DO set the keystore secrets.
            signingConfig =
                if (System.getenv("KEY_STORE_PATH") != null &&
                    file(System.getenv("KEY_STORE_PATH")).exists()
                ) {
                    signingConfigs.getByName(Constants.RELEASE)
                } else {
                    signingConfigs.getByName("releaseDebugSigned")
                }
            manifestPlaceholders["providerAuthority"] = "${Constants.APP_NAME}.provider"
            buildConfigField("String", "FILE_PROVIDER_AUTHORITY", "\"${Constants.APP_NAME}.provider\"")
        }

        debug {
            applicationIdSuffix = ".debug"
            // Launcher label inherits from app/src/main/res/values/strings.xml ("Morty VPN").
            // No resValue override so debug shows the same name as release.
            isDebuggable = true
            manifestPlaceholders["providerAuthority"] = "${Constants.APP_NAME}.provider.debug"
            buildConfigField("String", "FILE_PROVIDER_AUTHORITY", "\"${Constants.APP_NAME}.provider.debug\"")
        }

        create(Constants.NIGHTLY) {
            initWith(buildTypes.getByName(Constants.RELEASE))
            applicationIdSuffix = ".nightly"
            // Launcher label inherits from app/src/main/res/values/strings.xml ("Morty VPN").
            manifestPlaceholders["providerAuthority"] = "${Constants.APP_NAME}.provider.nightly"
            buildConfigField("String", "FILE_PROVIDER_AUTHORITY", "\"${Constants.APP_NAME}.provider.nightly\"")
        }
    }

    flavorDimensions.add("type")
    productFlavors {
        create("fdroid") {
            dimension = "type"
            buildConfigField("String", "FLAVOR", "\"fdroid\"")
        }
        create("google") {
            dimension = "type"
            buildConfigField("String", "FLAVOR", "\"google\"")
        }
        create("standalone") {
            dimension = "type"
            buildConfigField("String", "FLAVOR", "\"standalone\"")
        }
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
    }

    buildFeatures {
        compose = true
        buildConfig = true
        resValues = true
    }
    packaging { resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" } }
}

androidComponents {
    onVariants { variant ->
        val isNightly = project.isNightlyBuild()

        if (isNightly) {
            variant.outputs.forEach { output ->

                output.versionCode.set(
                    output.versionCode.get() + project.getVersionCodeIncrement()
                )

                val currentVersion = output.versionName.get()
                val nextVersion = bumpToNextPatchVersion(currentVersion)
                val gitHash = project.getGitCommitHash()

                output.versionName.set("$nextVersion-nightly+git.$gitHash")
            }
        }

        val abiNameMap = mapOf(
            "armeabi-v7a" to "armv7",
            "arm64-v8a" to "arm64",
            "x86" to "x86",
            "x86_64" to "x64",
        )

        variant.outputs.forEach { output ->
            val abi = output.filters.find { it.filterType == FilterConfiguration.FilterType.ABI }?.identifier
            val flavorName = variant.productFlavors.joinToString("-") { it.second }
            val versionName = output.versionName.get()
            val baseFileName = "${Constants.APP_NAME}-${flavorName}-v${versionName}"

            val outputFileName = if (!abi.isNullOrEmpty()) {
                val shortAbiName = abiNameMap.getOrDefault(abi, abi)
                "${baseFileName}-${shortAbiName}.apk"
            } else {
                "${baseFileName}.apk"
            }

            output.outputFileName.set(outputFileName)
        }
    }
}

dependencies {
    implementation(project(":logcatter"))
    implementation(project(":networkmonitor"))
    implementation(project(":tunnel"))

    // Core foundations
    implementation(libs.bundles.androidx.core.full)
    implementation(libs.bundles.androidx.lifecycle.core)
    implementation(libs.bundles.androidx.appcompat)
    implementation(libs.bundles.androidx.storage)

    // Compose setup
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.androidx.compose.ui)
    implementation(libs.bundles.androidx.compose.material)
    implementation(libs.androidx.activity.compose)

    // Navigation
    implementation(libs.bundles.androidx.navigation3)
    implementation(libs.bundles.navigation.lifecycle)

    // Material and icons
    implementation(libs.bundles.google.material)
    implementation(libs.bundles.material.icons)

    // Database
    implementation(libs.bundles.androidx.room)
    implementation(libs.bundles.androidx.datastore)
    ksp(libs.androidx.room.compiler)

    implementation(libs.bundles.androidx.work)

    // Networking and serialization
    implementation(libs.bundles.ktor.client)
    implementation(libs.bundles.kotlinx.serialization)
    implementation(libs.ipaddress)

    // State management
    implementation(libs.bundles.orbit.mvi)

    // Shizuku
    implementation(libs.bundles.shizuku)

    // UI utilities
    implementation(libs.bundles.ui.utilities)
    implementation(libs.lottie.compose)
    implementation(libs.sonner)
    implementation(libs.aboutlibraries.compose)

    // Misc utilities
    implementation(libs.bundles.misc.utilities)
    coreLibraryDesugaring(libs.desugar.jdk.libs)

    // Accompanist
    implementation(libs.bundles.accompanist)

    // Lifecycle Compose
    implementation(libs.lifecycle.runtime.compose)

    // Testing
    testImplementation(libs.junit)
    testImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test)
    androidTestImplementation(libs.androidx.room.testing)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.manifest)

    debugImplementation(libs.leakcanary.android)

    // Room database backup
    implementation(libs.roomdatabasebackup) {
        exclude(group = "org.reactivestreams", module = "reactive-streams")
    }

    // Ed25519/X25519 crypto for Proton VPN key generation
    implementation(libs.bouncycastleProv)

    // DI
    implementation(platform(libs.koin.bom))
    implementation(libs.koin.core)
    implementation(libs.koin.android)
    implementation(libs.koin.compose.viewmodel)
    implementation(libs.koin.androidx.compose)
    implementation(libs.koin.androidx.navigation)
    implementation(libs.koin.lazy)
    implementation(libs.koin.worker)
}

// https://gist.github.com/obfusk/61046e09cee352ae6dd109911534b12e#fix-proposed-by-linsui-disable-baseline-profiles
tasks.configureEach {
    if (name.contains("ArtProfile")) {
        enabled = false
    }
}
