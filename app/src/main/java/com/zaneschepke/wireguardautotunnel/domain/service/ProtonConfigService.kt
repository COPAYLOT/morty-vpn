package com.zaneschepke.wireguardautotunnel.domain.service

import android.util.Base64
import com.zaneschepke.wireguardautotunnel.data.crypto.ProtonCrypto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonCertificateDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonCertificateRequestDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonChallengeFrame
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonChallengePayload
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonLogicalServerDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonLogicalServersDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonSessionDto
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.util.extensions.saveTunnelsUniquely
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HeadersBuilder
import io.ktor.http.contentType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * Mirrors `download_all_countries.py`.
 *
 * Flow:
 *   1. credentialLess anonymous login (Phase 0 + Phase 1)
 *   2. GET /vpn/v1/logicals
 *   3. Pick best (lowest Load) free server per country
 *   4. Generate fresh Ed25519 keypair; derive X25519 priv via SHA-512
 *   5. POST /vpn/v1/certificate (1 year, persistent)
 *   6. Build a WireGuard [Interface]/[Peer] .conf per country and save
 *
 * Each request sets ONLY the headers Proton actually requires: User-Agent,
 * Accept: application/vnd.protonmail.v1+json, x-pm-appversion, x-pm-locale,
 * and — for authenticated calls — x-pm-uid + Authorization: Bearer.
 * Content-Type is set automatically by Ktor's ContentNegotiation plugin
 * when `setBody(DTO)` is used (we never manually set it).
 */
class ProtonConfigService(
    private val httpClient: HttpClient,
    private val tunnelRepository: TunnelRepository,
) {
    companion object {
        private const val API_HOST = "https://api.protonvpn.ch"
        private const val API_PREFIX = "/api"
        private const val CHALLENGE_FRAME_KEY = "vpn-android-v4-challenge-0"
        private const val CERT_MODE = "persistent"
        private const val DEVICE_NAME = "morty_vpn"
        private const val WG_PORT = 51820
        private const val APP_VERSION = "android-vpn@5.0.0"
        private const val APP_LOCALE = "en_US"
        private const val USER_AGENT = "ProtonVPN/5.0.0 (Android 14; Pixel 7)"
    }

    data class SyncResult(
        val added: Int,
        val failed: Int,
        val total: Int,
        val certSerial: String? = null,
        val error: Throwable? = null,
    ) {
        val isSuccess: Boolean get() = error == null
    }

    suspend fun sync(forceDeleteFirst: Boolean = true): SyncResult =
        withContext(Dispatchers.IO) {
            try {
                val session = anonymousLogin()
                val servers = fetchServers(session.AccessToken, session.UID)
                val best = pickBestPerCountry(servers)
                if (best.isEmpty()) {
                    return@withContext SyncResult(
                        added = 0,
                        failed = 0,
                        total = 0,
                        error = IllegalStateException("No free servers in Proton response"),
                    )
                }

                val keypair = ProtonCrypto.generateKeypair()
                val cert = requestCertificate(
                    session.AccessToken,
                    session.UID,
                    keypair.ed25519PublicPem,
                )

                val (parsed, broken, parseErrors) =
                    buildAndCollectConfigs(best, keypair.x25519Private)

                if (broken > 0 || parseErrors > 0) {
                    Timber.w(
                        "Proton sync: ${parsed.size} ok, $broken missing data, $parseErrors parse errors (${best.size} total)",
                    )
                }

                persistConfigs(parsed, forceDeleteFirst)

                SyncResult(
                    added = parsed.size,
                    failed = broken + parseErrors,
                    total = best.size,
                    certSerial = cert.SerialNumber,
                )
            } catch (e: Exception) {
                Timber.w(e, "Proton sync failed")
                SyncResult(0, 0, 0, error = e)
            }
        }

    // ------------------------------------------------------------------------
    // credentialLess login
    // ------------------------------------------------------------------------

    private fun challengePayload(): ProtonChallengePayload =
        ProtonChallengePayload(
            Payload = mapOf(
                CHALLENGE_FRAME_KEY to
                    ProtonChallengeFrame(
                        v = "2.0.7",
                        appLang = APP_LOCALE,
                        timezone = "Europe/Berlin",
                        deviceName = 1196226824L,
                        regionCode = "DE",
                        timezoneOffset = 60,
                        isJailbreak = false,
                        preferredContentSize = "normal",
                        storageCapacity = 128.0,
                        isDarkmodeOn = false,
                        keyboards = listOf(
                            "com.google.android.inputmethod.latin/" +
                                "com.android.inputmethod.latin.LatinIME"
                        ),
                    )
            )
        )

    /**
     * Populate the request's `HeadersBuilder` with Proton-required headers.
     * Called as `headers { addCommonProtonHeaders(...) }` so the same receiver
     * Kotlin's Ktor passes into the `headers {}` block is mutated in-place.
     */
    private fun HeadersBuilder.addCommonProtonHeaders(
        uid: String? = null,
        token: String? = null,
    ) {
        append("User-Agent", USER_AGENT)
        append("Accept", "application/vnd.protonmail.v1+json")
        append("x-pm-appversion", APP_VERSION)
        append("x-pm-locale", APP_LOCALE)
        if (uid != null) append("x-pm-uid", uid)
        if (token != null) append("Authorization", "Bearer $token")
        contentType(ContentType.Application.Json)
    }

    private suspend fun anonymousLogin(): ProtonSessionDto {
        Timber.d("Proton: Phase 0 (sessions)…")
        val phase0: ProtonSessionDto =
            httpClient
                .post("$API_HOST$API_PREFIX/auth/v4/sessions") {
                    headers { addCommonProtonHeaders() }
                    setBody(challengePayload())
                }
                .body()
        Timber.d("Proton: Phase 1 (credentialless)…")
        return httpClient
            .post("$API_HOST$API_PREFIX/auth/v4/credentialless") {
                headers { addCommonProtonHeaders(phase0.UID, phase0.AccessToken) }
                setBody(challengePayload())
            }
            .body()
    }

    // ------------------------------------------------------------------------
    // servers
    // ------------------------------------------------------------------------

    private suspend fun fetchServers(accessToken: String, uid: String):
        List<ProtonLogicalServerDto> {
        Timber.d("Proton: GET /logicals…")
        return httpClient
            .get("$API_HOST$API_PREFIX/vpn/v1/logicals") {
                headers { addCommonProtonHeaders(uid, accessToken) }
                parameter("SecureCoreFilter", "all")
                parameter("WithState", "true")
            }
            .body<ProtonLogicalServersDto>()
            .LogicalServers
    }

    private fun pickBestPerCountry(
        servers: List<ProtonLogicalServerDto>,
    ): Map<String, ProtonLogicalServerDto> =
        servers
            .asSequence()
            .filter { it.Tier == 0 && it.Status == 1 && (it.Features and 1) == 0 }
            .filter { it.ExitCountry.isNotBlank() }
            .groupBy { it.ExitCountry.uppercase() }
            .mapValues { (_, list) ->
                list.minBy { it.Load * 1000 + (it.Score * 100).toInt() }
            }

    // ------------------------------------------------------------------------
    // certificate
    // ------------------------------------------------------------------------

    private suspend fun requestCertificate(
        accessToken: String,
        uid: String,
        clientPubPem: String,
    ): ProtonCertificateDto {
        Timber.d("Proton: POST /certificate…")
        return httpClient
            .post("$API_HOST$API_PREFIX/vpn/v1/certificate") {
                headers { addCommonProtonHeaders(uid, accessToken) }
                setBody(
                    ProtonCertificateRequestDto(
                        ClientPublicKey = clientPubPem,
                        DeviceName = DEVICE_NAME,
                        Mode = CERT_MODE,
                    )
                )
            }
            .body()
    }

    // ------------------------------------------------------------------------
    // WireGuard config builder
    // ------------------------------------------------------------------------

    private fun buildAndCollectConfigs(
        best: Map<String, ProtonLogicalServerDto>,
        x25519Private: ByteArray,
    ): Triple<List<TunnelConfig>, Int, Int> {
        val parsed = mutableListOf<TunnelConfig>()
        var broken = 0
        var parseErrors = 0
        val xPrivB64 = Base64.encodeToString(x25519Private, Base64.NO_WRAP)
        for ((country, server) in best) {
            val first = server.Servers.firstOrNull()
            val entryIp = first?.EntryIP.orEmpty()
            val serverPub = first?.X25519PublicKey.orEmpty()
            if (entryIp.isBlank() || serverPub.isBlank()) {
                broken++
                continue
            }
            val name = "${flagEmoji(country)} $country"
            val conf =
                "[Interface]\n" +
                    "PrivateKey = $xPrivB64\n" +
                    "Address = 10.2.0.2/32\n" +
                    "DNS = 10.2.0.1\n" +
                    "\n" +
                    "[Peer]\n" +
                    "PublicKey = $serverPub\n" +
                    "AllowedIPs = 0.0.0.0/0, ::/0\n" +
                    "Endpoint = $entryIp:$WG_PORT\n" +
                    "PersistentKeepalive = 25\n"
            try {
                parsed += TunnelConfig.tunnelConfFromQuick(conf, name)
            } catch (e: Exception) {
                parseErrors++
                Timber.e(e, "Failed to parse config for $country")
            }
        }
        return Triple(parsed, broken, parseErrors)
    }

    private suspend fun persistConfigs(
        configs: List<TunnelConfig>,
        forceDeleteFirst: Boolean,
    ) {
        if (forceDeleteFirst) {
            val existing = tunnelRepository.getAll()
            if (existing.isNotEmpty()) tunnelRepository.delete(existing)
            tunnelRepository.saveTunnelsUniquely(configs, emptyList())
        } else {
            val existingNames = tunnelRepository.getAll().map { it.name }
            tunnelRepository.saveTunnelsUniquely(configs, existingNames)
        }
    }

    /** Country code (2 letters) → flag emoji via regional indicator pairs. */
    private fun flagEmoji(country: String): String {
        if (country.length != 2) return country
        val first = 0x1F1E6 + (country[0].code - 'A'.code)
        val second = 0x1F1E6 + (country[1].code - 'A'.code)
        return String(Character.toChars(first)) +
            String(Character.toChars(second))
    }
}