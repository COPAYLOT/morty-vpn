package com.zaneschepke.wireguardautotunnel.domain.service

import android.util.Base64
import com.zaneschepke.wireguardautotunnel.data.crypto.ProtonCrypto
import com.zaneschepke.wireguardautotunnel.data.network.ProtonProxyClient
import com.zaneschepke.wireguardautotunnel.data.network.dto.ObfuscationParams
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonCertificateDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonCertificateRequestDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonChallengeFrame
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonChallengePayload
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonLogicalServerDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonLogicalServersDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.ProtonSessionDto
import com.zaneschepke.wireguardautotunnel.data.repository.ObfuscationRepository
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.util.extensions.saveTunnelsUniquely
import io.ktor.client.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
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
 * All Proton API calls go through [proxyClient] (the user's Apps Script
 * HTTP proxy). The proxy is a generic forwarder that does the actual
 * HTTPS call to api.protonvpn.ch from the user's machine, where the
 * network has access. The APK sends `?op=proxy&url=...&method=...`
 * with the original Proton request body + headers as URL params.
 *
 * Obfuscation is fetched SEPARATELY by [obfuscationRepository] from a
 * separate script (the existing `?op=wg_obfuskate` endpoint, which the
 * user does not touch). It does not flow through this proxy.
 */
class ProtonConfigService(
    private val httpClient: HttpClient,
    private val tunnelRepository: TunnelRepository,
    private val obfuscationRepository: ObfuscationRepository,
    private val proxyClient: ProtonProxyClient,
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

        /**
         * Apps Script proxy URL (the user's deployed Web App). The script
         * is a generic HTTP forwarder: it accepts `?op=proxy&url=...&method=...`
         * and forwards the request to Proton, returning the response as
         * JSON. All 4 Proton calls in this service go through this proxy.
         */
        const val PROXY_BASE_URL: String = ProtonProxyClient.DEFAULT_BASE_URL

        private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    }

    data class SyncResult(
        val added: Int,
        val failed: Int,
        val total: Int,
        val certSerial: String? = null,
        val error: Throwable? = null,
        val httpStatus: Int? = null,
        val httpBody: String? = null,
    ) {
        val isSuccess: Boolean get() = error == null
    }

    suspend fun sync(forceDeleteFirst: Boolean = true): SyncResult =
        withContext(Dispatchers.IO) {
            try {
                coroutineScope {
                    // 1. Phase 0 + obfuscation (independent) run in parallel.
                    val phase0Job = async { anonymousLoginPhase0() }
                    val obfJob = async { obfuscationRepository.get() }

                    // 2. Phase 1 depends on Phase 0's UID + token.
                    val phase0 = phase0Job.await()
                    val phase1Job =
                        async { anonymousLoginPhase1(phase0.uid, phase0.accessToken) }

                    // 3. /logicals + /certificate both depend on Phase 1; can
                    //    run in parallel. /certificate also needs the new keypair.
                    val phase1 = phase1Job.await()
                    val keypair = ProtonCrypto.generateKeypair()
                    val serversJob =
                        async { fetchServers(phase1.accessToken, phase1.uid) }
                    val certJob =
                        async {
                            requestCertificate(
                                phase1.accessToken,
                                phase1.uid,
                                keypair.ed25519PublicPem,
                            )
                        }

                    val servers = serversJob.await()
                    val cert = certJob.await()
                    val obfuscation = obfJob.await()

                    val best = pickBestPerCountry(servers)
                    if (best.isEmpty()) {
                        return@coroutineScope SyncResult(
                            added = 0,
                            failed = 0,
                            total = 0,
                            error = IllegalStateException("No free servers in Proton response"),
                        )
                    }

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
                }
            } catch (e: Exception) {
                Timber.w(e, "Proton sync failed")
                val (status, body) = unwrapHttp(e)
                SyncResult(
                    added = 0,
                    failed = 0,
                    total = 0,
                    error = e,
                    httpStatus = status,
                    httpBody = body?.take(400),
                )
            }
        }

    // ------------------------------------------------------------------------
    // credentialLess login (Phase 0 + Phase 1)
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

    /** Headers Proton always requires (no auth). */
    private fun commonHeaders(): Map<String, String> =
        mapOf(
            "User-Agent" to USER_AGENT,
            "Accept" to "application/vnd.protonmail.v1+json",
            "x-pm-appversion" to APP_VERSION,
            "x-pm-locale" to APP_LOCALE,
        )

    /** Same plus auth headers. */
    private fun commonHeaders(uid: String, token: String): Map<String, String> =
        commonHeaders() +
            mapOf("x-pm-uid" to uid, "Authorization" to "Bearer $token")

    /** Phase 0 of the credentialLess login. Returns the session + UID. */
    private suspend fun anonymousLoginPhase0(): ProtonSessionDto {
        Timber.d("Proton: Phase 0 (sessions)…")
        val payload = json.encodeToString(challengePayload())
        val body =
            proxyClient.request(
                "POST",
                "$API_HOST$API_PREFIX/auth/v4/sessions",
                commonHeaders(),
                payload,
            ).body
        return json.decodeFromString<ProtonSessionDto>(body)
    }

    /** Phase 1 of the credentialLess login. Needs UID + token from Phase 0. */
    private suspend fun anonymousLoginPhase1(uid: String, accessToken: String): ProtonSessionDto {
        Timber.d("Proton: Phase 1 (credentialless)…")
        val payload = json.encodeToString(challengePayload())
        val body =
            proxyClient.request(
                "POST",
                "$API_HOST$API_PREFIX/auth/v4/credentialless",
                commonHeaders(uid, accessToken),
                payload,
            ).body
        return json.decodeFromString<ProtonSessionDto>(body)
    }

    // ------------------------------------------------------------------------
    // servers
    // ------------------------------------------------------------------------

    private suspend fun fetchServers(
        accessToken: String,
        uid: String,
    ): List<ProtonLogicalServerDto> {
        Timber.d("Proton: GET /logicals…")
        val url =
            "$API_HOST$API_PREFIX/vpn/v1/logicals?SecureCoreFilter=all&WithState=true"
        val body =
            proxyClient.request("GET", url, commonHeaders(uid, accessToken)).body
        return json.decodeFromString<ProtonLogicalServersDto>(body).LogicalServers
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
        val body =
            proxyClient
                .request(
                    "POST",
                    "$API_HOST$API_PREFIX/vpn/v1/certificate",
                    commonHeaders(uid, accessToken),
                    json.encodeToString(
                        ProtonCertificateRequestDto(
                            ClientPublicKey = clientPubPem,
                            DeviceName = DEVICE_NAME,
                            Mode = CERT_MODE,
                        )
                    ),
                )
                .body
        return json.decodeFromString<ProtonCertificateDto>(body)
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
        // NOTE: do NOT inject AmneziaWG obfuscation params here. Proton VPN
        // free tier is plain WireGuard — adding Jc/S1/H1/etc. produces
        // non-standard init packets that the server drops. The
        // ObfuscationParams fetch still happens (for diagnostics / future
        // use) but the params are not embedded in the [Interface] block.
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
                    obfBlock +
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

    /**
     * Walk the exception chain to extract HTTP status + body for the
     * snackbar. The proxy wraps non-2xx responses in [ProtonHttpException]
     * which carries the actual Proton response text; this surfaces it
     * to the UI instead of generic "Fetch failed".
     */
    private fun unwrapHttp(e: Throwable): Pair<Int?, String?> {
        var status: Int? = null
        var body: String? = null
        var cause: Throwable? = e
        while (cause != null) {
            if (cause is ProtonHttpException) {
                status = cause.status ?: status
                body = cause.body ?: body
                break
            }
            cause = cause.cause
        }
        return status to body
    }
}

/**
 * Thrown when the proxy reports a non-2xx Proton response. Carries the
 * actual status + body so the snackbar can show the real reason.
 */
class ProtonHttpException(
    message: String,
    val status: Int?,
    val body: String?,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
