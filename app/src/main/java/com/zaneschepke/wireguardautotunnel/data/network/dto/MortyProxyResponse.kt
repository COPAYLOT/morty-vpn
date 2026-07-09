package com.zaneschepke.wireguardautotunnel.data.network.dto

import kotlinx.serialization.Serializable

/**
 * Response shape returned by the Apps Script proxy at `?op=full`.
 *
 * The script does credentialLess login + GET /logicals + POST /certificate
 * + picks best per country + fetches the AmneziaWG obfuscation block
 * + builds per-country .conf on the user's machine (the user's machine
 * has access to Proton VPN; the APK may not). The script then returns
 * the shared cert serial + obfuscation block + one entry per country.
 *
 * Every user that hits the same script deployment gets the same shared
 * Ed25519/X25519 keypair and the same certificate. That's a deliberate
 * trade-off documented in the project — it removes the need for the APK
 * to perform crypto (no BouncyCastle, no keygen) while still giving
 * every install a working tunnel.
 *
 * @property ok          true if the script ran the full Proton flow.
 * @property certSerial  Proton cert serial number, for diagnostics.
 * @property obfuscation Plain-text AmneziaWG-style block. The script
 *                       embeds it directly so the APK doesn't have to
 *                       hit a second endpoint.
 * @property servers     One entry per country. `name` is what the APK
 *                       shows in the tunnel list; `x25519PrivateKey`
 *                       is the shared private key.
 */
@Serializable
data class MortyProxyResponse(
    val ok: Boolean = false,
    val certSerial: String? = null,
    val obfuscation: String? = null,
    val servers: List<MortyProxyServer> = emptyList(),
)

@Serializable
data class MortyProxyServer(
    val country: String = "",
    val name: String = "",
    val entryIp: String = "",
    val x25519PublicKey: String = "",
    val x25519PrivateKey: String = "",
)