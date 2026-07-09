package com.zaneschepke.wireguardautotunnel.data.network

import com.zaneschepke.wireguardautotunnel.domain.service.ProtonHttpException
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import kotlinx.serialization.Serializable
import timber.log.Timber
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Generic HTTP forwarder that talks to the user's Apps Script proxy.
 *
 * The proxy is a `doGet(e)` handler that accepts a `?op=proxy` request
 * with the original Proton request serialized as query params:
 *   - url:     the Proton URL (URL-encoded)
 *   - method:  GET / POST
 *   - headers: URL-encoded JSON object
 *   - body:    URL-encoded request body (optional)
 *
 * It then calls `UrlFetchApp.fetch(url, ...)` server-side and returns
 * the response status + body as JSON. This client is the bridge between
 * the APK (which has all the business logic) and the user's machine
 * (where the proxy runs and has direct access to api.protonvpn.ch).
 *
 * Obfuscation is fetched SEPARATELY by [com.zaneschepke.wireguardautotunnel.data.repository.ObfuscationRepository]
 * from a separate script — it does NOT go through this proxy.
 */
class ProtonProxyClient(
    private val httpClient: HttpClient,
    val baseUrl: String,
) {
    companion object {
        /**
         * Default proxy URL (the user's deployed Apps Script). User replaces
         * this constant after deployment.
         */
        const val DEFAULT_BASE_URL =
            "https://script.google.com/macros/s/AKfycbyLz_7o4txMqfOTiDSL2PV39IsoOEHIHDKeu9FdIsCO75iEEfw1hETA12kZnsTSGMxWiw/exec"
    }

    @Serializable
    data class Wrapper(
        val ok: Boolean = false,
        val status: Int = 0,
        val body: String = "",
        val error: String? = null,
    )

    data class Response(val status: Int, val body: String)

    /**
     * Forward a single HTTP request through the proxy.
     *
     * @throws ProtonHttpException on non-2xx Proton response (caller gets
     *         the status + body for diagnostic display in the snackbar)
     * @throws IllegalStateException on proxy-level failure (network,
     *         script error, ok=false, etc.)
     */
    suspend fun request(
        method: String,
        url: String,
        headers: Map<String, String> = emptyMap(),
        body: String? = null,
    ): Response {
        val params = buildString {
            append("op=proxy")
            append("&url=").append(URLEncoder.encode(url, StandardCharsets.UTF_8))
            append("&method=").append(method.uppercase())
            if (headers.isNotEmpty()) {
                val headersJson = JsonLenient.encodeToString(headers)
                append("&headers=").append(URLEncoder.encode(headersJson, StandardCharsets.UTF_8))
            }
            if (body != null) {
                append("&body=").append(URLEncoder.encode(body, StandardCharsets.UTF_8))
            }
        }
        val fullUrl = "$baseUrl?$params"
        val wrapper: Wrapper = httpClient.get(fullUrl).body()
        if (!wrapper.ok) {
            throw IllegalStateException("Proxy: ${wrapper.error ?: "unknown"}")
        }
        if (wrapper.status !in 200..299) {
            throw ProtonHttpException(
                "HTTP ${wrapper.status} via proxy",
                wrapper.status,
                wrapper.body.take(400),
            )
        }
        return Response(wrapper.status, wrapper.body)
    }
}

/** Local JSON helper that doesn't require a serializable data class. */
private object JsonLenient {
    private val json = kotlinx.serialization.json.Json {
        ignoreUnknownKeys = true
        isLenient = true
    }
    fun encodeToString(map: Map<String, String>): String =
        json.encodeToString(
            kotlinx.serialization.json.JsonObject.serializer(),
            kotlinx.serialization.json.buildJsonObject {
                for ((k, v) in map) put(k, kotlinx.serialization.json.JsonPrimitive(v))
            }
        )
}
