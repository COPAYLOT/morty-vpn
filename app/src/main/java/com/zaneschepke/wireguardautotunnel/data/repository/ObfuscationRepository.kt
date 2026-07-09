package com.zaneschepke.wireguardautotunnel.data.repository

import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.zaneschepke.wireguardautotunnel.data.DataStoreManager
import com.zaneschepke.wireguardautotunnel.data.network.dto.ObfuscationParams
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * Fetches the AmneziaWG-style obfuscation parameter block from the
 * Morty config endpoint and caches it.
 *
 * URL: https://script.google.com/macros/s/.../exec?op=wg_obfuskate
 *   → returns plain text (NOT JSON), e.g.
 *      MTU = 1280
 *      S1 = 0
 *      S2 = 0
 *      Jc = 4
 *      ...
 *      I1 = <b 0xce...>
 *
 * The block is inserted into every generated WireGuard `.conf`'s
 * [Interface] section, just before the [Peer] block. This effectively
 * upgrades plain WireGuard tunnels to AmneziaWG-style obfuscated
 * tunnels (the upstream tunnel library supports both via the same
 * AWG parser).
 *
 * Caching: we keep an in-process AtomicReference to the most recent
 * value so concurrent sync() calls don't trigger a network fetch each.
 * We also persist the raw text in DataStore so the very first launch
 * (and launches when the network is down) still produce tunnels with
 * the last-known obfuscation applied.
 */
class ObfuscationRepository(
    private val httpClient: HttpClient,
    private val dataStoreManager: DataStoreManager,
) {
    companion object {
        const val OBFUSCATION_URL =
            "https://script.google.com/macros/s/AKfycbw_tOUivmoyXuBU8OR-Mr8jMrNo3Zws_IymopHMvaQjelmxWozJ1E7Ha8FvnlKJL0uq/exec?op=wg_obfuskate"
        val OBFUSCATION_KEY = stringPreferencesKey("morty_obfuscation_raw")
    }

    private val cached = AtomicReference<ObfuscationParams?>(null)
    private val fetchLock = Mutex()

    /** Returns the cached value, or null if not yet fetched. */
    fun cachedOrNull(): ObfuscationParams? = cached.get()

    /**
     * Returns the current obfuscation params, fetching from the endpoint
     * if no cache is present. Safe to call concurrently — only one network
     * fetch happens at a time.
     */
    suspend fun get(): ObfuscationParams = fetchLock.withLock {
        cached.get()?.let { return@withLock it }
        fetchAndStore()
    }

    /**
     * Forces a network fetch regardless of cache state. Useful if the
     * upstream block changed and the user triggers a manual "refresh"
     * — not currently wired to a menu item, but kept for future use.
     */
    suspend fun refresh(): ObfuscationParams = fetchLock.withLock { fetchAndStore() }

    private suspend fun fetchAndStore(): ObfuscationParams {
        val raw = runCatching {
                httpClient.get(OBFUSCATION_URL).bodyAsText()
            }
            .onFailure { Timber.w(it, "Obfuscation fetch failed; falling back to DataStore cache") }
            .getOrNull()
        val finalRaw = raw ?: dataStoreManager.getFromStore(OBFUSCATION_KEY) ?: ""
        val parsed = ObfuscationParams.parse(finalRaw)
        cached.set(parsed)
        if (raw != null) {
            dataStoreManager.saveToDataStore(OBFUSCATION_KEY, raw)
        }
        if (parsed.isEmpty()) {
            Timber.w("Obfuscation params empty — tunnels will be plain WireGuard")
        } else {
            Timber.d("Obfuscation: ${parsed.lines.size} params loaded")
        }
        return parsed
    }
}