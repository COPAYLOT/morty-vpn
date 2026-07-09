package com.zaneschepke.wireguardautotunnel.domain.service

import androidx.datastore.preferences.core.booleanPreferencesKey
import com.zaneschepke.wireguardautotunnel.data.DataStoreManager
import com.zaneschepke.wireguardautotunnel.data.network.dto.MortyRemoteConfigDto
import com.zaneschepke.wireguardautotunnel.data.network.dto.MortyRemoteServerDto
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.parser.Config
import com.zaneschepke.wireguardautotunnel.util.extensions.saveTunnelsUniquely
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * Fetches the remote Morty VPN server list from Google Apps Script and imports
 * the tunnels into the local database.
 *
 * The remote endpoint returns a JSON payload of shape:
 *   { ok: true, timestamp, count, servers: [{ name, config }] }
 * where `config` is a full WireGuard / AmneziaWG `.conf` text (with embedded
 * AWG obfuscation parameters like S1/S2/Jc/Jmin/Jmax/H1..H4/I1..I5).
 */
class MortyRemoteConfigService(
    private val httpClient: HttpClient,
    private val tunnelRepository: TunnelRepository,
    private val dataStoreManager: DataStoreManager,
) {
    companion object {
        const val CONFIG_URL =
            "https://script.google.com/macros/s/AKfycbzTPDINBr7HKmgKvpl3Ycc4Zl9dfYxpeUDJgDzL0toEoO1gFVpxa1-a7sICH70tvV6JbQ/exec"
        val SYNCED_ONCE_KEY = booleanPreferencesKey("MORTY_REMOTE_SYNCED_ONCE")
    }

    /**
     * Result of a sync attempt.
     *
     * @param added number of new tunnels successfully written to the database
     * @param failed number of servers that failed to parse (skipped)
     * @param total total servers in the remote response
     * @param error optional fatal error (network failure, ok=false, etc.); when
     *   set, [added] and [failed] are both 0
     */
    data class SyncResult(
        val added: Int,
        val failed: Int,
        val total: Int,
        val error: Throwable? = null,
    ) {
        val isSuccess: Boolean get() = error == null
    }

    /**
     * Fetch the remote config and import the tunnels.
     *
     * @param forceDeleteFirst when true, delete all existing tunnels before
     *   saving the new ones (used by the menu action). When false, only add
     *   tunnels whose name does not already exist (used by first-launch sync
     *   so we don't clobber a user who already has tunnels set up).
     */
    suspend fun sync(forceDeleteFirst: Boolean = true): SyncResult =
        withContext(Dispatchers.IO) {
            try {
                val response: MortyRemoteConfigDto =
                    httpClient.get(CONFIG_URL).body<MortyRemoteConfigDto>()
                if (!response.ok) {
                    return@withContext SyncResult(
                        added = 0,
                        failed = 0,
                        total = 0,
                        error = IllegalStateException("Remote response ok=false"),
                    )
                }
                applyServers(response.servers, forceDeleteFirst)
            } catch (e: Exception) {
                Timber.e(e, "MortyRemoteConfigService.sync failed")
                SyncResult(0, 0, 0, e)
            }
        }

    suspend fun hasSyncedOnce(): Boolean =
        dataStoreManager.getFromStore(SYNCED_ONCE_KEY) == true

    private suspend fun applyServers(
        servers: List<MortyRemoteServerDto>,
        forceDeleteFirst: Boolean,
    ): SyncResult {
        // Parse each config separately so one bad entry doesn't kill the batch.
        val parsed = mutableListOf<TunnelConfig>()
        var brokenPeer = 0
        var parseErrors = 0
        for (server in servers) {
            when (val result = parseAndValidate(server)) {
                is ParseResult.Ok -> parsed += result.tunnel
                ParseResult.MissingPeer -> brokenPeer++
                is ParseResult.Error -> parseErrors++
            }
        }

        if (brokenPeer > 0 || parseErrors > 0) {
            Timber.w(
                "Remote sync: ${parsed.size} ok, $brokenPeer missing peer data, $parseErrors parse errors (${servers.size} total)",
            )
        }

        if (forceDeleteFirst) {
            val existing = tunnelRepository.getAll()
            if (existing.isNotEmpty()) {
                tunnelRepository.delete(existing)
            }
            val existingNames = emptyList<String>()
            if (parsed.isNotEmpty()) {
                tunnelRepository.saveTunnelsUniquely(parsed, existingNames)
            }
        } else {
            val existingNames = tunnelRepository.getAll().map { it.name }
            tunnelRepository.saveTunnelsUniquely(parsed, existingNames)
        }

        dataStoreManager.saveToDataStore(SYNCED_ONCE_KEY, true)
        return SyncResult(
            added = parsed.size,
            failed = brokenPeer + parseErrors,
            total = servers.size,
        )
    }

    /**
     * Result of validating a single remote server's `.conf` text against
     * the minimum requirements for a working tunnel:
     * - parses cleanly via [Config.parseQuickString], and
     * - has at least one peer with both a public key and an endpoint.
     */
    private sealed interface ParseResult {
        data class Ok(val tunnel: TunnelConfig) : ParseResult
        data object MissingPeer : ParseResult
        data class Error(val throwable: Throwable) : ParseResult
    }

    private fun parseAndValidate(server: MortyRemoteServerDto): ParseResult {
        val trimmedConfig = server.config.trim()
        val trimmedName = server.name.trim()
        val parsedConfig = try {
            Config.parseQuickString(trimmedConfig)
        } catch (e: Exception) {
            return ParseResult.Error(e)
        }
        val hasUsablePeer = parsedConfig.peers.any { peer ->
            peer.publicKey.isNotBlank() && !peer.endpoint.isNullOrBlank()
        }
        if (!hasUsablePeer) return ParseResult.MissingPeer
        return ParseResult.Ok(
            TunnelConfig(
                name = parsedConfig.name ?: trimmedName,
                quickConfig = trimmedConfig,
            )
        )
    }
}
