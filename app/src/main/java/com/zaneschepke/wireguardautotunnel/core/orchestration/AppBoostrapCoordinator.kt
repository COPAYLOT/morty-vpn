package com.zaneschepke.wireguardautotunnel.core.orchestration

import com.zaneschepke.logcatter.LogReader
import com.zaneschepke.wireguardautotunnel.core.tunnel.TunnelProvider
import com.zaneschepke.wireguardautotunnel.domain.enums.TunnelMode
import com.zaneschepke.wireguardautotunnel.domain.repository.DnsSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.GeneralSettingRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.LockdownSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.MonitoringSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.domain.service.MortyRemoteConfigService
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.launch
import timber.log.Timber

class AppBoostrapCoordinator(
    private val monitoringRepository: MonitoringSettingsRepository,
    private val settingsRepository: GeneralSettingRepository,
    private val dnsRepository: DnsSettingsRepository,
    private val tunnelRepository: TunnelRepository,
    private val lockdownRepository: LockdownSettingsRepository,
    private val tunnelProvider: TunnelProvider,
    private val dnsSettingsCoordinator: DnsSettingsCoordinator,
    private val logReader: LogReader,
    private val mortyRemoteConfigService: MortyRemoteConfigService,
) {

    private val _isReady = MutableStateFlow(false)
    val isReady: StateFlow<Boolean> = _isReady.asStateFlow()

    suspend fun bootstrap() = coroutineScope {
        launch { bootstrapLogging() }
        // First-launch: pull the latest server list from the remote endpoint
        // (non-blocking, non-critical). forceDeleteFirst=false so we only add
        // tunnels whose names are not already present, preserving any user
        // configuration from a manual import.
        launch { bootstrapRemoteConfig() }

        val criticalTasks =
            listOf(
                async { bootstrapDns() },
                async { ensureGlobalConfig() },
                async { restoreBackendConfiguration() },
            )

        try {
            criticalTasks.awaitAll()
            _isReady.value = true
            Timber.d("App bootstrap completed successfully")
        } catch (e: Exception) {
            Timber.e(e, "One or more critical bootstrap tasks failed")
            _isReady.value = true
        }
    }

    private suspend fun bootstrapRemoteConfig() {
        try {
            val result = mortyRemoteConfigService.sync(forceDeleteFirst = false)
            if (result.isSuccess) {
                Timber.d("Morty remote config bootstrap: ${result.added}/${result.total} added")
            } else {
                Timber.w(result.error, "Morty remote config bootstrap failed (non-fatal)")
            }
        } catch (e: Exception) {
            Timber.e(e, "Morty remote config bootstrap threw (non-fatal)")
        }
    }

    private suspend fun bootstrapDns() {
        val dnsSettings = dnsRepository.getDnsSettings()
        dnsSettingsCoordinator.appyDnsSettings(dnsSettings)
    }

    private suspend fun bootstrapLogging() {
        monitoringRepository.flow
            .distinctUntilChangedBy { it.isLocalLogsEnabled }
            .collect { settings ->
                if (settings.isLocalLogsEnabled) {
                    logReader.start()
                } else {
                    logReader.stop()
                }
            }
    }

    private suspend fun ensureGlobalConfig() {
        tunnelRepository.ensureGlobalConfigExists()
    }

    private suspend fun restoreBackendConfiguration() {
        val settings = settingsRepository.getGeneralSettings()

        if (settings.seamlessRoamingEnabled) {
            tunnelProvider.setSeamlessRoaming(true)
        }

        when (settings.tunnelMode) {
            TunnelMode.LOCK_DOWN -> {
                val lockdownSettings = lockdownRepository.getLockdownSettings()
                tunnelProvider.setLockDown(lockdownSettings).onFailure {
                    Timber.w(it, "Failed to restore lockdown/kill-switch on startup")
                }
            }
            else -> Unit
        }
    }
}
