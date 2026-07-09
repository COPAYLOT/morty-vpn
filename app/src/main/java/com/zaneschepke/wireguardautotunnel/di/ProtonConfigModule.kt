package com.zaneschepke.wireguardautotunnel.di

import com.zaneschepke.wireguardautotunnel.data.network.ProtonProxyClient
import com.zaneschepke.wireguardautotunnel.data.repository.ObfuscationRepository
import com.zaneschepke.wireguardautotunnel.domain.service.ProtonConfigService
import org.koin.dsl.module

val protonConfigModule = module {
    single { ObfuscationRepository(get(), get()) }
    single { ProtonProxyClient(get(), ProtonProxyClient.DEFAULT_BASE_URL) }
    single { ProtonConfigService(get(), get(), get(), get()) }
}
