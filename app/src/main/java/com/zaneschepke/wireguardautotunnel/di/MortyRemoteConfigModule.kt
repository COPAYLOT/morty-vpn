package com.zaneschepke.wireguardautotunnel.di

import com.zaneschepke.wireguardautotunnel.domain.service.MortyRemoteConfigService
import org.koin.dsl.module

val mortyRemoteConfigModule = module {
    single { MortyRemoteConfigService(get(), get(), get()) }
}
