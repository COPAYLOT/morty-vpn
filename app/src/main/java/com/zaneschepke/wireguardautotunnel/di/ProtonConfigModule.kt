package com.zaneschepke.wireguardautotunnel.di

import com.zaneschepke.wireguardautotunnel.domain.service.ProtonConfigService
import org.koin.dsl.module

val protonConfigModule = module { single { ProtonConfigService(get(), get()) } }
