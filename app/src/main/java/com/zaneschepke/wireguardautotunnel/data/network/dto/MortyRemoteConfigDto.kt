package com.zaneschepke.wireguardautotunnel.data.network.dto

import kotlinx.serialization.Serializable

@Serializable
data class MortyRemoteConfigDto(
    val ok: Boolean = false,
    val timestamp: String? = null,
    val count: Int = 0,
    val servers: List<MortyRemoteServerDto> = emptyList(),
)

@Serializable
data class MortyRemoteServerDto(
    val name: String = "",
    val config: String = "",
)
