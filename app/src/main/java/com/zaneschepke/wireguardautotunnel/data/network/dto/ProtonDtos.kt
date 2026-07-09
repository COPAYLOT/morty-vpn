package com.zaneschepke.wireguardautotunnel.data.network.dto

import kotlinx.serialization.Serializable

@Serializable
data class ProtonSessionDto(
    val AccessToken: String = "",
    val RefreshToken: String = "",
    val UID: String = "",
    val UserID: String? = null,
    val Scopes: List<String> = emptyList(),
    val LocalID: Int = 0,
    val TwoFactor: ProtonTwoFactorDto? = null,
    val PasswordMode: Int = 1,
)

@Serializable
data class ProtonTwoFactorDto(
    val Enabled: Int = 0,
    val FIDO2: ProtonFido2Dto? = null,
)

@Serializable
data class ProtonFido2Dto(
    val RegisteredKeys: List<ProtonFido2KeyDto> = emptyList(),
)

@Serializable
data class ProtonFido2KeyDto(
    val ID: String = "",
    val Name: String = "",
)

@Serializable
data class ProtonChallengePayload(
    val Payload: Map<String, ProtonChallengeFrame> = emptyMap(),
)

@Serializable
data class ProtonChallengeFrame(
    val v: String = "",
    val appLang: String = "",
    val timezone: String = "",
    val deviceName: Long = 0,
    val regionCode: String = "",
    val timezoneOffset: Int = 0,
    val isJailbreak: Boolean = false,
    val preferredContentSize: String = "",
    val storageCapacity: Double = 0.0,
    val isDarkmodeOn: Boolean = false,
    val keyboards: List<String> = emptyList(),
)

@Serializable
data class ProtonLogicalServersDto(
    val LogicalServers: List<ProtonLogicalServerDto> = emptyList(),
)

@Serializable
data class ProtonLogicalServerDto(
    val Name: String = "",
    val ExitCountry: String = "",
    val Tier: Int = 0,
    val Status: Int = 0,
    val Features: Int = 0,
    val Load: Int = 0,
    val Score: Double = 0.0,
    val City: String? = null,
    val Servers: List<ProtonPhysicalServerDto> = emptyList(),
)

@Serializable
data class ProtonPhysicalServerDto(
    val EntryIP: String = "",
    val X25519PublicKey: String = "",
    val Domain: String = "",
    val Status: Int = 1,
    val Labels: List<ProtonLabelDto> = emptyList(),
)

@Serializable
data class ProtonLabelDto(
    val Name: String = "",
    val Color: String = "",
    val Order: Int = 0,
)

@Serializable
data class ProtonCertificateRequestDto(
    val ClientPublicKey: String,
    val ClientPublicKeyMode: String = "EC",
    val DeviceName: String,
    val Mode: String = "persistent",
    val Features: List<Int> = emptyList(),
)

@Serializable
data class ProtonCertificateDto(
    val SerialNumber: String = "",
    val ExpirationTime: Long = 0L,
    val Mode: String = "",
    val Certificate: String = "",
    val PublicKey: String = "",
    val Signature: String = "",
)