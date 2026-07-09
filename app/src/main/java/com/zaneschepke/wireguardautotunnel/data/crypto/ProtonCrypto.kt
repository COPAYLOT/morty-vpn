package com.zaneschepke.wireguardautotunnel.data.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.StringWriter

/**
 * Proton VPN-compatible key generation.
 *
 * Proton's VPN API authenticates clients with an **Ed25519** public key
 * (sent as a SubjectPublicKeyInfo PEM blob), while the actual WireGuard
 * tunnel uses an **X25519** keypair. We therefore:
 *   1. Generate a fresh Ed25519 keypair (32-byte seed + 32-byte public).
 *   2. Convert the Ed25519 private key to an X25519 private key via
 *      the same hash-based derivation that libsodium uses
 *      (`crypto_sign_ed25519_sk_to_curve25519`):
 *        x25519_sk = SHA-512(seed || public)[0..32] with RFC 7748 clamping.
 *   3. Encode the Ed25519 public key as a PEM SubjectPublicKeyInfo so
 *      Proton's API accepts it as `ClientPublicKey`.
 */
object ProtonCrypto {
    private val secureRandom = SecureRandom()

    data class Keypair(
        /** X25519 private key (32 bytes, clamped). Goes into [Interface] PrivateKey. */
        val x25519Private: ByteArray,
        /** Ed25519 public key (32 bytes). */
        val ed25519Public: ByteArray,
        /** Ed25519 public key encoded as SubjectPublicKeyInfo PEM. Sent to Proton as ClientPublicKey. */
        val ed25519PublicPem: String,
    )

    fun generateKeypair(): Keypair {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(secureRandom))
        val pair = gen.generateKeyPair()
        val priv = pair.private as Ed25519PrivateKeyParameters
        val pub = pair.public as Ed25519PublicKeyParameters

        // libsodium convention: full ed25519 sk = seed (32) || pub (32)
        val x25519Priv = ed25519PrivateToX25519(priv.seed, pub.encoded)

        val pem = encodeEd25519PublicAsPem(pub.encoded)

        return Keypair(
            x25519Private = x25519Priv,
            ed25519Public = pub.encoded,
            ed25519PublicPem = pem,
        )
    }

    /**
     * Equivalent to libsodium's `crypto_sign_ed25519_sk_to_curve25519`.
     * Uses SHA-512(seed || pub)[0..32] with RFC 7748 clamping.
     */
    private fun ed25519PrivateToX25519(seed: ByteArray, pub: ByteArray): ByteArray {
        require(seed.size == 32 && pub.size == 32)
        val md = MessageDigest.getInstance("SHA-512")
        md.update(seed)
        md.update(pub)
        val hash = md.digest()
        val x = ByteArray(32)
        System.arraycopy(hash, 0, x, 0, 32)
        // RFC 7748 §5: clamp the scalar
        x[0] = (x[0].toInt() and 248).toByte()
        x[31] = ((x[31].toInt() and 127) or 64).toByte()
        return x
    }

    private fun encodeEd25519PublicAsPem(pub: ByteArray): String {
        val spki = SubjectPublicKeyInfo(EdECObjectIdentifiers.id_Ed25519, pub)
        val sw = StringWriter()
        JcaPEMWriter(sw).use { it.writeObject(spki) }
        return sw.toString()
    }
}