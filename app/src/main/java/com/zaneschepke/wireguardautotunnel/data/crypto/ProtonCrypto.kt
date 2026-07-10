package com.zaneschepke.wireguardautotunnel.data.crypto

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters

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

        // libsodium's crypto_sign_ed25519_sk_to_curve25519 hashes ONLY the
        // 32-byte seed, NOT the 64-byte libsodium secret form. BC's
        // Ed25519PrivateKeyParameters.encoded already returns the 32-byte
        // seed in IETF format, which is exactly what we need.
        val x25519Priv = ed25519PrivateToX25519(priv.encoded)

        val pem = encodeEd25519PublicAsPem(pub.encoded)

        return Keypair(
            x25519Private = x25519Priv,
            ed25519Public = pub.encoded,
            ed25519PublicPem = pem,
        )
    }

    /**
     * Equivalent to libsodium's `crypto_sign_ed25519_sk_to_curve25519`.
     *
     * input: 32-byte ed25519 seed (NOT 64-byte secret).
     *   libsodium: `crypto_hash_sha512(seed, 32, h); take first 32 of h; clamp`
     * output: 32-byte x25519 priv with RFC 7748 clamping.
     */
    private fun ed25519PrivateToX25519(seed: ByteArray): ByteArray {
        require(seed.size == 32) {
            "Expected 32-byte ed25519 seed, got ${seed.size} bytes. " +
                "libSodium's crypto_sign_ed25519_sk_to_curve25519 hashes ONLY the 32-byte " +
                "seed, not the 64-byte secret. Pass just priv.encoded here."
        }
        val md = MessageDigest.getInstance("SHA-512")
        md.update(seed)
        val hash = md.digest()
        val x = hash.copyOfRange(0, 32)
        // RFC 7748 §5: clamp the scalar
        x[0] = (x[0].toInt() and 248).toByte()
        x[31] = ((x[31].toInt() and 127) or 64).toByte()
        return x
    }

    /**
     * Ed25519 SubjectPublicKeyInfo DER header (14 bytes). Followed by 32
     * bytes of raw public key. Layout:
     *   SEQUENCE (44 bytes)
     *     SEQUENCE (7 bytes)
     *       OID 1.3.101.112 (5 bytes)
     *       NULL (2 bytes)
     *     BIT STRING (35 bytes)
     *       unused bits = 0
     *       32 bytes key
     */
    private val ED25519_SPKI_HEADER: ByteArray =
        byteArrayOf(
            0x30, 0x2C,
            0x30, 0x07,
            0x06, 0x03, 0x2B, 0x65, 0x70,
            0x05, 0x00,
            0x03, 0x21,
            0x00,
        )

    private fun encodeEd25519PublicAsPem(pub: ByteArray): String {
        require(pub.size == 32)
        val der = ED25519_SPKI_HEADER + pub
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return "-----BEGIN PUBLIC KEY-----\n" +
            b64.chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----\n"
    }
}