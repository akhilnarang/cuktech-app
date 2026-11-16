package dev.akhilnarang.cuktech.bind

import dev.akhilnarang.cuktech.proto.AesCcm
import dev.akhilnarang.cuktech.proto.MiCrypto
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * Crypto for the Mi BLE register (ECDH bind). Pure JVM code without android.* imports.
 * All functions are stateless and thread-safe.
 */
internal object BindCrypto {
    private val SETUP_INFO = "mible-setup-info".toByteArray()
    private val BLOB_NONCE = ByteArray(12) { (16 + it).toByte() } // 0x10..0x1b
    private val BLOB_AAD = "devID".toByteArray()

    /**
     * Keys that [deriveRegister] makes from the ECDH shared secret.
     *
     * @property token 12-byte login token. The app keeps it for later offline logins.
     * @property bindKey 16-byte bind key. The app sends it to the Xiaomi cloud.
     * @property aKey 16-byte AES-CCM key that encrypts the bind blob.
     */
    class RegisterSecrets(val token: ByteArray, val bindKey: ByteArray, val aKey: ByteArray)

    /**
     * Device info that the charger sends at the start of the register.
     *
     * @property version Standard-auth version. The app supports only version 2.
     * @property capsInOut IO capability byte. A low nibble that is not 0 means OOB input.
     * @property caps2 Second capability byte. The app echoes it back unchanged.
     * @property factoryDid Factory DID as ASCII digits. Can be empty.
     */
    class DevInfo(val version: Int, val capsInOut: Int, val caps2: Int, val factoryDid: String)

    /**
     * Makes a new random EC key pair on curve secp256r1 (P-256).
     *
     * @return The new key pair.
     */
    fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /**
     * Encodes the public key as the raw point that the charger expects.
     *
     * @param kp Key pair from [generateKeyPair].
     * @return 64 bytes: X || Y, each 32 bytes big-endian, without the 0x04 prefix.
     */
    fun publicKeyBytes(kp: KeyPair): ByteArray {
        val w = (kp.public as ECPublicKey).w
        return fixed32(w.affineX) + fixed32(w.affineY)
    }

    /**
     * Does the ECDH key agreement with the public key of the charger.
     *
     * @param kp Local key pair from [generateKeyPair].
     * @param peer64 Charger public key: X || Y, 64 bytes, without the 0x04 prefix.
     * @return The 32-byte shared secret. Clear it after use.
     * @throws IllegalArgumentException If [peer64] is not 64 bytes.
     * @throws java.security.GeneralSecurityException If the point is not on the curve.
     */
    fun ecdh(kp: KeyPair, peer64: ByteArray): ByteArray {
        require(peer64.size == 64) { "device pubkey must be 64 bytes, got ${peer64.size}" }
        val params = (kp.public as ECPublicKey).params
        val point = ECPoint(BigInteger(1, peer64.copyOfRange(0, 32)), BigInteger(1, peer64.copyOfRange(32, 64)))
        val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
        return KeyAgreement.getInstance("ECDH").run {
            init(kp.private)
            doPhase(peer, true)
            generateSecret()
        }
    }

    /**
     * Derives the register keys with HKDF-SHA256, info "mible-setup-info", 64 output bytes.
     * The salt is "none", which is 32 zero bytes per RFC 5869.
     * Output split: token[0:12], bind_key[12:28], a_key[28:44].
     *
     * @param shared ECDH shared secret from [ecdh].
     * @return The derived keys.
     */
    fun deriveRegister(shared: ByteArray): RegisterSecrets {
        val out = MiCrypto.hkdfSha256(shared, ByteArray(32), SETUP_INFO, 64)
        return RegisterSecrets(out.copyOfRange(0, 12), out.copyOfRange(12, 28), out.copyOfRange(28, 44))
    }

    /**
     * Makes the 20-byte DID field of the bind blob. Removes leading 0x00 bytes, then
     * left-pads with 0x00 to 20 bytes.
     *
     * @param did DID from the Xiaomi cloud, as ASCII.
     * @return 20 bytes.
     * @throws IllegalArgumentException If the DID is longer than 20 bytes.
     */
    fun normalizeDid(did: String): ByteArray {
        val raw = did.toByteArray(Charsets.US_ASCII).dropWhile { it == 0.toByte() }.toByteArray()
        require(raw.size <= 20) { "DID is ${raw.size} bytes; maximum is 20" }
        return ByteArray(20 - raw.size) + raw
    }

    /**
     * Builds the bind blob for parcel code 0x00.
     * Format: AES-CCM(a_key, did20 || cloud_sign[64] || utc_le[4]) with a 4-byte tag,
     * nonce 0x10..0x1b and AAD "devID".
     *
     * @param did20 DID field from [normalizeDid], 20 bytes.
     * @param cloudSign Signature from the Xiaomi cloud, 64 bytes.
     * @param utc Cloud UTC time in seconds, range 1..0xFFFFFFFF.
     * @param aKey 16-byte key from [RegisterSecrets.aKey].
     * @return 92 bytes: 88 bytes of ciphertext and a 4-byte tag.
     * @throws IllegalArgumentException If a size or [utc] is out of range.
     */
    fun buildBindBlob(did20: ByteArray, cloudSign: ByteArray, utc: Long, aKey: ByteArray): ByteArray {
        require(did20.size == 20) { "DID field must be 20 bytes" }
        require(cloudSign.size == 64) { "cloud_sign must decode to 64 bytes, got ${cloudSign.size}" }
        require(utc in 1..0xFFFFFFFFL) { "utc out of range: $utc" }
        val utcLe = ByteArray(4) { (utc shr (8 * it)).toByte() }
        return AesCcm(aKey, 4).encrypt(BLOB_NONCE, did20 + cloudSign + utcLe, BLOB_AAD)
    }

    /**
     * Parses the device-info payload.
     * Version 2 layout: [0:2] version LE, [2] IO caps, [3] caps2, [4:24] DID field.
     * For version 1 and 2, the DID field is all bytes after offset 4.
     *
     * @param d Raw payload.
     * @return The parsed info. Leading 0x00 bytes are removed from the DID.
     * @throws IllegalArgumentException If the payload is shorter than 4 bytes, the version
     *   is higher than 3, or the DID is longer than 20 bytes or has non-digit characters.
     */
    fun parseDevInfo(d: ByteArray): DevInfo {
        require(d.size >= 4) { "device info too short: ${d.size} bytes" }
        val version = (d[0].toInt() and 0xff) or ((d[1].toInt() and 0xff) shl 8)
        require(version <= 3) { "device reports unsupported auth version $version" }
        val field = when {
            d.size <= 4 -> ByteArray(0)
            version < 3 -> d.copyOfRange(4, d.size)
            else -> d.copyOfRange(4, minOf(24, d.size))
        }
        val did = field.dropWhile { it == 0.toByte() }.toByteArray()
        require(did.size <= 20) { "device-info DID field is ${did.size} bytes; maximum is 20" }
        require(did.all { it in '0'.code..'9'.code }) { "device-info DID field contains non-digit characters" }
        return DevInfo(version, d[2].toInt() and 0xff, d[3].toInt() and 0xff, String(did, Charsets.US_ASCII))
    }

    // Unsigned big-endian, left-padded to 32 bytes.
    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - b.size) + b
    }
}
