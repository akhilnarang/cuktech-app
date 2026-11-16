package dev.akhilnarang.cuktech.firmware

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * A firmware image that passed all checks in [validate]. Make it with [importSigned] or [validate].
 *
 * The signature trust anchor is a pinned public key from the 0073 firmware, identified by its hash.
 * It does not come from the candidate image.
 *
 * @property bytes A private copy of the image.
 * @property info Metadata that the image matched.
 * @property sha256 SHA-256 of [bytes], as lowercase hex.
 */
class FirmwarePackage private constructor(val bytes: ByteArray, val info: FirmwareInfo, val sha256: String) {
    companion object {
/** The only model that direct installation supports (China AD1204). */
        const val MODEL = "njcuk.fitting.ad1204"
/** The only running version for which the app knows the direct install flow. */
        const val RECEIVER_VERSION = "2.1.2_0073"
/** Maximum image size, in bytes (0x7c000 = 507904). This is the known staging limit. */
        const val MAX_SIZE = 0x7c000
/** Metadata of the official 0073 package, from earlier research. It is not a live check for new firmware. The file stays on Xiaomi's CDN; the user downloads it. */
        val KNOWN_0073 = FirmwareInfo(MODEL, RECEIVER_VERSION,
            "https://iot-ota-cdn.io.mi.com/miio_fw/signed_0bd090bce659c906f3d933f55cc3027c_upd_njcuk.fitting.ad1204.bin",
            "0bd090bce659c906f3d933f55cc3027c", "Previously researched official Xiaomi package. Not a live check for newer firmware.")
        private val magic = hex("000000004d49ef54464f544182562647")
        private val root = hex("04bef58b02dae3fff8541aa0448fbac44db7c69a2fa8f0b1b6ff7ad951db6628fad7f020ea39a2ee867fdd783fdc2fb086095cc2850413a2802c627dbdc715f4f9")
        private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun requirePackage(ok: Boolean, message: String) { if (!ok) throw IllegalArgumentException(message) }

        /**
         * Makes a package from a local file. It reads the model and version from the signing tag.
         * This metadata is accepted only after the independent pinned-root check in [validate].
         * @throws IllegalArgumentException If the file is not an official signed package or a check fails.
         */
        fun importSigned(input: ByteArray): FirmwarePackage {
            requirePackage(input.size in 1024..MAX_SIZE, "The firmware is larger than the known staging limit")
            val tag = (input.size - magic.size downTo 0).firstOrNull { at -> magic.indices.all { input[at + it] == magic[it] } }
                ?: throw IllegalArgumentException("Select an official signed Xiaomi firmware package")
            requirePackage(tag + 28 <= input.size, "Truncated signing header")
            val size = (input[tag + 16].toInt() and 255) or ((input[tag + 17].toInt() and 255) shl 8)
            requirePackage(size >= 32 && tag + size <= input.size, "Invalid signing tag size")
            var cursor = tag + 28
            val fields = mutableMapOf<Int, ByteArray>()
            while (cursor < tag + size - 4) {
                requirePackage(cursor + 2 <= tag + size - 4, "Truncated signing field")
                val type = input[cursor].toInt() and 255
                val length = input[cursor + 1].toInt() and 255
                requirePackage(cursor + 2 + length <= tag + size - 4 && type !in fields, "Invalid signing field")
                fields[type] = input.copyOfRange(cursor + 2, cursor + 2 + length)
                cursor += 2 + length
            }
            val version = fields[1] ?: throw IllegalArgumentException("Missing signed version")
            requirePackage(version.size == 5, "Invalid signed version")
            val v = version.map { it.toInt() and 255 }
            val name = "${v[0]}.${v[1]}.${v[2]}_${(v[3] or (v[4] shl 8)).toString().padStart(4, '0')}"
            val model = fields[4]?.toString(Charsets.US_ASCII) ?: ""
            val info = FirmwareInfo(model, name, "", MessageDigest.getInstance("MD5").digest(input).toHex(),
                "Imported official signed package. This is not a check for newer firmware.")
            return validate(input, info)
        }

/**
 * Checks an image against [info] and returns a package.
 *
 * Checks: size 1024..[MAX_SIZE] bytes, model [MODEL], `R2SF` at offset 40, MD5, signing tag
 * boundaries, pid 0x660e, signed model and signed version. Then it checks the two-certificate
 * chain against the pinned root and the ECDSA P-256 SHA-256 image signature.
 *
 * @param input The image. It is copied.
 * @param info Expected metadata.
 * @throws IllegalArgumentException If a check fails. The message is safe to show to the user.
 */
        fun validate(input: ByteArray, info: FirmwareInfo): FirmwarePackage {
            val b = input.clone()
            requirePackage(b.size in 1024..MAX_SIZE, "The firmware is larger than the known staging limit")
            requirePackage(info.model == MODEL, "Direct installation supports the China AD1204 model only")
            requirePackage(String(b, 40, 4, Charsets.US_ASCII) == "R2SF", "Invalid firmware image header")
            val md5 = MessageDigest.getInstance("MD5").digest(b).toHex()
            requirePackage(md5.equals(info.md5, true), "Firmware checksum does not match Xiaomi's metadata")
            val tag = (b.size - magic.size downTo 0).firstOrNull { at ->
                magic.indices.all { b[at + it] == magic[it] }
            } ?: throw IllegalArgumentException("Direct installation requires a signed Xiaomi package")
            requirePackage(tag + 28 <= b.size, "Truncated signing header")
            val fields = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            val tagSize = fields.getShort(tag + 16).toInt() and 65535
            val pid = fields.getShort(tag + 18).toInt() and 65535
            val size = fields.getInt(tag + 20)
            val certSize = fields.getShort(tag + 24).toInt() and 65535
            val certAt = tag + tagSize
            val signatureAt = certAt + certSize
            requirePackage(tagSize >= 32 && size == tag && certSize > 0 && signatureAt < b.size,
                "Invalid signing component boundaries")
            requirePackage(pid == 0x660e, "Firmware product ID does not match the China AD1204")
            var cursor = tag + 28
            val values = mutableMapOf<Int, ByteArray>()
            while (cursor < certAt - 4) {
                requirePackage(cursor + 2 <= certAt - 4, "Truncated signing field")
                val type = b[cursor].toInt() and 255
                val length = b[cursor + 1].toInt() and 255
                requirePackage(cursor + 2 + length <= certAt - 4 && type !in values, "Invalid signing field")
                values[type] = b.copyOfRange(cursor + 2, cursor + 2 + length)
                cursor += 2 + length
            }
            requirePackage(values[4]?.contentEquals(MODEL.toByteArray(Charsets.US_ASCII)) == true,
                "Signed firmware model does not match")
            val version = values[1] ?: throw IllegalArgumentException("Missing signed firmware version")
            requirePackage(version.size == 5, "Invalid signed firmware version")
            val v = version.map { it.toInt() and 255 }
            val name = "${v[0]}.${v[1]}.${v[2]}_${(v[3] or (v[4] shl 8)).toString().padStart(4, '0')}"
            requirePackage(name == info.version, "Signed firmware version does not match Xiaomi's metadata")
            try {
                val certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(b.copyOfRange(certAt, signatureAt).inputStream())
                    .map { it as X509Certificate }
                requirePackage(certificates.size == 2, "Expected two signing certificates")
                val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                    .getParameterSpec(ECParameterSpec::class.java)
                val point = ECPoint(BigInteger(1, root.copyOfRange(1, 33)), BigInteger(1, root.copyOfRange(33, 65)))
                val trusted = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, parameters))
                certificates[0].verify(trusted)
                certificates[1].verify(certificates[0].publicKey)
                val verifier = Signature.getInstance("SHA256withECDSA")
                verifier.initVerify(certificates[1].publicKey)
                verifier.update(b, 0, certAt)
                requirePackage(verifier.verify(b.copyOfRange(signatureAt, b.size)), "Invalid firmware signature")
            } catch (e: java.security.GeneralSecurityException) {
                throw IllegalArgumentException("Firmware signing chain or image signature is invalid", e)
            }
            return FirmwarePackage(b, info, MessageDigest.getInstance("SHA-256").digest(b).toHex())
        }

/** Lowercase hex, two characters per byte. */
        internal fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
