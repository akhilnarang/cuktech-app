package dev.akhilnarang.cuktech.firmware

import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest

/**
 * Synthetic signed packages. They have the R2SF header, the signing tag and two real
 * X.509 P-256 certificates. The test root is not the pinned root, so every package
 * that passes the metadata checks must fail at the chain check.
 * A real signature is not tested: the pinned root signs only the vendor image,
 * which the repository does not contain.
 */
class FirmwarePackageTest {
    private companion object {
        const val MODEL = "njcuk.fitting.ad1204"
        // keytool: self-signed CN=test-root and CN=test-leaf signed by it, SHA256withECDSA.
        const val ROOT = "308201523081f9a00302010202090081278c14c06bf190300a06082a8648ce3d04030230143112301006035504031309746573742d726f6f743020170d3236313131363038323734385a180f32313236313032333038323734385a30143112301006035504031309746573742d726f6f743059301306072a8648ce3d020106082a8648ce3d03010703420004b592a521725b50ba2dd053adb1c6b3735ddd1aeb4cb24d08effcfa04de62ed50a656d7c5af6ca221eb12c69593313972d2a5cd1ba3347589db0719e1fbdb8619a3323030301d0603551d0e04160414b47144fe6373ceaafa243d207191b499fa1e1613300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502204a71ae7365627961f9c3d8aaf156df12bf93c627975ce8617f1854cd8ef20774022100f3b1dab6103aa66610af6b7e43de1273c2c521fb358d8e423f06269b4685233b"
        const val LEAF = "3082016330820108a0030201020208557c224f76ccc0ff300a06082a8648ce3d04030230143112301006035504031309746573742d726f6f743020170d3236313131363038323734385a180f32313236313032333038323734385a30143112301006035504031309746573742d6c6561663059301306072a8648ce3d020106082a8648ce3d030107034200047480030fa8d966ea5b10de09ce69f640822a513ac59522c8e1253f046d31cdcf00646dc32f09ffa629d2cd3a24eb912d455779b27c7d604f8b1c9b4cd96a0659a3423040301d0603551d0e04160414bb1d5c11ef8c147bdd0a17cacae4aafff8b7da4e301f0603551d23041830168014b47144fe6373ceaafa243d207191b499fa1e1613300a06082a8648ce3d0403020349003046022100aff7850134eb9eb43eb8d418a1508eeea78a8ef45c1184d4842ac440a26e4068022100a693190f8066870fff90f4846b52831bec281d21b174a474bed34a55a7791a83"
        val MAGIC = hex("000000004d49ef54464f544182562647")
        // Signed version 2.1.2 build 0x0049 = 73, so "2.1.2_0073".
        val V0073 = byteArrayOf(2, 1, 2, 0x49, 0)
        fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        fun md5(b: ByteArray) = MessageDigest.getInstance("MD5").digest(b).joinToString("") { "%02x".format(it) }
    }

    /**
     * Image body (1024 bytes, R2SF at 40), then the tag: magic, tagSize LE16, pid LE16,
     * image size LE32, certSize LE16, 2 reserved bytes, TLV fields, 4 trailing bytes.
     * The two DER certificates and a 72-byte signature follow the tag.
     */
    private fun pkg(pid: Int = 0x660e, model: String = MODEL, version: ByteArray = V0073,
                    header: String = "R2SF", imageSize: Int = 1024, extraField: ByteArray = ByteArray(0),
                    certs: ByteArray = hex(ROOT) + hex(LEAF)): ByteArray {
        val body = ByteArray(1024).also { header.toByteArray().copyInto(it, 40) }
        val fields = byteArrayOf(1, version.size.toByte()) + version +
            byteArrayOf(4, model.length.toByte()) + model.toByteArray() + extraField
        val tagSize = 28 + fields.size + 4
        fun le(v: Int, n: Int) = ByteArray(n) { (v shr (8 * it)).toByte() }
        val tag = MAGIC + le(tagSize, 2) + le(pid, 2) + le(imageSize, 4) + le(certs.size, 2) + ByteArray(2) +
            fields + ByteArray(4)
        return body + tag + certs + ByteArray(72) { 0x30 }
    }

    private fun info(b: ByteArray, model: String = MODEL, version: String = "2.1.2_0073") =
        FirmwareInfo(model, version, "", md5(b), "")

    private fun rejection(block: () -> Unit): String? {
        try { block() } catch (e: IllegalArgumentException) { return e.message }
        fail("the package must be rejected")
        return null
    }

    @Test fun wellFormedPackageFromAnotherRootIsRejectedByThePinnedRoot() {
        val b = pkg()
        val chain = "Firmware signing chain or image signature is invalid"
        assertEquals(chain, rejection { FirmwarePackage.validate(b, info(b)) })
        // importSigned derives model and version from the tag. A wrong derivation fails
        // earlier with a metadata message.
        assertEquals(chain, rejection { FirmwarePackage.importSigned(b) })
    }

    @Test fun headerSizeModelChecksumAndSigningTagChecksRejectBadPackages() {
        val good = pkg()
        val noTag = good.copyOf(1024)
        val cases = listOf(
            ByteArray(FirmwarePackage.MAX_SIZE + 1) to "The firmware is larger than the known staging limit",
            good to "Direct installation supports the China AD1204 model only",
            pkg(header = "R2SG") to "Invalid firmware image header",
            good to "Firmware checksum does not match Xiaomi's metadata",
            noTag to "Direct installation requires a signed Xiaomi package",
            pkg(imageSize = 1023) to "Invalid signing component boundaries",
            pkg(pid = 0x660f) to "Firmware product ID does not match the China AD1204",
            pkg(extraField = byteArrayOf(7, 9)) to "Invalid signing field",
            pkg(model = "njcuk.fitting.ad1205") to "Signed firmware model does not match",
            pkg(version = V0073.copyOf(4)) to "Invalid signed firmware version",
            pkg(certs = hex(ROOT)) to "Expected two signing certificates",
            good to "Signed firmware version does not match Xiaomi's metadata",
        )
        for ((i, case) in cases.withIndex()) {
            val (b, message) = case
            val meta = when (message) {
                "Direct installation supports the China AD1204 model only" -> info(b, model = "njcuk.fitting.1204e")
                "Firmware checksum does not match Xiaomi's metadata" -> info(b).copy(md5 = "0".repeat(32))
                "Signed firmware version does not match Xiaomi's metadata" -> info(b, version = "2.1.2_0074")
                else -> info(b)
            }
            assertEquals("row $i", message, rejection { FirmwarePackage.validate(b, meta) })
        }
        assertEquals("Select an official signed Xiaomi firmware package", rejection { FirmwarePackage.importSigned(noTag) })
    }
}
