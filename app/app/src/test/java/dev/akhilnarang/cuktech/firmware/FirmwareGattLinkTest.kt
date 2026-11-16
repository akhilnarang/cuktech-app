package dev.akhilnarang.cuktech.firmware

import dev.akhilnarang.cuktech.proto.GattPort
import dev.akhilnarang.cuktech.proto.MiCrypto
import dev.akhilnarang.cuktech.proto.MiProto
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class FirmwareGattLinkTest {
    private class Port : GattPort {
        lateinit var cb: GattPort.Callbacks
        val token = ByteArray(12) { (it + 1).toByte() }
        val deviceRandom = ByteArray(16) { (it + 30).toByte() }
        lateinit var appRandom: ByteArray
        var code = 0
        val codes = mutableListOf<Int>()
        var count = 0
        var buffer = byteArrayOf()
        var payload18 = false
        var noWriteCompletion = false
        var badProof = false
        var badProbe = false
        var closed = false
        override fun setCallbacks(callbacks: GattPort.Callbacks) { cb = callbacks }
        override fun connect(mac: String) { cb.onConnected() }
        override fun discoverServices() { cb.onServicesDiscovered(true) }
        override fun requestMtu(mtu: Int) = error("MTU request must not replace reliable negotiation")
        override fun subscribe(uuid: String) { cb.onSubscribed(uuid, true) }
        private fun notify(uuid: String, b: ByteArray) { cb.onNotify(uuid, b) }
        override fun write(uuid: String, b: ByteArray): Boolean {
            if (!noWriteCompletion) cb.onWritten(uuid)
            if (uuid == MiProto.UPNP_UUID) {
                if (b.contentEquals(byteArrayOf(0xa4.toByte()))) notify(MiProto.AVDTP_UUID, byteArrayOf(0, 0, 4, 0, 6, 0xf2.toByte()))
                return true
            }
            if (b.size >= 4 && b[2] == 5.toByte() && b[0] == 0.toByte() && b[1] == 0.toByte()) {
                if (b[3] == 0.toByte()) {
                    payload18 = b[5] == 18.toByte()
                    notify(uuid, byteArrayOf(0, 0, 4, 1) + ByteArray(if (badProbe) 15 else 16) { 18 })
                }
                return true
            }
            if (b.contentEquals(MiProto.RCV_RDY)) {
                var proof = MiCrypto.hmacSha256(MiCrypto.deriveLogin(token, appRandom, deviceRandom).devKey, deviceRandom + appRandom)
                if (badProof) proof = proof.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
                notify(uuid, byteArrayOf(1, 0) + proof.copyOfRange(0, 18))
                notify(uuid, byteArrayOf(2, 0) + proof.copyOfRange(18, 32))
            } else if (b.contentEquals(MiProto.OFFICIAL_ACK)) {
                // Inline device-random reply was consumed.
            } else if (b.size == 6 && b[0] == 0.toByte() && b[1] == 0.toByte()) {
                code = b[3].toInt() and 255
                codes += code
                count = FirmwareTransfer.u16(b, 4)
                buffer = byteArrayOf()
                notify(uuid, MiProto.RCV_RDY)
            } else {
                buffer += b.copyOfRange(2, b.size)
                if (FirmwareTransfer.u16(b) == count) {
                    notify(uuid, MiProto.RCV_OK)
                    if (code == 0x0b) {
                        appRandom = buffer
                        notify(uuid, byteArrayOf(0, 0, 2, 0x0d) + deviceRandom)
                        notify(uuid, byteArrayOf(0, 0, 0, 0x0c, 2, 0))
                    } else if (code == 0x0a) {
                        val expected = MiCrypto.hmacSha256(MiCrypto.deriveLogin(token, appRandom, deviceRandom).appKey, appRandom + deviceRandom)
                        check(buffer.contentEquals(expected))
                        notify(MiProto.UPNP_UUID, MiProto.CFM_LOGIN_OK)
                    }
                }
            }
            return true
        }
        override fun read(uuid: String): Boolean { cb.onRead(uuid, "2.1.2_0073\u0000".toByteArray(), true); return true }
        override fun disconnect() { cb.onDisconnected(0) }
        override fun close() { closed = true }
    }

    @Test fun negotiatesEighteenBytesAndMutuallyAuthenticatesBeforeVersionRead() = runTest {
        val port = Port()
        val link = FirmwareGattLink(port)
        try {
            link.open("test-target", port.token)
            assertTrue(port.payload18)
            assertEquals("2.1.2_0073", link.version())
        } finally { link.close() }
        assertTrue(port.closed)
    }

    @Test fun invalidDeviceProofAndUnexpectedProbeAbortLogin() = runTest {
        for ((proof, message) in listOf(true to "Charger token authentication failed",
            false to "Charger did not confirm the 18-byte transport")) {
            val port = Port().apply { badProof = proof; badProbe = !proof }
            val link = FirmwareGattLink(port)
            try { link.open("test-target", port.token); fail("must reject invalid authentication/negotiation") }
            catch (e: IllegalStateException) { assertEquals(message, e.message) }
            finally { link.close() }
            assertFalse("no app proof (0x0a) after a failed check", 0x0a in port.codes)
        }
    }

    @Test fun queuedWriteWithoutGattCompletionTimesOut() = runTest {
        val port = Port().apply { noWriteCompletion = true }
        val link = FirmwareGattLink(port)
        try { link.open("test-target", port.token); fail("queued write must not count as delivered") }
        catch (e: IllegalStateException) { assertEquals("Timed out waiting for GATT write", e.message) }
        finally { link.close() }
    }
}
