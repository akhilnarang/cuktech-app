package dev.akhilnarang.cuktech.bind

import dev.akhilnarang.cuktech.proto.GattPort
import dev.akhilnarang.cuktech.proto.MiProto
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

/** Parcel upload on the AVDTP register channel, driven through a fake charger port. */
class RegisterLinkTest {
    /** Fake charger. [script] gets each AVDTP write and can answer with [send]. */
    private class Port(val script: Port.(ByteArray) -> Unit) : GattPort {
        lateinit var cb: GattPort.Callbacks
        val avdtp = mutableListOf<ByteArray>()
        var count = 0
        override fun setCallbacks(callbacks: GattPort.Callbacks) { cb = callbacks }
        override fun connect(mac: String) = cb.onConnected()
        override fun discoverServices() = cb.onServicesDiscovered(true)
        override fun requestMtu(mtu: Int) = cb.onMtu(mtu)
        override fun subscribe(uuid: String) = cb.onSubscribed(uuid, true)
        override fun write(uuid: String, data: ByteArray): Boolean {
            if (uuid == MiProto.AVDTP_UUID) {
                avdtp += data.clone()
                if (isAnnouncement(data)) count = (data[4].toInt() and 255) or ((data[5].toInt() and 255) shl 8)
                script(data)
            }
            return true
        }
        override fun disconnect() = cb.onDisconnected(0)
        override fun close() {}
        fun send(vararg b: Int) = cb.onNotify(MiProto.AVDTP_UUID, ByteArray(b.size) { b[it].toByte() })
        fun index(data: ByteArray) = (data[0].toInt() and 255) or ((data[1].toInt() and 255) shl 8)
        fun isAnnouncement(data: ByteArray) = data.size == 6 && data[0] == 0.toByte() && data[1] == 0.toByte() && data[2] == 0.toByte()
        fun isLastFrame(data: ByteArray) = !isAnnouncement(data) && index(data) == count
    }

    private suspend fun link(port: Port) = RegisterLink(port).also { it.open("test-target") }

    private suspend fun failure(block: suspend () -> Unit): String {
        try { block() } catch (e: BindException) { return e.message.orEmpty() }
        fail("the transfer must fail")
        error("unreachable")
    }

    /** Answers the announcement with RCV_RDY and the last frame with RCV_OK. */
    private val accept: Port.(ByteArray) -> Unit = {
        if (isAnnouncement(it)) send(0, 0, 1, 1) else if (isLastFrame(it)) send(0, 0, 1, 0)
    }

    @Test fun framesStayEighteenBytesAtLargeMtu() = runTest {
        val port = Port(accept)
        val link = link(port) // The fake port reports MTU 247.
        val blob = ByteArray(92) { it.toByte() }
        link.sendBindBlob(blob)
        // 92 B = 5 x 18 + 2, so 6 frames. Announcement: 00 00 00 code=00 count=0006 LE.
        assertArrayEquals(byteArrayOf(0, 0, 0, 0, 6, 0), port.avdtp[0])
        val frames = port.avdtp.drop(1)
        assertEquals(listOf(20, 20, 20, 20, 20, 4), frames.map { it.size })
        assertEquals(listOf(1, 2, 3, 4, 5, 6), frames.map { port.index(it) })
        assertArrayEquals(blob, frames.fold(ByteArray(0)) { a, f -> a + f.copyOfRange(2, f.size) })

        port.avdtp.clear()
        link.sendCloudCert(ByteArray(100) { it.toByte() })
        // 100 B = 5 x 18 + 10, so 6 frames. Code 07 is the cloud certificate.
        assertArrayEquals(byteArrayOf(0, 0, 0, 7, 6, 0), port.avdtp[0])
        assertEquals(listOf(20, 20, 20, 20, 20, 12), port.avdtp.drop(1).map { it.size })
    }

    @Test fun resendRequestRepeatsTheSameFrameAndInvalidIndexFails() = runTest {
        var asked = false
        val port = Port {
            if (isAnnouncement(it)) send(0, 0, 1, 1)
            else if (isLastFrame(it) && !asked) { asked = true; send(0, 0, 1, 5, 3, 0) }
            else if (asked) send(0, 0, 1, 0)
        }
        link(port).sendBindBlob(ByteArray(92) { it.toByte() })
        // Announcement, frames 1..6, then frame 3 again.
        assertEquals(8, port.avdtp.size)
        assertArrayEquals(port.avdtp[3], port.avdtp[7])
        assertEquals(3, port.index(port.avdtp[7]))

        for (sn in listOf(0, 7)) {
            val bad = Port {
                if (isAnnouncement(it)) send(0, 0, 1, 1) else if (isLastFrame(it)) send(0, 0, 1, 5, sn, 0)
            }
            assertEquals("parcel 0x00 (92 bytes): charger kept asking for frame $sn",
                failure { link(bad).sendBindBlob(ByteArray(92)) })
            assertEquals(7, bad.avdtp.size)
        }
    }

    private suspend fun TestScope.assertAbort(code: Int, beforeReady: Boolean) {
        val port = Port {
            if (isAnnouncement(it)) {
                if (beforeReady) send(0, 0, 1, code) else send(0, 0, 1, 1)
            } else if (isLastFrame(it)) send(0, 0, 1, code)
        }
        val link = link(port)
        val start = testScheduler.currentTime
        assertEquals("parcel 0x00 (92 bytes): charger aborted the transfer (%02x)".format(code),
            failure { link.sendBindBlob(ByteArray(92)) })
        assertEquals("no wait for a timeout", start, testScheduler.currentTime)
        assertEquals("no write after the abort", if (beforeReady) 1 else 7, port.avdtp.size)
    }

    @Test fun abortStopsTheTransferAtOnce() = runTest {
        for (code in listOf(3, 4)) for (beforeReady in listOf(false, true)) assertAbort(code, beforeReady)
    }

    /** Charger that asks for frame 3 again [asks] times after the last frame, then confirms. */
    private fun asking(asks: Int): Port {
        var asked = 0
        return Port {
            if (isAnnouncement(it)) send(0, 0, 1, 1)
            else if (isLastFrame(it) || (asked > 0 && index(it) == 3)) {
                if (asked < asks) { asked++; send(0, 0, 1, 5, 3, 0) } else send(0, 0, 1, 0)
            }
        }
    }

    @Test fun eightResendRequestsAreServedAndTheNinthFails() = runTest {
        val ok = asking(8)
        link(ok).sendBindBlob(ByteArray(92))
        assertEquals(1 + 6 + 8, ok.avdtp.size)
        val bad = asking(9)
        assertEquals("parcel 0x00 (92 bytes): charger kept asking for frame 3", failure { link(bad).sendBindBlob(ByteArray(92)) })
        assertEquals(1 + 6 + 8, bad.avdtp.size)
    }
}
