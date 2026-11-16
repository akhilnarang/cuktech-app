package dev.akhilnarang.cuktech.firmware

import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.util.ArrayDeque

class FirmwareTransferTest {
    private class Wire(val image: ByteArray) : FirmwareWire {
        val sent = mutableListOf<Pair<String, ByteArray>>()
        val control = ArrayDeque<ByteArray>()
        val data = ArrayDeque<ByteArray>()
        var last = 0
        var crc = 0L
        var badCommit = false
        var commitFailure = false
        var missing = false
        var invalidMissing = false
        var announced = 0
        var firmwareIndex = 0
        var awaitResend = false
        override suspend fun subscribe(uuid: String) = Unit
        override suspend fun receive(uuid: String, timeoutMs: Long) =
            (if (uuid == FirmwareTransfer.CONTROL) control else data).pollFirst() ?: error("No scripted notification")
        private fun response(command: Int, params: ByteArray) {
            control.add(byteArrayOf(1, (3 + params.size).toByte()) + FirmwareTransfer.le16(command) + byteArrayOf(0) + params)
        }
        private fun committed() {
            data.add(byteArrayOf(0, 0, 1, 0))
            control.add(byteArrayOf(2, 3, if (commitFailure) 5 else 0) + FirmwareTransfer.le16(firmwareIndex + if (badCommit) 1 else 0))
        }
        override suspend fun write(uuid: String, bytes: ByteArray) {
            sent.add(uuid to bytes.clone())
            if (uuid == FirmwareTransfer.CONTROL) {
                when (FirmwareTransfer.u16(bytes)) {
                    1 -> response(1, byteArrayOf(4, 0))
                    2 -> response(2, byteArrayOf(0, 2))
                    3 -> response(3, FirmwareTransfer.le16(last) + ByteArray(4) { (crc shr (8 * it)).toByte() })
                    4 -> response(4, byteArrayOf())
                }
            } else {
                val piece = FirmwareTransfer.u16(bytes)
                if (piece == 0) {
                    announced = FirmwareTransfer.u16(bytes, 4)
                    data.add(byteArrayOf(0, 0, 1, 1))
                } else {
                    if (piece == 1) firmwareIndex = FirmwareTransfer.u16(bytes, 2)
                    if (awaitResend) { awaitResend = false; committed() }
                    else if (piece == announced) {
                        if (missing || invalidMissing) {
                            data.add(byteArrayOf(0, 0, 1, 5) + FirmwareTransfer.le16(if (invalidMissing) announced + 1 else 1))
                            awaitResend = true
                            missing = false
                        } else committed()
                    }
                }
            }
        }
        fun activationSent() = sent.any { it.first == FirmwareTransfer.CONTROL && FirmwareTransfer.u16(it.second) == 4 }
        fun firstFirmwareIndex() = sent.first { it.first == FirmwareTransfer.DATA && FirmwareTransfer.u16(it.second) == 1 }
            .second.let { FirmwareTransfer.u16(it, 2) }
    }

    @Test fun fullAndShortFragmentsRequireCommitBeforeActivation() = runTest {
        val bytes = ByteArray(513) { it.toByte() }
        val w = Wire(bytes)
        val progress = mutableListOf<Int>()
        FirmwareTransfer(w).send(bytes, { n, _ -> progress.add(n) }, {})
        assertEquals(listOf(0, 512, 513), progress)
        assertTrue(w.activationSent())
        assertArrayEquals(byteArrayOf(1, 0, 2, 0, 0), w.sent.last { it.first == FirmwareTransfer.DATA }.second)
        assertArrayEquals(byteArrayOf(4, 0, 4, 1, 0, 0, 0), w.sent.last().second)
    }

    @Test fun validPrefixResumesAndMismatchRestartsAtOne() = runTest {
        val b = ByteArray(1100) { (it * 7).toByte() }
        for (valid in listOf(true, false)) {
            val w = Wire(b).apply { last = 1; crc = java.util.zip.CRC32().apply { update(b, 0, 512) }.value xor if (valid) 0L else 1L }
            FirmwareTransfer(w).send(b, { _, _ -> }, {})
            assertEquals(if (valid) 2 else 1, w.firstFirmwareIndex())
        }
    }

    @Test fun mismatchedOrFailedCommitNeverAdvancesOrActivates() = runTest {
        for (badIndex in listOf(true, false)) {
            val b = ByteArray(512)
            val w = Wire(b).apply { badCommit = badIndex; commitFailure = !badIndex }
            val progress = mutableListOf<Int>()
            try { FirmwareTransfer(w).send(b, { n, _ -> progress.add(n) }, {}); fail("must reject commit") }
            catch (_: IllegalStateException) { }
            assertEquals(listOf(0), progress)
            assertFalse(w.activationSent())
        }
    }

    @Test fun missingPieceResentButOutOfRangeIndexRejected() = runTest {
        for (invalid in listOf(false, true)) {
            val b = ByteArray(512)
            val w = Wire(b).apply { missing = !invalid; invalidMissing = invalid }
            try {
                FirmwareTransfer(w).send(b, { _, _ -> }, {})
                assertFalse(invalid)
                assertEquals(2, w.sent.count { it.first == FirmwareTransfer.DATA && FirmwareTransfer.u16(it.second) == 1 })
            } catch (_: IllegalStateException) { assertTrue(invalid) }
            assertEquals(!invalid, w.activationSent())
        }
    }

    @Test fun notificationLengthAndKindMustMatchExactly() {
        for (b in listOf(byteArrayOf(1), byteArrayOf(1, 3, 4), byteArrayOf(2, 0))) {
            try { FirmwareTransfer.envelope(b, 1); fail("must reject malformed envelope") }
            catch (_: IllegalStateException) { }
        }
    }

    @Test fun outOfRangeResumeNeverStartsDataOrActivation() = runTest {
        val b = ByteArray(512)
        val w = Wire(b).apply { last = 2 }
        try { FirmwareTransfer(w).send(b, { _, _ -> }, {}); fail("must reject resume") }
        catch (_: IllegalStateException) { }
        assertFalse(w.sent.any { it.first == FirmwareTransfer.DATA })
        assertFalse(w.activationSent())
    }
}
