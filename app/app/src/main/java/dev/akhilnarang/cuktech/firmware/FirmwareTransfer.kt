package dev.akhilnarang.cuktech.firmware

import java.util.zip.CRC32

/** GATT operations that [FirmwareTransfer] needs. Tests can use a fake. */
internal interface FirmwareWire {
/** Enables notifications on [uuid] and waits for the confirmation. */
    suspend fun subscribe(uuid: String)
/** Writes [bytes] to [uuid] and waits for the write completion. */
    suspend fun write(uuid: String, bytes: ByteArray)
/** Waits for the next notification from [uuid]. Throws if [timeoutMs] passes. */
    suspend fun receive(uuid: String, timeoutMs: Long = 20_000): ByteArray
}

/**
 * OTA transfer protocol. It has no Android dependencies.
 * Each fragment needs a transport ACK on [DATA], then a separate flash-commit event on [CONTROL].
 */
internal class FirmwareTransfer(private val wire: FirmwareWire) {
    companion object {
/** OTA control characteristic (0x0017): commands and commit events. */
        const val CONTROL = "00000017-0000-1000-8000-00805f9b34fb"
/** OTA data characteristic (0x0018): fragment pieces and ACKs. */
        const val DATA = "00000018-0000-1000-8000-00805f9b34fb"
/** Reads an unsigned little-endian 16-bit value at [offset]. */
        fun u16(b: ByteArray, offset: Int = 0): Int = (b[offset].toInt() and 255) or ((b[offset + 1].toInt() and 255) shl 8)
/** Encodes the low 16 bits of [n] as 2 little-endian bytes. */
        fun le16(n: Int) = byteArrayOf(n.toByte(), (n shr 8).toByte())
/** CRC-32 of the first [length] bytes of [b]. */
        fun crc(b: ByteArray, length: Int): Long = CRC32().apply { update(b, 0, length) }.value
/**
 * Removes the 2-byte notification header [kind, length] and returns the payload.
 * @throws IllegalStateException If the kind or length does not match.
 */
        fun envelope(b: ByteArray, kind: Int): ByteArray {
            check(b.size >= 2 && b[0].toInt() == kind && (b[1].toInt() and 255) == b.size - 2) {
                "Malformed firmware notification"
            }
            return b.copyOfRange(2, b.size)
        }
    }

// Sends a control command and returns the response payload after the id and status bytes.
    private suspend fun command(id: Int, params: ByteArray = byteArrayOf()): ByteArray {
        wire.write(CONTROL, le16(id) + byteArrayOf(params.size.toByte()) + params)
        val response = envelope(wire.receive(CONTROL), 1)
        check(response.size >= 3 && u16(response) == id) { "Unexpected firmware command response" }
        check(response[2] == 0.toByte()) { "Charger rejected firmware command $id (status ${response[2].toInt() and 255})" }
        return response.copyOfRange(3, response.size)
    }

/**
 * Sends a firmware image and asks the charger to verify it.
 *
 * The image goes in 512-byte fragments. Each fragment goes in 18-byte pieces with a 2-byte index.
 * If the charger reports an earlier prefix with a matching CRC-32, the transfer continues from there.
 * A fragment can use a maximum of 10 ACK rounds.
 *
 * @param bytes The complete, checked image.
 * @param progress Called with the committed bytes and the total bytes.
 * @param phase Called with a short user-facing text when a new step starts.
 * @throws IllegalStateException If the charger rejects a step or sends a reply that is not valid.
 */
    suspend fun send(bytes: ByteArray, progress: (Int, Int) -> Unit, phase: (String) -> Unit) {
        wire.subscribe(CONTROL)
        wire.subscribe(DATA)
        val protocol = command(1)
        check(protocol.size == 2 && u16(protocol) in 2..4) { "Unsupported firmware transfer protocol" }
        val size = command(2)
        check(size.size == 2 && u16(size) == 512) { "Charger did not accept the 18-byte transport negotiation" }
        val fragmentSize = 512
        val resume = command(3)
        check(resume.size == 6) { "Invalid firmware resume response length" }
        val count = (bytes.size + fragmentSize - 1) / fragmentSize
        val last = u16(resume)
        check(last <= count) { "Firmware resume index exceeds the selected package" }
        var remoteCrc = 0L
        for (i in 0..3) remoteCrc = remoteCrc or ((resume[i + 2].toLong() and 255) shl (i * 8))
        val prefix = minOf(last * fragmentSize, bytes.size)
        val start = if (last > 0 && crc(bytes, prefix) == remoteCrc) last else 0
        phase(if (start > 0) "Resuming verified firmware prefix" else "Writing firmware")
        progress(minOf(start * fragmentSize, bytes.size), bytes.size)
        for (index in start + 1..count) {
            val end = minOf(index * fragmentSize, bytes.size)
            val logical = le16(index) + bytes.copyOfRange((index - 1) * fragmentSize, end)
            val pieces = logical.toList().chunked(18).mapIndexed { i, piece -> le16(i + 1) + piece.toByteArray() }
            wire.write(DATA, byteArrayOf(0, 0, 0, 0) + le16(pieces.size))
            var started = false
            var complete = false
            var rounds = 0
            while (!complete) {
                check(++rounds <= 10) { "Firmware fragment exceeded its retry limit" }
                val ack = wire.receive(DATA, 6_000)
                check(ack.size >= 4 && ack[0] == 0.toByte() && ack[1] == 0.toByte() && ack[2] == 1.toByte()) {
                    "Invalid reliable-transfer acknowledgement"
                }
                when (ack[3].toInt() and 255) {
                    1 -> {
                        check(!started && ack.size == 4) { "Unexpected ready acknowledgement" }
                        started = true
                        pieces.forEach { wire.write(DATA, it) }
                    }
                    5 -> {
                        check(started && ack.size >= 6 && ack.size % 2 == 0) { "Invalid missing-piece request" }
                        val missing = (4 until ack.size step 2).map { u16(ack, it) }
                        check(missing.distinct().size == missing.size && missing.all { it in 1..pieces.size }) {
                            "Missing-piece index is outside the pending fragment"
                        }
                        missing.forEach { wire.write(DATA, pieces[it - 1]) }
                    }
                    0 -> { check(started && ack.size == 4) { "Unexpected completion acknowledgement" }; complete = true }
                    else -> error("Charger rejected a reliable firmware fragment")
                }
            }
            val committed = envelope(wire.receive(CONTROL), 2)
            check(committed.size == 3 && u16(committed, 1) == index) { "Firmware commit index does not match the pending fragment" }
            check(committed[0] == 0.toByte()) { "Charger failed to commit firmware fragment $index" }
            progress(end, bytes.size)
        }
        phase("Verifying signature and preparing restart")
        check(command(4, byteArrayOf(1, 0, 0, 0)).isEmpty()) { "Unexpected firmware verification response" }
    }
}
