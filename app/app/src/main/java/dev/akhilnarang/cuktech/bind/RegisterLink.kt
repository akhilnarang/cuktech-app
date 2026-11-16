package dev.akhilnarang.cuktech.bind

import dev.akhilnarang.cuktech.proto.GattPort
import dev.akhilnarang.cuktech.proto.MiProto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException

/**
 * A bind step failed. The message is for the user.
 *
 * @param message Reason for the failure.
 */
class BindException(message: String) : IOException(message)

/**
 * Coroutine wrapper over a [GattPort] with the v2 register channel and parcel
 * protocol. It is a port of blebind.py V2RegisterClient.
 * Use it on the main thread only, because the port and its write queue post every
 * callback there. The class does not log frame contents.
 * After the first transport failure, all later calls throw that failure.
 *
 * @param port GATT transport. Production uses AndroidGattPort.
 */
internal class RegisterLink(private val port: GattPort) : GattPort.Callbacks {
    private val connected = CompletableDeferred<Unit>()
    private val services = CompletableDeferred<Unit>()
    private val mtuDone = CompletableDeferred<Int>()
    private val disconnected = CompletableDeferred<Unit>()
    private val subs = HashMap<String, CompletableDeferred<Unit>>()
    private val upnp = Channel<ByteArray>(64)
    private val avdtp = Channel<ByteArray>(64)
    private var failure: Throwable? = null

    init {
        port.setCallbacks(this)
    }

    // ------------------------------------------------------------ transport

    /**
     * Connects (15 s), discovers services (10 s), requests MTU 247 (5 s, optional), then
     * subscribes AVDTP before UPNP (5 s each). This is the register order that works on hardware.
     *
     * @param address BLE address of the charger.
     * @throws BindException If a step fails or times out.
     */
    suspend fun open(address: String) {
        port.connect(address)
        step(15_000, "connect") { connected.await() }
        port.discoverServices()
        step(10_000, "service discovery") { services.await() }
        port.requestMtu(247)
        withTimeoutOrNull(5_000) { mtuDone.await() }
        subscribe(MiProto.AVDTP_UUID)
        subscribe(MiProto.UPNP_UUID)
    }

    private suspend fun subscribe(uuid: String) {
        val d = CompletableDeferred<Unit>().also { subs[uuid] = it }
        failure?.let { throw it }
        port.subscribe(uuid)
        step(5_000, "subscribe ${uuid.substring(4, 8)}") { d.await() }
    }

    /** Disconnects, waits up to 3 s for the disconnect callback, then closes the port. */
    suspend fun close() {
        port.disconnect()
        withTimeoutOrNull(3_000) { disconnected.await() }
        port.close()
    }

    private fun write(uuid: String, data: ByteArray) {
        failure?.let { throw it }
        if (!port.write(uuid, data)) throw BindException("GATT write was not accepted")
    }

    private suspend fun <T> step(ms: Long, what: String, block: suspend () -> T): T = try {
        withTimeout(ms) { block() }
    } catch (e: TimeoutCancellationException) {
        throw BindException("timeout: $what")
    }

    private fun fail(e: Throwable) {
        if (failure != null) return
        failure = e
        listOf(connected, services).forEach { it.completeExceptionally(e) }
        mtuDone.complete(23)
        subs.values.forEach { it.completeExceptionally(e) }
        upnp.close(e)
        avdtp.close(e)
    }

    override fun onConnected() { connected.complete(Unit) }
    override fun onDisconnected(status: Int) {
        disconnected.complete(Unit)
        fail(BindException("charger disconnected (status $status)"))
    }
    override fun onServicesDiscovered(ok: Boolean) {
        if (ok) services.complete(Unit) else fail(BindException("service discovery failed"))
    }
    override fun onMtu(mtu: Int) { mtuDone.complete(mtu) }
    override fun onSubscribed(uuid: String, ok: Boolean) {
        if (ok) subs[uuid]?.complete(Unit) else fail(BindException("subscribe failed"))
    }
    override fun onNotify(uuid: String, data: ByteArray) {
        val ch = when (uuid) {
            MiProto.UPNP_UUID -> upnp
            MiProto.AVDTP_UUID -> avdtp
            else -> return
        }
        // never continue with missing protocol frames
        if (ch.trySend(data).isFailure) fail(BindException("notification queue overflow"))
    }
    override fun onWriteFailed(uuid: String, reason: String) { fail(BindException("GATT write failed: $reason")) }

    // ------------------------------------------------------------ protocol IO

    private suspend fun recv(ch: Channel<ByteArray>, ms: Long = TIMEOUT): ByteArray {
        val d = step(ms, "waiting for the charger") { ch.receive() }
        if (d.size == 4 && d[1] == 0.toByte() && d[2] == 0.toByte() && d[3] == 0.toByte()) {
            when (d[0].toInt() and 0xff) {
                0xe0 -> throw BindException("charger reports e0 (not registered)")
                0xe1, 0xe2, 0xe3 -> throw BindException("charger auth error %02x".format(d[0]))
            }
        }
        return d
    }

    // Throws if [d] is a transfer abort: 00 00 01 03 or 00 00 01 04.
    private fun checkAbort(d: ByteArray) {
        if (d.size >= 4 && d[0] == 0.toByte() && d[1] == 0.toByte() && d[2] == 1.toByte() &&
            (d[3] == 3.toByte() || d[3] == 4.toByte())) {
            throw BindException("charger aborted the transfer (%02x)".format(d[3]))
        }
    }

    // Sends [data] as an announced parcel on AVDTP and resends frames that the charger asks for.
    private suspend fun sendParcel(code: Int, data: ByteArray) {
        // fw 0x41eeb4 drops any non-last frame that isn't exactly 2 + 18 bytes (fragment size is
        // only raised by a negotiation we never run), so never size chunks by MTU
        val chunks = data.toList().chunked(18).map { it.toByteArray() }
        if (chunks.size > MAX_PARCELS) throw BindException("payload needs ${chunks.size} parcels")
        fun frame(i: Int) = byteArrayOf((i + 1).toByte(), ((i + 1) shr 8).toByte()) + chunks[i]
        try {
            write(MiProto.AVDTP_UUID, byteArrayOf(0, 0, 0, code.toByte(), chunks.size.toByte(), (chunks.size shr 8).toByte()))
            // Discard unrelated frames until RCV_RDY. An abort stops the transfer at once.
            while (true) {
                val d = recv(avdtp)
                if (d.contentEquals(MiProto.RCV_RDY)) break
                checkAbort(d)
            }
            chunks.indices.forEach { write(MiProto.AVDTP_UUID, frame(it)) }
            var resends = 0
            while (true) {
                val d = recv(avdtp)
                if (d.contentEquals(MiProto.RCV_OK)) return
                checkAbort(d)
                // fw 0x41f14c asks for a missing frame: 00 00 01 05 sn_lo sn_hi
                if (d.size >= 4 && d[0] == 0.toByte() && d[1] == 0.toByte() && d[2] == 1.toByte() && d[3] == 5.toByte()) {
                    val sn = if (d.size >= 6) (d[4].toInt() and 0xff) or ((d[5].toInt() and 0xff) shl 8) else 0
                    if (sn !in 1..chunks.size || ++resends > 8) throw BindException("charger kept asking for frame $sn")
                    write(MiProto.AVDTP_UUID, frame(sn - 1))
                }
            }
        } catch (e: BindException) {
            throw BindException("parcel 0x%02x (%d bytes): %s".format(code, data.size, e.message))
        }
    }

    // Reads an inline (variant 0x02) or a multi-frame (variant 0x00) payload with [code].
    private suspend fun recvPayload(code: Int): ByteArray {
        val ann = recv(avdtp)
        if (ann.size < 4 || ann[3].toInt() and 0xff != code) {
            throw BindException("unexpected announcement (expected code 0x%02x)".format(code))
        }
        return when (ann[2].toInt()) {
            0x02 -> ann.copyOfRange(4, ann.size).also { write(MiProto.AVDTP_UUID, MiProto.OFFICIAL_ACK) }
            0x00 -> recvParcel(ann)
            else -> throw BindException("unknown announcement variant")
        }
    }

    private suspend fun recvParcel(ann: ByteArray): ByteArray {
        if (ann.size < 6) throw BindException("short parcel announcement")
        val expected = (ann[4].toInt() and 0xff) or ((ann[5].toInt() and 0xff) shl 8)
        if (expected !in 1..MAX_PARCELS) throw BindException("invalid parcel count $expected")
        write(MiProto.AVDTP_UUID, MiProto.RCV_RDY)
        val frames = java.util.TreeMap<Int, ByteArray>()
        while (frames.size < expected) {
            val d = recv(avdtp)
            if (d.size < 2) throw BindException("short parcel")
            val idx = (d[0].toInt() and 0xff) or ((d[1].toInt() and 0xff) shl 8)
            if (idx !in 1..expected || idx in frames) throw BindException("bad parcel index $idx")
            frames[idx] = d.copyOfRange(2, d.size)
        }
        write(MiProto.AVDTP_UUID, MiProto.RCV_OK)
        return frames.values.fold(ByteArray(0)) { a, b -> a + b }
    }

    // ------------------------------------------------------------ register steps

    /**
     * Sends a2 on UPNP and reads the device-info payload.
     *
     * @return The device info.
     * @throws BindException If the payload is not valid, the version is not 2, or the
     *   charger needs OOB input.
     */
    suspend fun getDevInfo(): BindCrypto.DevInfo {
        write(MiProto.UPNP_UUID, byteArrayOf(0xa2.toByte(), 0, 0, 0))
        val info = try {
            BindCrypto.parseDevInfo(recvPayload(0x00))
        } catch (e: IllegalArgumentException) {
            throw BindException(e.message ?: "bad device info")
        }
        if (info.version != 2) throw BindException("charger uses standard-auth v${info.version}; only v2 is supported")
        if (info.capsInOut and 0x0f != 0) throw BindException("charger requires OOB input; unsupported")
        return info
    }

    /**
     * Sends 0x15 with the two capability bytes from [info] on UPNP.
     *
     * @param info Device info from [getDevInfo].
     * @throws BindException If the write is not accepted.
     */
    fun sendCapsEcho(info: BindCrypto.DevInfo) =
        write(MiProto.UPNP_UUID, byteArrayOf(0x15, info.capsInOut.toByte(), info.caps2.toByte()))

    /**
     * Sends the local public key as parcel 0x03.
     *
     * @param pub64 Public key, 64 bytes X || Y.
     * @throws BindException If the transfer fails.
     */
    suspend fun sendPubkey(pub64: ByteArray) = sendParcel(0x03, pub64)

    /**
     * Reads the charger public key (payload code 0x03).
     *
     * @return 64 bytes X || Y.
     * @throws BindException If the payload is not 64 bytes or the read fails.
     */
    suspend fun recvPeerPubkey(): ByteArray =
        recvPayload(0x03).also { if (it.size != 64) throw BindException("device pubkey must be 64 bytes") }

    /**
     * Writes the bind result on UPNP: 0x13 = bind ok, 0x14 = bind failed.
     * After 0x14 the charger leaves the pending-bind state.
     *
     * @param ok True to send 0x13, false to send 0x14.
     * @throws BindException If the write is not accepted.
     */
    fun writeBindResult(ok: Boolean) = write(MiProto.UPNP_UUID, byteArrayOf(if (ok) 0x13 else 0x14, 0, 0, 0))

    /**
     * Sends the bind blob as parcel 0x00.
     *
     * @param blob Blob from [BindCrypto.buildBindBlob], 92 bytes.
     * @throws BindException If the blob is not 92 bytes or the transfer fails.
     */
    suspend fun sendBindBlob(blob: ByteArray) {
        if (blob.size != 92) throw BindException("bind blob must be 92 bytes")
        sendParcel(0x00, blob)
    }

    /**
     * Sends the cloud certificate as parcel 0x07.
     *
     * @param cert Certificate bytes from the Xiaomi cloud.
     * @throws BindException If the certificate is empty or the transfer fails.
     */
    suspend fun sendCloudCert(cert: ByteArray) {
        if (cert.isEmpty()) throw BindException("cloud cert is empty")
        sendParcel(0x07, cert)
    }

    /**
     * Waits up to 15 s (the same as the vendor app) for the first UPNP frame after the
     * certificate: 0x11 = ok, 0x12 = rejected.
     *
     * @throws BindException If the charger rejects the bind, sends a different frame, or
     *   does not reply.
     */
    suspend fun awaitFinal() {
        val f = withTimeoutOrNull(15_000) { upnp.receive() }
            ?: throw BindException("charger stopped replying after the certificate upload. Bind result unknown.")
        when {
            f.contentEquals(byteArrayOf(0x11, 0, 0, 0)) -> return
            f.contentEquals(byteArrayOf(0x12, 0, 0, 0)) -> throw BindException("charger rejected the bind (0x12)")
            else -> throw BindException("unexpected final response from the charger")
        }
    }

    private companion object {
        const val TIMEOUT = 10_000L
        const val MAX_PARCELS = 64
    }
}
