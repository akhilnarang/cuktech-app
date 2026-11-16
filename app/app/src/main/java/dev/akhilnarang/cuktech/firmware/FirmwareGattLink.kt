package dev.akhilnarang.cuktech.firmware

import dev.akhilnarang.cuktech.proto.GattPort
import dev.akhilnarang.cuktech.proto.MiCrypto
import dev.akhilnarang.cuktech.proto.MiProto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.security.SecureRandom

/**
 * Coroutine adapter for one firmware GATT connection. Use it on the main thread only.
 *
 * Each write waits for the Android GATT completion. Only one write can be in progress.
 * After a disconnect or a failure, all waits and later calls throw the same [IllegalStateException].
 * Use a new instance for each connection.
 */
internal class FirmwareGattLink(private val port: GattPort) : GattPort.Callbacks, FirmwareWire {
    private val connected = CompletableDeferred<Unit>()
    private val discovered = CompletableDeferred<Unit>()
    private val disconnected = CompletableDeferred<Unit>()
    private val subscriptions = mutableMapOf<String, CompletableDeferred<Unit>>()
    private val channels = listOf(MiProto.UPNP_UUID, MiProto.AVDTP_UUID, FirmwareTransfer.CONTROL, FirmwareTransfer.DATA)
        .associateWith { Channel<ByteArray>(64) }
    private var written: CompletableDeferred<Unit>? = null
    private var reading: CompletableDeferred<String>? = null
    private var failure: Throwable? = null
    init { port.setCallbacks(this) }

/**
 * Connects, negotiates the 18-byte payload with A4, and does the Mi token login.
 *
 * Timeouts: 15 s to connect and 10 s for service discovery.
 * @param address Charger BLE MAC address.
 * @param token 12-byte BLE login token. This function does not change or keep it.
 * @throws IllegalStateException If a step times out, the charger rejects the token, or a reply is not valid.
 */
    suspend fun open(address: String, token: ByteArray) {
        port.connect(address)
        step(15_000, "connection") { connected.await() }
        port.discoverServices()
        step(10_000, "service discovery") { discovered.await() }
        // The ATT default MTU is sufficient. Negotiate 18 payload bytes through A4.
        subscribe(MiProto.AVDTP_UUID)
        write(MiProto.UPNP_UUID, byteArrayOf(0xa4.toByte()))
        val offer = receive(MiProto.AVDTP_UUID)
        check(offer.size == 6 && offer.copyOfRange(0, 4).contentEquals(byteArrayOf(0, 0, 4, 0)) &&
            (offer[5].toInt() and 255) >= 18) { "Unsupported firmware link negotiation" }
        val answer = offer.clone().also { it[2] = 5; it[5] = 18 }
        write(MiProto.AVDTP_UUID, answer)
        val probe = receive(MiProto.AVDTP_UUID)
        check(probe.size == 20 && probe.copyOfRange(0, 4).contentEquals(byteArrayOf(0, 0, 4, 1))) {
            "Charger did not confirm the 18-byte transport"
        }
        write(MiProto.AVDTP_UUID, probe.clone().also { it[2] = 5 })
        subscribe(MiProto.UPNP_UUID)
        val appRandom = ByteArray(16).also { SecureRandom().nextBytes(it) }
        write(MiProto.UPNP_UUID, MiProto.CMD_LOGIN)
        sendAuth(0x0b, appRandom)
        val devRandom = receiveAuth(0x0d)
        check(devRandom.size == 16) { "Malformed charger login random" }
        val deviceProof = receiveAuth(0x0c)
        val keys = MiCrypto.deriveLogin(token, appRandom, devRandom)
        try {
            check(deviceProof.size == 32 && MiCrypto.constantTimeEquals(deviceProof,
                MiCrypto.hmacSha256(keys.devKey, devRandom + appRandom))) { "Charger token authentication failed" }
            sendAuth(0x0a, MiCrypto.hmacSha256(keys.appKey, appRandom + devRandom))
            check(receive(MiProto.UPNP_UUID).contentEquals(MiProto.CFM_LOGIN_OK)) { "Charger did not confirm login" }
        } finally {
            keys.devKey.fill(0); keys.appKey.fill(0); keys.devIv.fill(0); keys.appIv.fill(0)
        }
    }

    private suspend fun sendAuth(code: Int, data: ByteArray) {
        val pieces = data.toList().chunked(18)
        write(MiProto.AVDTP_UUID, byteArrayOf(0, 0, 0, code.toByte()) + FirmwareTransfer.le16(pieces.size))
        check(receive(MiProto.AVDTP_UUID).contentEquals(MiProto.RCV_RDY)) { "Unexpected login ready response" }
        pieces.forEachIndexed { i, p -> write(MiProto.AVDTP_UUID, FirmwareTransfer.le16(i + 1) + p.toByteArray()) }
        check(receive(MiProto.AVDTP_UUID).contentEquals(MiProto.RCV_OK)) { "Unexpected login completion response" }
    }

    private suspend fun receiveAuth(code: Int): ByteArray {
        val header = receive(MiProto.AVDTP_UUID)
        check(header.size >= 4 && header[0] == 0.toByte() && header[1] == 0.toByte() &&
            (header[3].toInt() and 255) == code) { "Unexpected login payload" }
        if (header[2] == 2.toByte()) {
            write(MiProto.AVDTP_UUID, MiProto.OFFICIAL_ACK)
            return header.copyOfRange(4, header.size)
        }
        check(header.size == 6 && header[2] == 0.toByte()) { "Malformed login parcel announcement" }
        val count = FirmwareTransfer.u16(header, 4)
        check(count in 1..4) { "Invalid login parcel count" }
        write(MiProto.AVDTP_UUID, MiProto.RCV_RDY)
        val parts = sortedMapOf<Int, ByteArray>()
        repeat(count) {
            val p = receive(MiProto.AVDTP_UUID)
            check(p.size in 3..20) { "Invalid login parcel length" }
            val i = FirmwareTransfer.u16(p)
            check(i in 1..count && i !in parts) { "Invalid login parcel index" }
            parts[i] = p.copyOfRange(2, p.size)
        }
        write(MiProto.AVDTP_UUID, MiProto.RCV_OK)
        return parts.values.fold(byteArrayOf()) { a, b -> a + b }
    }

/**
 * Reads the running firmware version from the version characteristic. Timeout 5 s.
 * @return The version in the form `X.Y.Z_NNNN`.
 * @throws IllegalStateException If the read fails, times out or gives a value that is not valid.
 */
    suspend fun version(): String {
        val result = CompletableDeferred<String>()
        reading = result
        try {
            check(port.read(MiProto.FIRMWARE_VERSION_UUID)) { "Firmware version is unavailable" }
            return step(5_000, "running firmware version") { result.await() }
        } finally { reading = null }
    }

/** Enables notifications on [uuid]. Timeout 5 s. */
    override suspend fun subscribe(uuid: String) {
        failure?.let { throw it }
        val result = CompletableDeferred<Unit>().also { subscriptions[uuid] = it }
        port.subscribe(uuid)
        step(5_000, "notification subscription") { result.await() }
    }
/** Writes [bytes] and waits for the GATT completion. Timeout 10 s. */
    override suspend fun write(uuid: String, bytes: ByteArray) {
        failure?.let { throw it }
        check(written == null) { "Overlapping GATT operations" }
        val result = CompletableDeferred<Unit>()
        written = result
        try {
            check(port.write(uuid, bytes)) { "Firmware GATT write was rejected" }
            step(10_000, "GATT write") { result.await() }
        } finally { written = null }
    }
/** Returns the next queued notification from [uuid]. The queue holds 64 notifications. */
    override suspend fun receive(uuid: String, timeoutMs: Long): ByteArray = step(timeoutMs, "charger response") {
        failure?.let { throw it }
        channels.getValue(uuid).receive()
    }
// Converts a timeout into an IllegalStateException so that callers see a normal failure.
    private suspend fun <T> step(ms: Long, what: String, block: suspend () -> T): T = try {
        withTimeout(ms) { block() }
    } catch (e: TimeoutCancellationException) {
        throw IllegalStateException("Timed out waiting for $what", e)
    }
/** Disconnects, waits a maximum of 2 s, then closes the port. It runs also if the caller is cancelled. */
    suspend fun close() = withContext(NonCancellable) {
        try { port.disconnect(); withTimeoutOrNull(2_000) { disconnected.await() } }
        finally { port.close() }
    }
// Only the first failure counts. It completes all pending waits with the same error.
    private fun fail(message: String) {
        if (failure != null) return
        val error = IllegalStateException(message).also { failure = it }
        connected.completeExceptionally(error); discovered.completeExceptionally(error)
        subscriptions.values.forEach { it.completeExceptionally(error) }
        written?.completeExceptionally(error); reading?.completeExceptionally(error)
        channels.values.forEach { it.close(error) }
    }
    override fun onConnected() { connected.complete(Unit) }
    override fun onDisconnected(status: Int) { disconnected.complete(Unit); fail("Firmware connection ended (status $status)") }
    override fun onServicesDiscovered(ok: Boolean) { if (ok) discovered.complete(Unit) else fail("Firmware services are unavailable") }
    override fun onMtu(mtu: Int) = Unit
    override fun onSubscribed(uuid: String, ok: Boolean) {
        if (ok) subscriptions[uuid]?.complete(Unit) else fail("Firmware notification subscription failed")
    }
    override fun onWritten(uuid: String) { written?.complete(Unit) }
    override fun onWriteFailed(uuid: String, reason: String) { fail("Firmware GATT write failed") }
    override fun onNotify(uuid: String, data: ByteArray) {
        if (uuid == MiProto.UPNP_UUID && data.size == 4 && data[1] == 0.toByte() &&
            data[2] == 0.toByte() && data[3] == 0.toByte() && (data[0].toInt() and 255) in setOf(0x23, 0xe0, 0xe1, 0xe2, 0xe3)) {
            fail("Charger rejected token login"); return
        }
        if (channels[uuid]?.trySend(data.clone())?.isFailure == true) fail("Firmware notification queue overflow")
    }
    override fun onRead(uuid: String, data: ByteArray, ok: Boolean) {
        if (uuid != MiProto.FIRMWARE_VERSION_UUID) return
        val value = data.takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.US_ASCII).trim()
        if (ok && value.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+_[0-9]+"))) reading?.complete(value)
        else reading?.completeExceptionally(IllegalStateException("Invalid running firmware version"))
    }
}
