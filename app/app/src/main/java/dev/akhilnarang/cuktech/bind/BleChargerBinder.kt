package dev.akhilnarang.cuktech.bind

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import dev.akhilnarang.cuktech.BindProgress
import dev.akhilnarang.cuktech.BindResult
import dev.akhilnarang.cuktech.ChargerBinder
import dev.akhilnarang.cuktech.CloudSession
import dev.akhilnarang.cuktech.XiaomiCloud
import dev.akhilnarang.cuktech.proto.AndroidGattPort
import dev.akhilnarang.cuktech.proto.MiController
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The charger can hold this binding, but the app cannot confirm it. This occurs if a
 * step fails after 0x13, or if the offline login check fails. The exception carries the
 * token so that the app does not lose it.
 *
 * @param message Reason for the failure.
 * @property tokenHex Login token as lowercase hex.
 * @property did DID that the Xiaomi cloud gave to the charger.
 */
class BindIncompleteException(message: String, val tokenHex: String, val did: String) : Exception(message)

/**
 * Charger setup: BLE register and Xiaomi cloud bind. The UI gets the user consent and
 * does the sign-in before it calls [bind].
 *
 * @param context Any context. The binder keeps only the application context.
 */
class BleChargerBinder(context: Context) : ChargerBinder {
    private val context = context.applicationContext

    /**
     * Binds a charger to the Xiaomi account and checks the offline login.
     * Runs on the main thread. The steps are:
     * 1. Scan for the advert (20 s) and check that the charger is not bound.
     * 2. Check that the charger is not already on the account.
     * 3. Do the BLE register (ECDH) and get the DID and bind signature from the cloud.
     * 4. Send 0x13, the bind blob and the cloud certificate, then wait for 0x11.
     * 5. Connect again and do an offline login with the new token (60 s).
     *
     * If a step fails after the public key upload and before 0x13, the binder sends 0x14
     * so that the charger leaves the pending-bind state.
     *
     * @param address BLE address of the charger.
     * @param session Signed-in Xiaomi cloud session.
     * @param cloud Xiaomi cloud client.
     * @param progress Gets a text step for each stage, on the main thread.
     * @return The token (hex) and the DID.
     * @throws SecurityException If the Bluetooth connect permission is missing.
     * @throws BindException If a check or a register step fails. The charger is not bound.
     * @throws BindIncompleteException If the result is unknown after 0x13, or if the login
     *   check fails. The charger can be bound.
     */
    override suspend fun bind(
        address: String,
        session: CloudSession,
        cloud: XiaomiCloud,
        progress: (BindProgress) -> Unit,
    ): BindResult = withContext(Dispatchers.Main) { // GATT port + write queue are main-thread only
        val say = { s: String -> progress(BindProgress.Step(s)) }
        if (Build.VERSION.SDK_INT >= 31 &&
            context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED
        ) throw SecurityException("Bluetooth connect permission not granted")

        // ---- identity guards from the live advert (smac + model are never typed in)
        say("Looking for the charger")
        val (scan, frame) = withTimeoutOrNull(20_000) {
            BleChargerScanner(context).frames().first { it.first.device.address.equals(address, ignoreCase = true) }
        } ?: throw BindException("The charger is not advertising. Make sure that it is on power and near this phone.")
        if (frame.registered) throw BindException("The charger is already bound. Do a factory reset first.")
        val smac = frame.smac?.takeIf { frame.smacMatches(address) }
            ?: throw BindException("The charger's advertised MAC is missing or does not match. Move closer and try again.")
        val model = Fe95.MODELS[frame.productId] ?: throw BindException("Unknown product id")
        val name = scan.scanRecord?.deviceName
        if (name != null && !name.startsWith(Fe95.MODEL_NAME_PREFIX)) throw BindException("Unexpected device name. The app does not bind it.")

        say("Checking your Xiaomi account")
        val ids = setOf(hex(address), hex(smac), hex(smac).chunked(2).reversed().joinToString(""))
        if (cloud.listDevices(session).any { it.mac != null && hex(it.mac) in ids }) {
            throw BindException("This charger is already on your Xiaomi account.")
        }

        // ---- register on one connection
        say("Connecting to the charger")
        val link = RegisterLink(AndroidGattPort(context))
        var devicePending = false
        var confirmStarted = false
        val token: ByteArray
        val tokenHex: String
        val did: String
        try {
            link.open(address)
            say("Reading charger info")
            val info = link.getDevInfo()
            link.sendCapsEcho(info)
            say("Exchanging keys with the charger")
            val kp = BindCrypto.generateKeyPair()
            devicePending = true // pubkey upload is next: from here a failure must send 0x14
            link.sendPubkey(BindCrypto.publicKeyBytes(kp))
            val shared = BindCrypto.ecdh(kp, link.recvPeerPubkey())
            val secrets = BindCrypto.deriveRegister(shared)
            shared.fill(0)
            token = secrets.token
            tokenHex = hex(token)

            say("Registering the charger with Xiaomi")
            did = cloud.applyDid(session, address, model, tokenHex, info.factoryDid)
            say("Getting the bind signature from Xiaomi")
            val material = cloud.standardBind(session, did, tokenHex, hex(secrets.bindKey), smac)
            val blob = BindCrypto.buildBindBlob(BindCrypto.normalizeDid(did), material.cloudSign, material.utc, secrets.aKey)

            say("Sending the bind to the charger")
            confirmStarted = true // BEFORE 0x13: never send 0x14 after this point
            try {
                link.writeBindResult(true)
                link.sendBindBlob(blob)
                link.sendCloudCert(material.cloudCert)
                link.awaitFinal()
            } catch (e: Exception) {
                throw BindIncompleteException("Bind outcome unknown: ${e.message}", tokenHex, did)
            }
        } catch (e: Throwable) {
            if (devicePending && !confirmStarted) withContext(NonCancellable) {
                say("Telling the charger to cancel the bind")
                runCatching { link.writeBindResult(false) }
                delay(500) // let the queued 0x14 go out before the link closes
            }
            throw e
        } finally {
            withContext(NonCancellable) { link.close() }
        }

        // ---- verify on a fresh connection with the existing (hardware-proven) login
        say("Charger accepted the bind. Checking offline login")
        delay(1_000)
        try {
            verifyLogin(address, token)
        } catch (e: Exception) {
            throw BindIncompleteException("Bound (0x11), but offline login check failed: ${e.message}", tokenHex, did)
        }
        say("Done: charger bound and offline login works")
        BindResult(tokenHex, did)
    }

    /**
     * Opens a new connection with [MiController] and waits until it is ready, or 60 s.
     * The controller does MTU 247, subscribe AVDTP, a4 greet, subscribe UPNP, login, MIOT init.
     *
     * @throws BindException If the controller reports a fatal error.
     * @throws kotlinx.coroutines.TimeoutCancellationException If the login takes more than 60 s.
     */
    private suspend fun verifyLogin(address: String, token: ByteArray) {
        val done = CompletableDeferred<Unit>()
        val main = Handler(Looper.getMainLooper())
        lateinit var c: MiController
        c = MiController(
            AndroidGattPort(context),
            object : MiController.Scheduler {
                override fun postDelayed(r: Runnable, ms: Long) { main.postDelayed(r, ms) }
                override fun cancel(r: Runnable) { main.removeCallbacks(r) }
            },
            object : MiController.Listener {
                override fun onStatus(text: String) { if (c.isReady) done.complete(Unit) }
                override fun onPortsChanged() {}
                override fun onPropsChanged() {}
                override fun onResult(what: String, ok: Boolean, error: String?) {}
                override fun onFatal(stage: String, message: String) {
                    done.completeExceptionally(BindException("$stage: $message"))
                }
            },
        )
        try {
            c.connect(token, address)
            withTimeout(60_000) { done.await() }
        } finally {
            c.close()
        }
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun hex(mac: String) = mac.replace(":", "").replace("-", "").lowercase()
}
