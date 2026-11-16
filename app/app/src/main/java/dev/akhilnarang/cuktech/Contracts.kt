package dev.akhilnarang.cuktech

// Shared contracts between cloud/, bind/ and ui/. The implementations are in
// those packages.

/**
 * Interactive steps that the Xiaomi sign-in can need. The UI implements them.
 * Each function suspends until the user answers. A null or false result means that the user cancelled.
 */
interface LoginPrompts {
    /**
     * Asks the user to read a captcha.
     * @param image The captcha image bytes as the server sends them. Max. 512 KiB.
     * @return The text that the user typed, or null if the user cancelled.
     */
    suspend fun captcha(image: ByteArray): String?
    /**
     * Asks for the 2FA code.
     * @param sms True if the code was sent by SMS. False if it was sent by email.
     * @return The code, or null if the user cancelled.
     */
    suspend fun verificationCode(sms: Boolean): String?
    /**
     * Asks the user to confirm the sign-in in a browser (notification URL).
     * @param url The Xiaomi confirmation page to open.
     * @return True after the user says that the confirmation is done. False if the user cancelled.
     */
    suspend fun browserConfirmation(url: String): Boolean
}

/**
 * Authenticated Xiaomi session. Never logged.
 * [CloudSessionStore][dev.akhilnarang.cuktech.cloud.CloudSessionStore] can save it, encrypted with the Android Keystore.
 *
 * @property userId Xiaomi account user ID.
 * @property ssecurity Base64 session secret. The client uses it to sign and encrypt /app requests.
 * @property serviceToken `serviceToken` cookie from the STS step of the sign-in.
 * @property deviceId Random 16-letter client device ID sent at sign-in.
 * @property skewSeconds Server time minus local time, in seconds (from the HTTP `Date` header). The client adds it to the nonce time.
 * @property region Cloud region code, for example `cn`, `de` or `sg`.
 */
class CloudSession(
    val userId: String,
    val ssecurity: String,
    val serviceToken: String,
    val deviceId: String,
    val skewSeconds: Double,
    val region: String,
)

/**
 * A device from the Xiaomi account device list.
 *
 * @property did Cloud device ID.
 * @property pid Product ID, or null if the server does not send it.
 * @property mac BLE MAC address, or null.
 */
data class CloudDevice(
    val did: String, val pid: Int?, val model: String?, val name: String?, val mac: String?,
    /** BLE token uploaded at bind (hex; first 24 chars = 12-byte login token). Never logged. */
    val token: String? = null,
) {
    override fun toString() = "CloudDevice(did=$did, pid=$pid, model=$model, name=$name, mac=$mac, token=${if (token == null) "null" else "<redacted>"})"
}

/**
 * Cloud reply to a standard bind.
 *
 * @property cloudSign Server signature for the charger. Always 64 bytes.
 * @property cloudCert Server certificate that goes with [cloudSign].
 * @property utc Server `utc` value, in the range 1..0xFFFFFFFF (u32).
 */
class BindMaterial(val cloudSign: ByteArray, val cloudCert: ByteArray, val utc: Long)

/**
 * Failure of a Xiaomi cloud call or a firmware download. The message is safe to show to the user.
 *
 * @property authRejected True if the server rejected the session or the credentials. Sign in again.
 */
class CloudException(message: String, val authRejected: Boolean = false) : Exception(message)

/**
 * Xiaomi cloud account API. All calls suspend and do the network work on the IO dispatcher.
 * All calls throw [CloudException] on a network, server or protocol failure.
 */
interface XiaomiCloud {
    /**
     * Signs in to the Xiaomi account.
     * @param region Cloud region code: `cn`, `de`, `us`, `ru`, `tw`, `sg`, `in` or `i2`.
     * @param prompts Callbacks for captcha, 2FA and browser confirmation.
     * @return A new session.
     * @throws CloudException If the region is unknown, the sign-in fails or the user cancels a prompt.
     */
    suspend fun login(username: String, password: String, region: String, prompts: LoginPrompts): CloudSession
    /**
     * Lists the devices of the account in the session region.
     * @throws CloudException If the request fails. [CloudException.authRejected] is true for an expired session.
     */
    suspend fun listDevices(session: CloudSession): List<CloudDevice>
    /**
     * Calls `/device/bltapplydid` to get the server device ID for a new BLE bind.
     * @param mac Charger BLE MAC address.
     * @param model Xiaomi model name, for example `njcuk.fitting.ad1204`.
     * @param tokenHex New 12-byte BLE token, as hex.
     * @param factoryDid Device ID that the charger reports before the bind. If empty, the request does not send it.
     * @return The server did.
     * @throws CloudException If the server rejects the request.
     */
    suspend fun applyDid(session: CloudSession, mac: String, model: String, tokenHex: String, factoryDid: String): String
    /**
     * Calls `/v2/device/ble_standard_bind`. The response fields are URL-safe base64.
     * @param did Server did from [applyDid].
     * @param tokenHex New 12-byte BLE token, as hex.
     * @param bindKeyHex Bind key from the ECDH exchange, as hex. It is also sent as `beacon_key`.
     * @param smac Charger MAC address from the FE95 advert, `AA:BB:CC:DD:EE:FF` form.
     * @return The server signature, certificate and time for the charger.
     * @throws CloudException If the server rejects the bind.
     */
    suspend fun standardBind(session: CloudSession, did: String, tokenHex: String, bindKeyHex: String, smac: String): BindMaterial
    /**
     * Calls `/user/del_owner_device_batch` to remove the device from the account.
     * @throws CloudException If the server rejects the request.
     */
    suspend fun removeDevice(session: CloudSession, did: String, pid: Int)
}

/**
 * A charger found by a BLE scan (FE95 service data, pid 0x660E or 0x8AB9).
 *
 * @property address BLE MAC address.
 * @property name Advertised name, or null.
 * @property pid Xiaomi product ID from the FE95 frame.
 * @property registered True if the FE95 frame says that the charger is bound to an account.
 * @property rssi Signal strength of the latest advert, in dBm.
 */
data class ChargerAdvert(val address: String, val name: String?, val pid: Int, val registered: Boolean, val rssi: Int)

/** Progress events of [ChargerBinder.bind]. */
sealed interface BindProgress {
    /** A new bind step started. [text] is a short user-facing description. */
    data class Step(val text: String) : BindProgress
}

/**
 * Result of a completed bind.
 *
 * @property tokenHex New 12-byte BLE login token, as hex. Never logged.
 * @property did Server device ID.
 */
class BindResult(val tokenHex: String, val did: String)

/**
 * Mi BLE register (bind) flow. It does the ECDH exchange with the charger and the cloud half
 * through [XiaomiCloud]. If a step fails after the ECDH exchange and before 0x13, it writes 0x14.
 * The charger then leaves the pending-bind state. It never unbinds the charger.
 */
interface ChargerBinder {
    /**
     * Binds the charger to the account of [session].
     * @param address Charger BLE MAC address.
     * @param progress Called for each step. [BleChargerBinder][dev.akhilnarang.cuktech.bind.BleChargerBinder] calls it on the main thread.
     * @return The new token and server did.
     * @throws CloudException If a cloud step fails.
     * @throws dev.akhilnarang.cuktech.bind.BindException If a BLE step fails, or the charger is already bound.
     * @throws SecurityException If the Bluetooth connect permission is missing.
     */
    suspend fun bind(
        address: String,
        session: CloudSession,
        cloud: XiaomiCloud,
        progress: (BindProgress) -> Unit,
    ): BindResult
}

/** BLE scan for AD1204U-family chargers. Needs the Bluetooth scan permission. */
interface ChargerScanning {
    /** Emits each matching advert until the collector cancels. Adverts are deduplicated by address and carry the latest RSSI. */
    fun scan(): kotlinx.coroutines.flow.Flow<ChargerAdvert>
}

// Implementations:
//   dev.akhilnarang.cuktech.cloud.XiaomiCloudClient()            : XiaomiCloud
//   dev.akhilnarang.cuktech.bind.BleChargerBinder(context)        : ChargerBinder
//   dev.akhilnarang.cuktech.bind.BleChargerScanner(context)       : ChargerScanning
