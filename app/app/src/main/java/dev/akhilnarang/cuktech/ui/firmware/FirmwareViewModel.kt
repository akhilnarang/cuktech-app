package dev.akhilnarang.cuktech.ui.firmware

import android.app.Application
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.PowerManager
import android.util.AtomicFile
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.akhilnarang.cuktech.CloudException
import dev.akhilnarang.cuktech.CloudSession
import dev.akhilnarang.cuktech.LoginPrompts
import dev.akhilnarang.cuktech.cloud.CloudSessionStore
import dev.akhilnarang.cuktech.cloud.XiaomiCloudClient
import dev.akhilnarang.cuktech.firmware.FirmwareDownloader
import dev.akhilnarang.cuktech.firmware.FirmwareInfo
import dev.akhilnarang.cuktech.firmware.FirmwarePackage
import dev.akhilnarang.cuktech.firmware.FirmwareInstaller
import dev.akhilnarang.cuktech.ConnectionService
import dev.akhilnarang.cuktech.proto.SecureStore
import dev.akhilnarang.cuktech.ui.setup.Prompt
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import org.json.JSONObject

/**
 * State and actions of the firmware screen: cloud check, download, import, export and install.
 * A saved package and its metadata are kept in `filesDir/firmware` and checked again at start.
 * Actions run one at a time. A call while [busy] does nothing. Call all functions on the main thread.
 */
class FirmwareViewModel(app: Application) : AndroidViewModel(app) {
    private val store = SecureStore(app)
    private val sessions = CloudSessionStore(store)
    private val cloud = XiaomiCloudClient()
    private var session: CloudSession? = null
    private var packageFile: File? = null
/** Last running version read from the charger, or null. */
    var installedVersion by mutableStateOf<String?>(store.firmwareVersion); private set
/** True while an install runs. */
    var installing by mutableStateOf(false); private set
/** Install progress 0..1, or null. */
    var installProgress by mutableStateOf<Float?>(null); private set
/** Text of the current install step, or null. */
    var installPhase by mutableStateOf<String?>(null); private set
/** True if a package is ready and its model supports direct installation. */
    val directInstallAvailable: Boolean get() = downloaded && latest?.model == FirmwarePackage.MODEL
    private val firmwareDir = File(app.filesDir, "firmware").apply { mkdirs() }
    private val cachedMetadata = AtomicFile(File(firmwareDir, "download.json"))
/** True if a cloud login is saved. */
    var hasSavedLogin by mutableStateOf(false); private set
/** True if the screen must show the sign-in form. */
    var needsSignIn by mutableStateOf(false); private set
/** True while an action runs. */
    var busy by mutableStateOf(false); private set
/** Last failure message, or null. */
    var error by mutableStateOf<String?>(null); private set
/** Result message of the last action, or null. */
    var note by mutableStateOf<String?>(null); private set
/** Metadata of the offered or loaded package, or null. */
    var latest by mutableStateOf<FirmwareInfo?>(null); private set
/** Download progress 0..1, or null if the total size is not known. */
    var downloadProgress by mutableStateOf<Float?>(null); private set
/** True if a checked package file is saved. */
    var downloaded by mutableStateOf(false); private set
/** Sign-in dialog that the flow waits on, or null. */
    var prompt by mutableStateOf<Prompt?>(null); private set

    init {
        try {
            session = sessions.load()
            hasSavedLogin = session != null
        } catch (e: IllegalStateException) { error = e.message }
        needsSignIn = session == null
        try {
            if (cachedMetadata.baseFile.exists()) {
                val json = JSONObject(cachedMetadata.openRead().use { it.readBytes().toString(Charsets.UTF_8) })
                val info = FirmwareInfo(json.getString("model"), json.getString("version"), json.getString("url"),
                    json.getString("md5"), json.optString("changelog"))
                val name = json.getString("file")
                check(name.matches(Regex("[0-9a-f]{64}\\.bin")))
                val file = File(firmwareDir, name)
                if (file.length() in 1024..(8 * 1024 * 1024)) {
                    if (info.model == FirmwarePackage.MODEL) FirmwarePackage.validate(file.readBytes(), info)
                    latest = info; packageFile = file; downloaded = true
                    note = "Saved firmware package is available offline."
                }
            }
        } catch (_: Exception) { cachedMetadata.delete() }
    }

    private suspend fun <T> ask(make: (CompletableDeferred<T>) -> Prompt): T {
        val reply = CompletableDeferred<T>()
        prompt = make(reply)
        try { return reply.await() } finally { prompt = null }
    }

    private val prompts = object : LoginPrompts {
        override suspend fun captcha(image: ByteArray): String? = ask {
            Prompt.Captcha(BitmapFactory.decodeByteArray(image, 0, image.size)?.asImageBitmap(), it)
        }
        override suspend fun verificationCode(sms: Boolean): String? = ask { Prompt.EmailCode(sms, it) }
        override suspend fun browserConfirmation(url: String): Boolean = ask { Prompt.Browser(url, it) }
    }

/** Completes a sign-in dialog. See [dev.akhilnarang.cuktech.ui.setup.SetupViewModel.answer]. Consent is always refused here. */
    fun answer(p: Prompt, value: Any?) {
        when (p) {
            is Prompt.Captcha -> p.reply.complete(value as String?)
            is Prompt.EmailCode -> p.reply.complete(value as String?)
            is Prompt.Browser -> p.reply.complete(value == true)
            is Prompt.Consent -> p.reply.complete(false)
        }
    }

// Runs one action. An auth rejection deletes the saved login. Errors go in [error].
    private fun run(block: suspend () -> Unit) {
        if (busy) return
        busy = true
        error = null
        note = null
        viewModelScope.launch {
            try { block() }
            catch (e: TimeoutCancellationException) { error = "The operation timed out. Reconnect and check the charger before you try the installation again." }
            catch (e: CancellationException) { throw e }
            catch (e: CloudException) {
                if (e.authRejected) {
                    sessions.clear()
                    session = null
                    hasSavedLogin = false
                    needsSignIn = true
                    error = "Your cloud login expired. Sign in again. The Bluetooth token is still saved."
                } else error = e.message
            }
            catch (e: Exception) { error = e.message ?: "The request failed" }
            finally { busy = false }
        }
    }

// Finds the saved charger in the account and gets its latest firmware metadata.
    private suspend fun check(auth: CloudSession, username: String? = null) {
        val mac = store.mac ?: throw IllegalStateException("No charger is saved")
        val target = mac.filter { it.isLetterOrDigit() }.lowercase()
        val reversed = target.chunked(2).reversed().joinToString("")
        val device = cloud.listDevices(auth).firstOrNull {
            it.mac?.filter { c -> c.isLetterOrDigit() }?.lowercase() in setOf(target, reversed)
        } ?: throw CloudException("This charger is not listed in this account on ${auth.region}. Check the account and region.")
        val info = cloud.latestFirmware(auth, device.did, device.model ?: "")
        // Retain a valid login only after its device-list request succeeds.
        var cached = true
        try { sessions.save(auth, username) }
        catch (e: IllegalStateException) { cached = false }
        session = auth
        hasSavedLogin = cached
        needsSignIn = false
        if (latest != info) {
            cachedMetadata.delete()
            packageFile?.delete()
            packageFile = null
            downloaded = false
        }
        latest = info
        note = if (info.version == installedVersion) "This matches the last version read from your charger."
               else "Xiaomi offers this version for your charger."
        if (!cached) note += " Cannot save the cloud login. It works until you close this screen."
    }

/** Asks Xiaomi for the latest firmware with the saved login. Shows the sign-in if there is no login. */
    fun checkLatest() = run {
        val auth = session
        if (auth == null) needsSignIn = true else check(auth)
    }

/**
 * Signs in, saves the login, and checks for the latest firmware.
 * @param region Xiaomi cloud region code, for example `cn`.
 */
    fun signIn(username: String, password: String, region: String) = run {
        val auth = cloud.login(username, password, region, prompts)
        check(auth, username)
    }

/** Downloads and checks [latest], then saves it. For [FirmwarePackage.MODEL], the signature is also checked. */
    fun download() = run {
        val info = latest ?: return@run
        downloaded = false
        downloadProgress = 0f
        try {
            val file = FirmwareDownloader.download(info, getApplication<Application>().cacheDir) { received, length ->
                downloadProgress = if (length > 0) received.toFloat() / length else null
            }
            val saved = try { savePackage(file.readBytes(), info) } finally { file.delete() }
            if (packageFile != saved) packageFile?.delete()
            packageFile = saved
            downloaded = true
            note = if (info.model == FirmwarePackage.MODEL) "Downloaded. Checksum, signing chain and image signature are correct."
                else "Downloaded. The Xiaomi checksum is correct."
        } finally { downloadProgress = null }
    }

// Saves the package as {sha256}.bin and writes download.json. Both writes are atomic.
    private suspend fun savePackage(bytes: ByteArray, info: FirmwareInfo): File = withContext(Dispatchers.IO) {
        if (info.model == FirmwarePackage.MODEL) FirmwarePackage.validate(bytes, info)
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val target = File(firmwareDir, "$sha.bin")
        val atomic = AtomicFile(target)
        val output = atomic.startWrite()
        try { output.write(bytes); atomic.finishWrite(output) }
        catch (e: Exception) { atomic.failWrite(output); throw e }
        val metadata = JSONObject().put("model", info.model).put("version", info.version)
            .put("url", info.url).put("md5", info.md5).put("changelog", info.changelog).put("file", target.name)
        val meta = cachedMetadata.startWrite()
        try { meta.write(metadata.toString().toByteArray()); cachedMetadata.finishWrite(meta) }
        catch (e: Exception) { cachedMetadata.failWrite(meta); throw e }
        target
    }

/** Imports a local signed package. It must pass [FirmwarePackage.importSigned]. */
    fun importFirmware(uri: Uri) = run {
        val image = withContext(Dispatchers.IO) {
            val source = getApplication<Application>().contentResolver.openInputStream(uri)
                ?: throw IllegalStateException("Cannot open the selected firmware file")
            val bytes = source.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    check(output.size() + n <= FirmwarePackage.MAX_SIZE) { "The firmware is larger than the known staging limit" }
                    output.write(buffer, 0, n)
                }
                output.toByteArray()
            }
            FirmwarePackage.importSigned(bytes)
        }
        val saved = savePackage(image.bytes, image.info)
        if (packageFile != saved) packageFile?.delete()
        packageFile = saved
        latest = image.info
        downloaded = true
        note = "Imported. Pinned signing chain, signed model/version and image signature are correct."
    }

/** Copies the saved package to [uri]. */
    fun export(uri: Uri) = run {
        val file = packageFile ?: throw IllegalStateException("Download the package first")
        withContext(Dispatchers.IO) {
            val output = getApplication<Application>().contentResolver.openOutputStream(uri, "w")
                ?: throw IllegalStateException("The selected file could not be opened")
            output.use { target -> file.inputStream().use { it.copyTo(target) } }
        }
        note = "Firmware file exported."
    }

/** Deletes the saved cloud login. The Bluetooth token stays. */
    fun forgetLogin() {
        if (busy) return
        sessions.clear()
        session = null
        hasSavedLogin = false
        needsSignIn = true
        error = null
        note = "Cloud login forgotten. Your Bluetooth token is still saved."
    }

/**
 * Installs the saved package with [FirmwareInstaller]. It checks the package again first.
 * It holds a partial wake lock (max. 21 minutes) and runs [ConnectionService] while it works.
 */
    fun install() = run {
        val info = latest ?: throw IllegalStateException("Download firmware first")
        val file = packageFile ?: throw IllegalStateException("Download firmware first")
        val image = withContext(Dispatchers.IO) { FirmwarePackage.validate(file.readBytes(), info) }
        val address = store.mac ?: throw IllegalStateException("No charger is saved")
        val token = store.loadToken() ?: throw IllegalStateException("The saved Bluetooth token is unavailable")
        val app = getApplication<Application>()
        val power = app.getSystemService(PowerManager::class.java)
        val wake = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "cuktech:firmware")
        installing = true
        installProgress = 0f
        try {
            ConnectionService.start(app, firmware = true)
            wake.acquire(21 * 60_000L)
            val reinstall = FirmwareInstaller(app).install(address, token, image,
                progress = { written, total -> installProgress = written.toFloat() / total },
                phase = { installPhase = it },
                observedVersion = { installedVersion = it; store.saveFirmwareVersion(it) })
            installPhase = "Running firmware ${info.version} confirmed"
            note = if (reinstall) "Charger reports ${info.version} after reinstallation. A version read cannot tell the difference between two images with the same version."
                else "Installed ${info.version}. A new authenticated version read confirms it."
        } catch (e: Exception) {
            installPhase = "Installation not confirmed"
            throw e
        } finally {
            token.fill(0)
            if (wake.isHeld) wake.release()
            ConnectionService.stop(app)
            installing = false
            installProgress = null
        }
    }
}
