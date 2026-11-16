package dev.akhilnarang.cuktech.ui.setup

import android.app.Application
import android.graphics.BitmapFactory
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.akhilnarang.cuktech.BindProgress
import dev.akhilnarang.cuktech.ChargerAdvert
import dev.akhilnarang.cuktech.LoginPrompts
import dev.akhilnarang.cuktech.bind.BleChargerBinder
import dev.akhilnarang.cuktech.bind.BleChargerScanner
import dev.akhilnarang.cuktech.cloud.XiaomiCloudClient
import dev.akhilnarang.cuktech.cloud.CloudSessionStore
import dev.akhilnarang.cuktech.CloudException
import dev.akhilnarang.cuktech.CloudSession
import dev.akhilnarang.cuktech.BindResult
import dev.akhilnarang.cuktech.bind.BindIncompleteException
import dev.akhilnarang.cuktech.proto.SecureStore
import dev.akhilnarang.cuktech.ui.hexToBytes
import dev.akhilnarang.cuktech.ui.isToken24
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Step of the setup flow. */
sealed interface Step {
/** Scan for chargers. */
  data object Scan : Step

/** Sign in to Xiaomi for [charger]. */
  data class SignIn(val charger: ChargerAdvert) : Step

/** Type a token for [charger] by hand. */
  data class Import(val charger: ChargerAdvert) : Step

/** Bind or token fetch for [charger] is in progress or complete. */
  data class Binding(val charger: ChargerAdvert) : Step
}

/** A dialog that the sign-in or bind flow waits on. The answer completes `reply`. */
sealed interface Prompt {
/** Captcha to read. [image] is null if Android cannot decode it. */
  data class Captcha(val image: ImageBitmap?, val reply: CompletableDeferred<String?>) : Prompt

/** 2FA code. [sms] is true for SMS, false for email. */
  data class EmailCode(val sms: Boolean, val reply: CompletableDeferred<String?>) : Prompt

/** Confirm the sign-in at [url] in a browser. */
  data class Browser(val url: String, val reply: CompletableDeferred<Boolean>) : Prompt

/** Confirm the bind before the app writes to the charger. [keepInAccount] is the chosen option. */
  data class Consent(val keepInAccount: Boolean, val reply: CompletableDeferred<Boolean>) : Prompt
}

/**
 * State and actions of the setup flow: scan, sign in, bind or fetch the token, and save it.
 * Call all functions on the main thread.
 */
class SetupViewModel(app: Application) : AndroidViewModel(app) {
  private val store = SecureStore(app)
  private val cloud = XiaomiCloudClient()
  private val scanner = BleChargerScanner(app)
  private val binder = BleChargerBinder(app)
  private val sessions = CloudSessionStore(store)

/** Current step. */
  var step by mutableStateOf<Step>(Step.Scan)
    private set
/** Chargers found by the scan, by BLE address. */
  val chargers = mutableStateMapOf<String, ChargerAdvert>()
/** Scan failure message, or null. */
  var scanError by mutableStateOf<String?>(null)
    private set
/** Dialog that the flow waits on, or null. */
  var prompt by mutableStateOf<Prompt?>(null)
    private set
/** True while a sign-in or bind runs. */
  var busy by mutableStateOf(false)
    private set
/** Last failure message, or null. */
  var error by mutableStateOf<String?>(null)
    private set
/** Progress lines of the bind or token fetch. */
  val progress = mutableStateListOf<String>()
/** True after the token is saved. */
  var finished by mutableStateOf(false)
    private set
/** Problem that did not stop the flow, or null. */
  var warning by mutableStateOf<String?>(null)
    private set
/** Sign-in status text while the sign-in runs, or null. */
  var loginStatus by mutableStateOf<String?>(null)
    private set

// Uses the saved session if the server accepts it. A network error keeps the saved session.
  private suspend fun loginOrReuse(username: String, password: String, region: String): CloudSession {
    val cached = try { sessions.load(username, region) } catch (e: IllegalStateException) { null }
    if (cached != null) {
      loginStatus = "Checking saved Xiaomi login…"
      try {
        cloud.listDevices(cached)
        return cached
      } catch (e: CloudException) {
        if (!e.authRejected) throw e // transient error: retain the saved login
        sessions.clear()
      }
    }
    loginStatus = "Signing in to Xiaomi…"
    return cloud.login(username, password, region, prompts)
  }

  private var scanJob: Job? = null

/** Starts the BLE scan if it is not running. Found chargers go in [chargers]. */
  fun startScan() {
    if (scanJob?.isActive == true) return
    scanError = null
    scanJob =
      viewModelScope.launch {
        try {
          scanner.scan().collect { chargers[it.address] = it }
        } catch (e: CancellationException) {
          throw e
        } catch (e: Exception) {
          scanError = e.message ?: "Scan failed"
        }
      }
  }

/** Stops the scan and opens the sign-in for [charger]. */
  fun pick(charger: ChargerAdvert) {
    scanJob?.cancel()
    error = null
    // bound chargers also sign in: the token is read back from the owner's account
    step = Step.SignIn(charger)
  }

/** Opens the manual token import for [charger]. */
  fun showImport(charger: ChargerAdvert) {
    error = null
    step = Step.Import(charger)
  }

  /**
   * For a bound charger: signs in with the account that owns it, reads its token from the device
   * list (same method as ha-cuk-ble) and saves it. It changes nothing on the account or the charger.
   * The result goes in [finished], [error] and [warning]. It does nothing if [busy].
   * @param region Xiaomi cloud region code, for example `cn` or `de`.
   */
  fun signInAndFetch(charger: ChargerAdvert, username: String, password: String, region: String) {
    if (busy) return
    busy = true
    error = null
    viewModelScope.launch {
      try {
        val session = loginOrReuse(username, password, region)
        loginStatus = "Finding the charger in your account…"
        val want = charger.address.filter { it.isLetterOrDigit() }.uppercase(Locale.US)
        val dev = cloud.listDevices(session).firstOrNull {
          it.mac?.filter { c -> c.isLetterOrDigit() }?.uppercase(Locale.US) == want
        } ?: throw IllegalStateException(
          "This charger is not in that account on the $region server. Check the account and region.")
        // Mi Home hex-decodes the whole field (RE: BluetoothCache); never truncate it
        val token = dev.token?.trim()?.lowercase(Locale.US)
        if (token.isNullOrEmpty())
          throw IllegalStateException("The account lists this charger but returned no token")
        if (!isToken24(token))
          throw IllegalStateException("Unexpected token format (${token.length} characters). Please report this.")
        store.save(charger.address.uppercase(Locale.US), hexToBytes(token))
        try { sessions.save(session, username) }
        catch (e: IllegalStateException) { warning = "Token saved. Cannot save the cloud login. Sign in again for firmware checks." }
        step = Step.Binding(charger)
        progress.clear()
        progress += "Signed in and found ${dev.name ?: "the charger"}"
        progress += "Token saved on this phone (the Xiaomi account is unchanged)"
        finished = true
      } catch (e: CancellationException) {
        throw e
      } catch (e: Exception) {
        error = e.message ?: e.javaClass.simpleName
      } finally {
        busy = false
        loginStatus = null
      }
    }
  }

/** Goes back to the scan and starts it again. */
  fun backToScan() {
    error = null
    progress.clear()
    step = Step.Scan
    startScan()
  }

/**
 * Completes a dialog.
 * @param value A `String?` for [Prompt.Captcha] and [Prompt.EmailCode] (null cancels). Else `true` to accept.
 */
  fun answer(p: Prompt, value: Any?) {
    @Suppress("UNCHECKED_CAST")
    when (p) {
      is Prompt.Captcha -> p.reply.complete(value as String?)
      is Prompt.EmailCode -> p.reply.complete(value as String?)
      is Prompt.Browser -> p.reply.complete(value == true)
      is Prompt.Consent -> p.reply.complete(value == true)
    }
  }

  private suspend fun <T> ask(make: (CompletableDeferred<T>) -> Prompt): T {
    val d = CompletableDeferred<T>()
    prompt = make(d)
    try {
      return d.await()
    } finally {
      prompt = null
    }
  }

  private val prompts =
    object : LoginPrompts {
      override suspend fun captcha(image: ByteArray): String? =
        ask { Prompt.Captcha(BitmapFactory.decodeByteArray(image, 0, image.size)?.asImageBitmap(), it) }

      override suspend fun verificationCode(sms: Boolean): String? = ask { Prompt.EmailCode(sms, it) }

      override suspend fun browserConfirmation(url: String): Boolean = ask { Prompt.Browser(url, it) }
    }

  /**
   * Signs in, asks for consent, binds, saves the token, then removes the charger from the account.
   * The session never leaves this coroutine. The result goes in [finished], [error] and [warning].
   * It does nothing if [busy].
   * @param keepInAccount True to keep the charger in the Xiaomi account after the bind.
   */
  fun signInAndBind(charger: ChargerAdvert, username: String, password: String, region: String, keepInAccount: Boolean = false) {
    if (busy) return
    busy = true
    error = null
    viewModelScope.launch {
      try {
        val session = loginOrReuse(username, password, region)
        if (!ask { Prompt.Consent(keepInAccount, it) }) return@launch
        step = Step.Binding(charger)
        progress.clear()
        val result =
          try {
            binder.bind(charger.address, session, cloud) { p ->
              viewModelScope.launch(Dispatchers.Main.immediate) { progress += (p as BindProgress.Step).text }
            }
          } catch (e: BindIncompleteException) {
            // the charger may hold this token (0x13 sent): keep it, never drop it
            warning = "Bind completed with a problem (${e.message}). The token is kept. Try Connect."
            BindResult(e.tokenHex, e.did)
          }
        // Save first: losing the token after a bind is worse than leaving the device in the account.
        store.save(charger.address.uppercase(Locale.US), hexToBytes(result.tokenHex))
        try { sessions.save(session, username) }
        catch (e: IllegalStateException) { warning = "Token saved. Cannot save the cloud login. Sign in again for firmware checks." }
        progress += "Token saved on this phone"
        if (keepInAccount) progress += "Kept in your Xiaomi account"
        else try {
          progress += "Removing the charger from your Xiaomi account…"
          val pid =
            cloud.listDevices(session).firstOrNull { it.did == result.did }?.pid
              ?: throw IllegalStateException("device not found in the account")
          cloud.removeDevice(session, result.did, pid)
          progress += "Removed from your Xiaomi account"
        } catch (e: CancellationException) {
          throw e
        } catch (e: Exception) {
          warning = (warning?.let { "$it\n" } ?: "") +
            "Cannot remove the charger from your Xiaomi account (${e.message}). It still works offline. You can remove it in Mi Home."
        }
        finished = true
      } catch (e: CancellationException) {
        throw e
      } catch (e: Exception) {
        error = e.message ?: e.javaClass.simpleName
      } finally {
        busy = false
      }
    }
  }

  /**
   * Saves a typed token for [charger].
   * @param hex Exactly 24 hex characters. Spaces at the ends are removed.
   * @return Null on success, else an error message.
   */
  fun importToken(charger: ChargerAdvert, hex: String): String? {
    val t = hex.trim()
    if (!isToken24(t)) return "Expected exactly 24 hex characters (12 bytes)"
    return try {
      store.save(charger.address.uppercase(Locale.US), hexToBytes(t))
      null
    } catch (e: IllegalStateException) {
      "Secure storage failed: ${e.message}"
    }
  }
}
