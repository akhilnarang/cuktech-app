package dev.akhilnarang.cuktech.ui.controller

import android.Manifest
import android.app.Application
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import dev.akhilnarang.cuktech.ConnectionService
import android.os.Looper
import android.os.SystemClock
import android.widget.Toast
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import dev.akhilnarang.cuktech.telemetry.*
import dev.akhilnarang.cuktech.proto.AndroidGattPort
import dev.akhilnarang.cuktech.proto.MiController
import dev.akhilnarang.cuktech.proto.MiProto
import dev.akhilnarang.cuktech.proto.PortTelemetry
import dev.akhilnarang.cuktech.proto.PortProtocol
import dev.akhilnarang.cuktech.proto.ProtocolControls
import dev.akhilnarang.cuktech.proto.VendorStatus
import dev.akhilnarang.cuktech.proto.DiagnosticSnapshot
import dev.akhilnarang.cuktech.proto.SecureStore
import dev.akhilnarang.cuktech.cloud.CloudSessionStore

/** Color of the connection status dot: idle, in progress, connected, failed. */
enum class Dot { Idle, Busy, Ok, Error }

/**
 * Owns the BLE session with the saved charger and the dashboard state.
 * This is a port of the engine wiring of the 0.3.4 MainActivity.
 * All engine callbacks arrive on the main thread. Call all functions on the main thread.
 */
class ControllerViewModel(app: Application) : AndroidViewModel(app) {
  private val store = SecureStore(app)
  private val sessions = CloudSessionStore(store)
  private var cloudSignedIn by mutableStateOf(sessions.exists())
  private val main = Handler(Looper.getMainLooper())
  private val scheduler =
    object : MiController.Scheduler {
      override fun postDelayed(r: Runnable, ms: Long) {
        main.postDelayed(r, ms)
      }

      override fun cancel(r: Runnable) = main.removeCallbacks(r)
    }

  private var engine: MiController? = null
  private var autoTried = false
  private var wasConnected = false
  private var refreshRetried = false
  private var sessionRetries = 0
  private var reconnectAfterTemperature = false
  private var vendorQueryActive = false
  private var userDisconnected = false
  private var retryTask: Runnable? = null
  private var protocolTask: Runnable? = null
  private var nextProtocolRead = 0L
  private val session = TelemetrySession()
  private var ticking = false
  private var visible = false
/** Text of the operation in progress, or null. */
  var operation by mutableStateOf<String?>(null)
    private set
/** Monotonic time of the last 1 Hz tick, in ms (`SystemClock.elapsedRealtime`). */
  var nowElapsed by mutableLongStateOf(SystemClock.elapsedRealtime())
    private set
/** Monotonic receive time of the last reading of each port, in ms, or null. */
  var receivedAt by mutableStateOf<List<Long?>>(List(4) { null })
    private set
/** Telemetry history for the charts. */
  var history by mutableStateOf<List<TelemetryPoint>>(emptyList())
    private set
/** Statistics of the current session. */
  var statistics by mutableStateOf(SessionStats())
    private set
/** Session log, a maximum of 100 lines, oldest first. */
  var events by mutableStateOf<List<SessionEvent>>(emptyList())
    private set

/** Snapshot of all UI state for [DashboardScreen]. */
  val state: ControllerState get() = ControllerState(
    title, detail, dot, ready, stale, busy, operation, buttonLabel, buttonEnabled,
    ports, List(4) { protocolOf(it) }, receivedAt, nowElapsed, props.toMap(), firmwareVersion,
    note, temperatureNote, vendorSnapshots.toMap(), thermalHistory.toList(), history, statistics, events,
    cloudSignedIn = cloudSignedIn,
  )

  private fun event(text: String) { events = (events + SessionEvent(System.currentTimeMillis(), text)).takeLast(100) }

  private val tick = object : Runnable {
    override fun run() {
      if (!ticking) return
      nowElapsed = SystemClock.elapsedRealtime()
      val e = engine
      if (ready && !vendorQueryActive && !stale) {
        val samples = ports.mapIndexed { i, p -> p?.let { PortSample(it.voltageV, it.currentA, it.inUse, it.capCode, protocolOf(i)?.label) } }
        if (session.record(nowElapsed, System.currentTimeMillis(), samples, receivedAt)) {
          history = session.points(); statistics = session.stats
        }
        if (e != null && !busy && !e.isBusy && nowElapsed >= nextProtocolRead) {
          nextProtocolRead = nowElapsed + 15_000
          readProtocols(e)
        }
      } else session.pause()
      main.postDelayed(this, 1000)
    }
  }

  private fun readProtocols(e: MiController) {
    busy = true
    operation = "Checking charging protocols…"
    e.requestProtocols()
  }

/** BLE address of the saved charger, or null. */
  val mac: String? = store.mac
/** Connection status dot. */
  var dot by mutableStateOf(Dot.Idle)
    private set
/** Connection status title. */
  var title by mutableStateOf("Not connected")
    private set
/** Connection status detail, or null. */
  var detail by mutableStateOf<String?>("Tap Connect to reach the charger.")
    private set
/** Label of the connection button. */
  var buttonLabel by mutableStateOf("Connect")
    private set
/** True if the connection button is enabled. */
  var buttonEnabled by mutableStateOf(true)
    private set
/** True while a logged-in session is active. */
  var ready by mutableStateOf(false)
    private set
/** True if the live data is old: no session, or a vendor query paused the readings. */
  var stale by mutableStateOf(false)
    private set
/** Latest reading of each port (C1, C2, C3, A), or null. */
  var ports by mutableStateOf<List<PortTelemetry.Port?>>(List(4) { null })
    private set
/** Result message of the last action, or null. */
  var note by mutableStateOf<String?>(null)
    private set
/** True if the screen must ask for the Bluetooth connect permission. */
  var needsPermission by mutableStateOf(false)
    private set
  /** Props that the charger confirmed, with the value of a pending set on top. A failed set restores the old value. */
  val props = mutableStateMapOf<Int, Long>()
  private var pendingSet: Pair<Int, Long>? = null
/** True while a command or read is in progress. Other commands are ignored. */
  var busy by mutableStateOf(false)
    private set
/** Running firmware version from this session, or null. */
  var firmwareVersion by mutableStateOf<String?>(null)
    private set
/** Status text of the diagnostics and sensor reads, or null. */
  var temperatureNote by mutableStateOf<String?>(null)
    private set
/** Latest vendor diagnostic snapshot, by status selector. */
  val vendorSnapshots = mutableStateMapOf<Int, DiagnosticSnapshot>()
/** Latest 120 thermal snapshots, oldest first. */
  val thermalHistory = mutableStateListOf<DiagnosticSnapshot>()
/** Latest thermal snapshot, or null. */
  val latestThermal: DiagnosticSnapshot? get() = thermalHistory.lastOrNull()

  /** True if the saved token was corrupt and is deleted. The screen then goes back to setup. */
  var credentialsLost by mutableStateOf(false)
    private set

/** Call when the screen resumes. It starts the tick and connects automatically one time. */
  fun onResume() {
    cloudSignedIn = sessions.exists() // firmware manager may have signed in or out
    visible = true
    startTicking()
    if (engine == null && !autoTried && !userDisconnected) {
      autoTried = true
      startConnect()
    }
  }

  /**
   * Call when the screen stops. The session continues in the background. A user disconnect stays.
   * The 1 Hz tick continues to record while a session is ready (the foreground service keeps the
   * process alive). Else it stops until the screen is visible again.
   */
  fun onStop() {
    visible = false
    if (!ready) stopTicking()
  }

  private fun startTicking() {
    if (!ticking) { ticking = true; main.post(tick) }
  }

  private fun stopTicking() {
    ticking = false
    main.removeCallbacks(tick)
  }

/** Connects, cancels a connection attempt, or disconnects, as the current state requires. */
  fun onConnectClicked() {
    reconnectAfterTemperature = false
    val e = engine
    if ((e != null && !e.isReady) || (e == null && dot == Dot.Busy)) {
      userDisconnected = true
      retryTask?.let(main::removeCallbacks); retryTask = null
      e?.close(); engine = null; ConnectionService.stop(getApplication())
      setDisconnected("Connect"); setState(Dot.Idle, "Disconnected", "Connection cancelled")
      return
    }
    if (e != null) {
      // connecting/disconnecting: ignore; the fenced "closed" status finishes teardown
      if (e.isReady) {
        userDisconnected = true
        session.pause()
        e.userDisconnect()
        buttonLabel = "Disconnecting…"
        buttonEnabled = false
        setState(Dot.Busy, "Disconnecting…", null)
      }
      return
    }
    userDisconnected = false
    sessionRetries = 0
    startConnect()
  }

/** Call with the result of the Bluetooth connect permission request. */
  fun onPermissionResult(granted: Boolean) {
    needsPermission = false
    if (granted && engine == null && !userDisconnected) startConnect()
    else if (!granted) {
      setDisconnected("Connect")
      setState(Dot.Idle, "Permission needed", "Allow Nearby devices to connect to your charger.")
    }
  }

  private fun hasConnectPermission() =
    Build.VERSION.SDK_INT < 31 ||
      getApplication<Application>().checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) ==
        PackageManager.PERMISSION_GRANTED

  private fun startConnect() {
    reconnectAfterTemperature = false
    if (!hasConnectPermission()) {
      needsPermission = true
      setState(Dot.Busy, "Permission needed", "Allow Nearby devices, then tap Connect.")
      return
    }
    val token = store.loadToken()
    if (token == null) {
      setDisconnected("Connect")
      if (store.wasCorrupt()) credentialsLost = true
      else setState(Dot.Error, "Storage unavailable", "Cannot read secure storage now. Tap Connect again.")
      return
    }
    wasConnected = false
    note = null
    ready = false
    stale = true
    receivedAt = List(4) { null }
    props.clear()
    pendingSet = null
    buttonEnabled = true
    buttonLabel = "Cancel"
    setState(Dot.Busy, "Connecting…", null)
    lateinit var self: MiController
    // Session fence: only the current engine may deliver callbacks.
    self = MiController(AndroidGattPort(getApplication()), scheduler, Fenced { engine === self })
    engine = self
    self.connect(token, store.mac)
    token.fill(0) // engine keeps its own clone
  }

// Engine listener. It ignores callbacks from an engine that is no longer current.
  private inner class Fenced(val active: () -> Boolean) : MiController.Listener {
    override fun onVendorStatus(reading: VendorStatus.Reading) {
      if (active()) {
        val snapshot = DiagnosticSnapshot(reading, java.time.OffsetDateTime.now().withNano(0).toString(), SystemClock.elapsedRealtime())
        vendorSnapshots[reading.selector] = snapshot
        if (reading.thermal != null) {
          thermalHistory.add(snapshot)
          if (thermalHistory.size > 120) thermalHistory.removeAt(0)
        }
      }
    }
    override fun onFirmwareVersion(version: String) {
      if (active()) {
        firmwareVersion = version
        store.saveFirmwareVersion(version)
      }
    }
    override fun onStatus(text: String) {
      if (!active()) return
      when {
        text.startsWith("ready") -> {
          if (ready) return // Engine emits both its stage and descriptive ready notification.
          vendorQueryActive = false
          wasConnected = true
          sessionRetries = 0
          ConnectionService.start(getApplication())
          startTicking()
          setState(Dot.Ok, "Connected", "Live data active")
          buttonEnabled = true
          buttonLabel = "Disconnect"
          ready = true
          stale = false
          busy = true
          operation = "Reading charger settings…"
          nextProtocolRead = SystemClock.elapsedRealtime() + 15_000
          event("Charger connected")
        }
        text == "closed" -> {
          engine = null
          ConnectionService.stop(getApplication())
          setState(Dot.Idle, "Disconnected", "Tap Connect to reconnect.")
          setDisconnected("Connect")
          if (reconnectAfterTemperature) {
            setState(Dot.Busy, "Reconnecting…", "Starting live data again after the temperature query")
            buttonEnabled = true
            buttonLabel = "Cancel"
            retryTask = Runnable { if (reconnectAfterTemperature && engine == null && !userDisconnected) startConnect() }
            main.postDelayed(retryTask!!, 2000)
          }
        }
        text == "disconnecting" -> {
          ready = false
          buttonEnabled = false
          setState(Dot.Busy, "Disconnecting…", null)
        }
        else -> setState(Dot.Busy, "Connecting…", text.replaceFirstChar { it.uppercase() })
      }
    }

    override fun onPortsChanged() {
      if (!active()) return
      val e = engine!!
      val now = e.ports.toList()
      // plug/unplug: protocol bytes are only in the settings read, so fetch them again
      val changed = now.map { it?.inUse } != ports.map { it?.inUse }
      val at = SystemClock.elapsedRealtime()
      receivedAt = now.mapIndexed { i, value -> if (value != null && value !== ports[i]) at else receivedAt[i] }
      now.forEachIndexed { i, value ->
        if (value != null && ports[i] != null && value.inUse != ports[i]?.inUse)
          event("${PortTelemetry.PORTS[i]} output ${if (value.inUse) "active" else "idle"}")
      }
      ports = now
      stale = vendorQueryActive || !ready
      if (changed && e.isReady) {
        protocolTask?.let(main::removeCallbacks)
        protocolTask = Runnable { if (engine === e && e.isReady && !busy && !e.isBusy) readProtocols(e) }
        main.postDelayed(protocolTask!!, 500)
      }
    }

    override fun onPropsChanged() {
      if (!active()) return
      renderProps()
    }

    override fun onResult(what: String, ok: Boolean, error: String?) {
      if (!active()) return
      if (what == "protocols") {
        busy = false
        operation = null
        return // A failed protocol read keeps the last reported label.
      }
      if (what == "temperature" || what == "diagnostics" || what == "startup artwork") {
        busy = false
        operation = null
        vendorQueryActive = false
        reconnectAfterTemperature = engine?.temperatureRequiresReconnect == true
        if (reconnectAfterTemperature) stale = true
        temperatureNote = if (!ok) "Diagnostic incomplete: $error"
          else if (what == "startup artwork") "Startup flag accepted. The artwork changes when the charger restarts."
          else "Cached diagnostic readings (experimental)"
        return
      }
      pendingSet = null
      busy = false
      operation = null
      val e = engine
      if (what == "refresh" && ok) refreshRetried = false
      if (what == "refresh" && !ok && !refreshRetried && e != null && e.isReady) {
        refreshRetried = true
        note = "Reading settings again…"
        busy = true
        operation = "Reading settings again…"
        e.requestRefresh()
        return
      }
      note =
        when {
          ok -> if (what == "refresh" || what == "timers") null else "Setting confirmed by charger readback"
          // port readings are pushed by the charger independently
          what == "refresh" -> "Cannot read settings. Live port readings still update. ($error)"
          what == "timers" -> "Cannot read the timers. Move near the charger and try again. ($error)"
          else -> "Cannot change $what. The previous value is restored. ($error)"
        }
      renderProps()
      if (ok && what != "refresh" && what != "timers") event("Confirmed: ${what.replace('_', ' ')}")
    }

    override fun onFatal(stage: String, message: String) {
      if (!active()) return
      if (engine?.temperatureRequiresReconnect == true) {
        temperatureNote = "Diagnostic stopped. Reconnecting to start readings again."
        reconnectAfterTemperature = true
      }
      engine = null
      ConnectionService.stop(getApplication())
      // the charger frees the old session only once it sees the link drop, which can take several
      // seconds after a quick close/reopen; a subscribe failure on the still-closing link is the same case
      val transient = message.startsWith("charger still has the previous session open") || stage == "subscribe" || reconnectAfterTemperature
      if (transient && sessionRetries < RETRY_DELAYS_MS.size) {
        val delay = RETRY_DELAYS_MS[sessionRetries++]
        setState(Dot.Busy, "Connecting…", "The charger is closing the previous session. Retrying (${sessionRetries}/${RETRY_DELAYS_MS.size})")
        setDisconnected("Cancel")
        retryTask = Runnable { if (engine == null && !userDisconnected) startConnect() }
        main.postDelayed(retryTask!!, delay)
        return
      }
      sessionRetries = 0
      val msg =
        when {
          wasConnected -> "Connection lost. Tap Reconnect."
          stage == "connect" -> "Charger not found. Tap Reconnect."
          else -> "Connection failed. Tap Reconnect."
        }
      Toast.makeText(getApplication(), msg, Toast.LENGTH_SHORT).show()
      setState(Dot.Error, "Connection lost", "${stage.replaceFirstChar { it.uppercase() }}: $message")
      setDisconnected("Reconnect")
      event("Connection lost. Recording paused.")
    }
  }

/**
 * Decodes the reported charging protocol of a port from props 0x11 (C1, C2) or 0x12 (C3, A).
 * @param port Port index 0..3.
 * @return The protocol, or null if the prop is not known.
 */
  fun protocolOf(port: Int): PortProtocol? {
    val v = props[if (port < 2) 0x11 else 0x12] ?: return null
    if (v !in 0..0xffffffffL) return null
    return PortProtocol.decode(port, v)
  }

/** Reads the thermal snapshot (vendor query). Firmware 2.1.2_0073 only. Live data pauses during the query. */
  fun readTemperature() {
    val e = engine ?: return
    if (!e.isReady || busy || e.isBusy) return
    if (firmwareVersion != "2.1.2_0073") {
      temperatureNote = "This diagnostic is known only for firmware 2.1.2_0073. Installed version: ${firmwareVersion ?: "unknown"}"
      return
    }
    busy = true
    operation = "Reading sensor snapshot…"
    note = null
    vendorQueryActive = true
    stale = true
    temperatureNote = "Reading thermal snapshot…"
    e.requestTemperature()
  }

/** Reads all vendor diagnostic snapshots. Firmware 2.1.2_0073 only. Live data pauses during the query. */
  fun readDiagnostics() {
    val e = engine ?: return
    if (!e.isReady || busy || e.isBusy) return
    if (firmwareVersion != "2.1.2_0073") {
      temperatureNote = "Diagnostics are known only for firmware 2.1.2_0073. Installed version: ${firmwareVersion ?: "unknown"}"
      return
    }
    busy = true
    operation = "Reading diagnostics…"
    note = null
    vendorQueryActive = true
    stale = true
    vendorSnapshots.clear()
    temperatureNote = "Reading sensors and controller status…"
    e.requestDiagnostics()
  }

/** Sets the startup artwork flag. Firmware 2.1.2_0073 only. The change shows after the charger restarts. */
  fun setHolidayArtwork(enabled: Boolean) {
    val e = engine ?: return
    if (!e.isReady || busy || e.isBusy || firmwareVersion != "2.1.2_0073") return
    busy = true
    operation = "Changing startup artwork…"
    note = null
    vendorQueryActive = true
    stale = true
    temperatureNote = "Changing startup artwork…"
    e.setHolidayArtwork(enabled)
  }

/** Returns a plain-text diagnostic report for the clipboard. It contains no token. */
  fun diagnosticSummary(): String = buildString {
    appendLine("CUKTECH local diagnostics")
    appendLine("Firmware: ${firmwareVersion ?: "unknown"}; connected: $ready; MIOT marked stale: $stale")
    ports.forEachIndexed { index, port ->
      val protocol = protocolOf(index)
      appendLine("${PortTelemetry.PORTS[index]}: ${port?.cap ?: "no telemetry"}; ${port?.voltageV ?: "?"} V; ${port?.currentA ?: "?"} A; ${protocol?.label ?: "unknown protocol"}; code=${protocol?.raw ?: "unavailable"}")
      protocol?.vendorLabel?.let { appendLine("  Official app protocol label: $it") }
      port?.let {
        appendLine("  MIOT 2.${index + 1}=0x${it.raw.toString(16).padStart(8, '0')}; status=0x${(it.raw and 255L).toString(16).padStart(2, '0')}")
      }
    }
    props[MiProto.PIID_PROTOCOL_CTL_EXTEND]?.let { appendLine("Protocol-enable mask: 0x${it.toString(16).padStart(8,'0')}") }
    appendLine("Vendor replies are separate cached snapshots. Receive times are not sensor sample times.")
    appendLine("Protocol names include vendor UI labels. miPPS is not confirmed. USB-A 02 is not known.")
    appendLine("Thermal stage / active power budget / protection flag: not reported")
    vendorSnapshots.toSortedMap().values.forEach { snapshot ->
      val reading = snapshot.reading
      appendLine("${reading.title} · received ${snapshot.receivedAt} (${snapshot.ageText(SystemClock.elapsedRealtime())})")
      reading.fields.forEach { (label, value) -> appendLine("  $label: $value") }
      appendLine("  AF08: ${reading.rawHex}")
    }
    if (thermalHistory.isNotEmpty()) {
      appendLine("Thermal history: last ${thermalHistory.size} received sensor replies, experimental NTC estimates")
      thermalHistory.forEach { snapshot ->
        val thermal = snapshot.reading.thermal
        appendLine("  ${snapshot.receivedAt}: NTC2=${thermal.shellEstimateC ?: "unavailable"}; NTC1=${thermal.protectionEstimateC ?: "unavailable"}; MCU low byte=${thermal.mcuText()}")
      }
    }
  }

/** Reads all settings and readings again. */
  fun refreshReadings() {
    val e = engine ?: return
    if (!e.isReady || busy || e.isBusy) return
    busy = true
    operation = "Refreshing readings and settings…"
    note = null
    e.requestRefresh()
  }

  private fun renderProps() {
    props.clear()
    engine?.props?.let { props.putAll(it) }
    pendingSet?.let { (k, v) -> props[k] = v }
    stale = vendorQueryActive || !ready
  }

// Shows the new value at once, sends it, and restores the old value if the readback fails.
  private fun set(piid: Int, value: Long, send: MiController.() -> Unit) {
    val e = engine ?: return
    if (!e.isReady || busy || e.isBusy || !props.containsKey(piid) || props[piid] == value) return
    pendingSet = piid to value
    busy = true
    operation = "Applying setting and verifying readback…"
    note = null
    props[piid] = value
    e.send()
  }

/** Sets the scene mode. [index] is the position in the scene list. */
  fun setScene(index: Int) = set(MiProto.PIID_SCENE_MODE, MiProto.sceneModeValue(index).toLong()) { setSceneMode(MiProto.sceneModeValue(index)) }

/** Sets USB-A always-on. */
  fun setUsbA(on: Boolean) = set(MiProto.PIID_USB_A_ALWAYS_ON, if (on) 1 else 0) { setUsbAAlwaysOn(on) }

/** Sets screen off when idle. */
  fun setScreenOff(on: Boolean) = set(MiProto.PIID_SCREEN_OFF_IDLE, if (on) 1 else 0) { setScreenOffIdle(on) }

/** Sets the screen orientation lock. */
  fun setDirLock(on: Boolean) = set(MiProto.PIID_SCREEN_DIR_LOCK, if (on) 1 else 0) { setScreenDirLock(on) }

/** Sets the screen saver time, in the charger units of PIID_SCREEN_SAVE_TIME. */
  fun setScreenTime(value: Int) = set(MiProto.PIID_SCREEN_SAVE_TIME, value.toLong()) { setScreenSaveTime(value) }

/** Sets the charger display language code. */
  fun setLanguage(value: Int) = set(MiProto.PIID_DEVICE_LANGUAGE, value.toLong()) { setDeviceLanguage(value) }

/** Turns port [index] (0..3) on or off in the port mask. */
  fun setPort(index: Int, on: Boolean) {
    val old = props[MiProto.PIID_PORT_CTL]?.toInt() ?: return
    val mask = if (on) old or (1 shl index) else old and (1 shl index).inv()
    set(MiProto.PIID_PORT_CTL, mask.toLong()) { setPortMask(mask) }
  }

/** Sets one protocol-enable bit. Firmware 2.1.2_0073 only. */
  fun setProtocol(bit: Int, on: Boolean) {
    if (firmwareVersion != "2.1.2_0073") return
    val old = props[MiProto.PIID_PROTOCOL_CTL_EXTEND] ?: return
    val next = ProtocolControls.update(old, bit, on)
    set(MiProto.PIID_PROTOCOL_CTL_EXTEND, next) { setProtocolFlag(bit, on) }
  }

/** Reads the shutdown timers of all ports. */
  fun loadTimers() {
    val e = engine ?: return
    if (!e.isReady || busy || e.isBusy) return
    busy = true
    operation = "Reading shutdown timers…"
    note = null
    e.readCountdowns()
  }

/** Sets the shutdown timer of port [index] (0..3), in minutes. 0 turns it off. */
  fun setTimer(index: Int, minutes: Int) = set(MiProto.PIID_COUNTDOWN_C1 + index, minutes.toLong()) {
    setCountdown(index, minutes)
  }

/** Disconnects and deletes the saved charger token and address. */
  fun forget() {
    reconnectAfterTemperature = false
    engine?.close()
    engine = null
    userDisconnected = true
    main.removeCallbacksAndMessages(null); ticking = false
    ConnectionService.stop(getApplication())
    store.clear()
  }

  /** Deletes only the saved Xiaomi cloud login. The Bluetooth token of the charger stays. */
  fun signOutCloud() {
    sessions.clear()
    cloudSignedIn = false
    note = "Signed out of Xiaomi. The charger still works offline. To check for firmware, sign in again."
  }

  /** Closes the session so that the firmware updater has the only BLE connection to the charger. */
  fun prepareFirmware() {
    main.removeCallbacksAndMessages(null)
    ticking = false
    reconnectAfterTemperature = false
    engine?.close()
    engine = null
    autoTried = false
    userDisconnected = false
    ConnectionService.stop(getApplication())
    setDisconnected("Connect")
    title = "Disconnected for firmware"
  }

  private fun setState(d: Dot, t: String, det: String?) {
    dot = d
    title = t
    detail = det
  }

  private fun setDisconnected(label: String) {
    buttonEnabled = true
    buttonLabel = label
    ready = false
    busy = false
    pendingSet = null
    stale = true
    operation = null
    session.pause()
    receivedAt = List(4) { null }
    if (!visible) stopTicking()
  }

/** Clears the history, the statistics and the session log. */
  fun resetSession() {
    session.clear(); history = emptyList(); statistics = SessionStats(); events = emptyList()
    event("Session statistics reset")
  }

/** Writes the history as CSV to [uri] on the IO dispatcher. The result goes in [note]. */
  fun exportCsv(uri: Uri) {
    val snapshot = history.toList()
    viewModelScope.launch {
      note = try {
        withContext(Dispatchers.IO) {
          getApplication<Application>().contentResolver.openOutputStream(uri, "wt")?.bufferedWriter()?.use { it.write(TelemetryCsv.encode(snapshot)) }
            ?: error("The selected file could not be opened")
        }
        "Exported ${snapshot.size} receive-time samples"
      } catch (e: kotlinx.coroutines.CancellationException) { throw e }
      catch (_: Exception) { "Could not save the session CSV. Choose another file and try again." }
    }
  }

  private companion object {
    val RETRY_DELAYS_MS = longArrayOf(3000, 5000, 8000, 12000)
  }

  override fun onCleared() {
    main.removeCallbacksAndMessages(null) // no pending retry may reconnect after the screen is gone
    engine?.close()
    engine = null
    ConnectionService.stop(getApplication())
  }
}
