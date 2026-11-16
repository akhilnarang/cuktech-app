package dev.akhilnarang.cuktech.ui.controller

import dev.akhilnarang.cuktech.proto.DiagnosticSnapshot
import dev.akhilnarang.cuktech.proto.PortProtocol
import dev.akhilnarang.cuktech.proto.PortTelemetry
import dev.akhilnarang.cuktech.telemetry.SessionEvent
import dev.akhilnarang.cuktech.telemetry.SessionStats
import dev.akhilnarang.cuktech.telemetry.TelemetryPoint
import dev.akhilnarang.cuktech.telemetry.TelemetrySession

/**
 * Dashboard UI state. The real controller, the previews and the UI tests use it.
 * Port lists have 4 items in the order C1, C2, C3, A.
 *
 * @property dot Color of the connection status dot.
 * @property ready True after the token login is complete.
 * @property stale True if the live data is old or the link is down.
 * @property operation Text of the operation in progress, or null.
 * @property connectionAction Label of the main connection button.
 * @property receivedAt Monotonic receive time of each port, in ms, or null.
 * @property nowMs Monotonic time of this state, in ms.
 * @property props Last known property values, by PIID.
 * @property firmware Running firmware version, or null if not known.
 * @property snapshots Latest vendor diagnostic snapshot, by status selector.
 * @property thermalHistory Latest thermal snapshots, oldest first.
 * @property preview True for demo data. Controls are then disabled.
 * @property cloudSignedIn True if a Xiaomi cloud session is saved.
 */
data class ControllerState(
    val title: String = "Not connected", val detail: String? = "Connect to see your charger.",
    val dot: Dot = Dot.Idle, val ready: Boolean = false, val stale: Boolean = true,
    val busy: Boolean = false, val operation: String? = null,
    val connectionAction: String = "Connect", val connectionActionEnabled: Boolean = true,
    val ports: List<PortTelemetry.Port?> = List(4) { null },
    val protocols: List<PortProtocol?> = List(4) { null },
    val receivedAt: List<Long?> = List(4) { null }, val nowMs: Long = 0,
    val props: Map<Int, Long> = emptyMap(), val firmware: String? = null,
    val notice: String? = null, val temperatureNote: String? = null,
    val snapshots: Map<Int, DiagnosticSnapshot> = emptyMap(),
    val thermalHistory: List<DiagnosticSnapshot> = emptyList(),
    val history: List<TelemetryPoint> = emptyList(), val stats: SessionStats = SessionStats(),
    val events: List<SessionEvent> = emptyList(), val preview: Boolean = false,
    val cloudSignedIn: Boolean = false,
) {
/** True if the user can send a command now. */
    val canControl get() = ready && !busy && !stale && !preview
/** True if [port] (0..3) has a sample that is a maximum of [TelemetrySession.FRESH_MS] old. */
    fun isFresh(port: Int) = !stale && ready && receivedAt[port]?.let { nowMs - it in 0..TelemetrySession.FRESH_MS } == true
/** Total output power of the ports in use, in W, or null if a port is not fresh. */
    val freshTotalW: Double? get() = if ((0..3).all(::isFresh)) ports.sumOf { if (it?.inUse == true) it.powerW else 0.0 } else null
}

/**
 * Callbacks of the dashboard. The defaults do nothing, for previews and tests.
 * Port and timer indexes are 0..3 (C1, C2, C3, A).
 */
data class ControllerActions(
    val connect: () -> Unit = {}, val refresh: () -> Unit = {}, val scene: (Int) -> Unit = {},
    val port: (Int, Boolean) -> Unit = { _, _ -> }, val readTimers: () -> Unit = {},
    val timer: (Int, Int) -> Unit = { _, _ -> }, val usbA: (Boolean) -> Unit = {},
    val screenOff: (Boolean) -> Unit = {}, val orientation: (Boolean) -> Unit = {},
    val screenTime: (Int) -> Unit = {}, val language: (Int) -> Unit = {}, val artwork: (Boolean) -> Unit = {},
    val protocol: (Int, Boolean) -> Unit = { _, _ -> }, val sensors: () -> Unit = {},
    val diagnostics: () -> Unit = {}, val firmware: () -> Unit = {}, val forget: () -> Unit = {},
    val signOutCloud: () -> Unit = {}, val resetSession: () -> Unit = {}, val export: () -> Unit = {}, val copyDiagnostics: () -> Unit = {},
)
