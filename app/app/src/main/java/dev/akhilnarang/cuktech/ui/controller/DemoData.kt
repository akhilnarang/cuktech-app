package dev.akhilnarang.cuktech.ui.controller

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.akhilnarang.cuktech.proto.*
import dev.akhilnarang.cuktech.telemetry.*
import dev.akhilnarang.cuktech.ui.hexToBytes
import kotlin.math.sin

/** Generated data for the labelled dashboard preview. It has no controller, token or BLE access. */
object DemoData {
/** Makes a preview state with 300 s of example history. */
    fun state(): ControllerState {
        val recorder = TelemetrySession()
        val epoch = 1_797_040_800_000L
        for (i in 0..300) {
            val ports = listOf(
                PortSample(20.0, 1.6 + sin(i / 30.0) * 0.35, true, 6, "PD Fixed"),
                PortSample(9.0, 2.0 + sin(i / 18.0) * 0.45, true, 4, "PD PPS"),
                PortSample(9.0, 0.7 + sin(i / 26.0) * 0.2, true, 0x60, "UFCS"),
                PortSample(0.0, 0.0, false, 0x60, null),
            )
            recorder.record(i * 1000L, epoch + i * 1000L, ports, List(4) { i * 1000L })
        }
        val sensor = VendorStatus.decodeStatus(hexToBytes("fedcba01f1020a28242c07020129000000ef"), 2)
        val snapshots = listOf(36, 37, 38, 40).mapIndexed { i, temp ->
            val frame = hexToBytes("fedcba01f1020a28242c07020129000000ef"); frame[7] = temp.toByte(); frame[13] = (temp + 1).toByte()
            DiagnosticSnapshot(VendorStatus.decodeStatus(frame, 2), java.time.Instant.ofEpochMilli(epoch + i * 80_000).atOffset(java.time.ZoneOffset.UTC).toString(), i * 80_000L)
        }
        return ControllerState(
            title = "Dashboard preview", detail = "Generated example data", dot = Dot.Ok, ready = true, stale = false,
            connectionAction = "Exit preview", ports = listOf(PortTelemetry.decode(0, 0xc8120601L), PortTelemetry.decode(1, 0x5a140401L), PortTelemetry.decode(2, 0x5a076001L), PortTelemetry.decode(3, 0x00006000)),
            protocols = listOf(PortProtocol.decode(0, 0x07410837), PortProtocol.decode(1, 0x07410837), PortProtocol.decode(2, 0x0a160000), PortProtocol.decode(3, 0)),
            receivedAt = List(4) { 300_000L }, nowMs = 300_000, firmware = "2.1.2_0073",
            props = mapOf(MiProto.PIID_SCENE_MODE to 1L, MiProto.PIID_PORT_CTL to 15L, MiProto.PIID_USB_A_ALWAYS_ON to 0L,
                MiProto.PIID_SCREEN_SAVE_TIME to 30L, MiProto.PIID_SCREEN_OFF_IDLE to 1L, MiProto.PIID_SCREEN_DIR_LOCK to 0L,
                MiProto.PIID_DEVICE_LANGUAGE to 0L, MiProto.PIID_PROTOCOL_CTL_EXTEND to 0x03030f0fL,
                MiProto.PIID_COUNTDOWN_C1 to 0L, (MiProto.PIID_COUNTDOWN_C1 + 1) to 60L, (MiProto.PIID_COUNTDOWN_C1 + 2) to 0L, (MiProto.PIID_COUNTDOWN_C1 + 3) to 0L),
            snapshots = mapOf(2 to snapshots.last()), thermalHistory = snapshots, history = recorder.points(), stats = recorder.stats,
            events = listOf(SessionEvent(epoch, "Sample session started"), SessionEvent(epoch + 90_000, "C2 output active"), SessionEvent(epoch + 180_000, "Confirmed: charging scene")), preview = true,
        )
    }
}

/** Dashboard with [DemoData]. The connection button calls [onBack]. */
@Composable
fun DemoScreen(onBack: () -> Unit) {
    val state = remember { DemoData.state() }
    DashboardScreen(state, ControllerActions(connect = onBack))
}
