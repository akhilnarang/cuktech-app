package dev.akhilnarang.cuktech.ui.controller

import dev.akhilnarang.cuktech.firmware.FirmwareSupport
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.akhilnarang.cuktech.proto.DiagnosticSnapshot
import dev.akhilnarang.cuktech.theme.portColor

/** Insights tab: thermal snapshot, sensor history, power-control settings and vendor snapshots. */
@Composable
internal fun DiagnosticsContent(state: ControllerState, actions: ControllerActions, wide: Boolean) {
    val latest = state.thermalHistory.lastOrNull()
    val thermal = latest?.reading?.thermal
    val supported = state.firmware in FirmwareSupport.DIAGNOSTICS
    Panel {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { Pill("ON REQUEST"); Pill("EXPERIMENTAL") }
        Text("Thermal snapshot", style = MaterialTheme.typography.titleLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Metric("Shell input · NTC2", thermal?.shellEstimateC?.let { "$it °C" } ?: "—", Modifier.weight(1f), portColor(0))
            Metric("Protection input · NTC1", thermal?.protectionEstimateC?.let { "$it °C" } ?: "—", Modifier.weight(1f), portColor(1))
        }
        Caption(if (latest == null) "No sensor reply yet." else "Received ${latest.receivedAt} · ${latest.ageText(state.nowMs)}")
        Text("These are experimental NTC estimates from cached controller data. The receive time is not the time of the sensor measurement.", style = MaterialTheme.typography.bodyMedium)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = actions.sensors, enabled = state.canControl && supported) { Text("Read sensors") }
            OutlinedButton(onClick = actions.diagnostics, enabled = state.canControl && supported) { Text("Read all diagnostics") }
        }
        Caption("Each request stops output updates for a short time, then the app reconnects. Sensor reads are manual to prevent repeated interruptions.")
        if (!supported) Caption("Diagnostic layouts are known only for firmware ${FirmwareSupport.describe(FirmwareSupport.DIAGNOSTICS)}. Connect to read your version.")
        state.temperatureNote?.let { Caption(it) }
    }
    if (state.thermalHistory.isNotEmpty()) Panel {
        Text("Received sensor history", style = MaterialTheme.typography.titleMedium)
        val series = listOf(ChartSeries("NTC2", portColor(0), state.thermalHistory.mapIndexed { i, s -> ChartValue(s.receivedElapsedMs, s.reading.thermal.shellEstimateC?.toDouble(), i, java.time.OffsetDateTime.parse(s.receivedAt).toInstant().toEpochMilli()) }),
            ChartSeries("NTC1", portColor(1), state.thermalHistory.mapIndexed { i, s -> ChartValue(s.receivedElapsedMs, s.reading.thermal.protectionEstimateC?.toDouble(), i, java.time.OffsetDateTime.parse(s.receivedAt).toInstant().toEpochMilli()) }))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { series.forEach { Pill(it.name, it.color) } }
        TelemetryChart(series, unit = "°C", dots = true)
        Caption("${state.thermalHistory.size} snapshots received in this session. Each dot is one reading. The temperature is not sampled continuously.")
    }
    if (thermal != null) Panel {
        Text("Power-control settings", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Metric("Rail setting", thermal.railText(), Modifier.weight(1f))
            Metric("PFC setting", thermal.pfcText(), Modifier.weight(1f))
        }
        Caption("These are the commanded control settings. They are not measured rail feedback or a fault mask.")
        HorizontalDivider()
        Metric("MCU diagnostic byte", thermal.mcuText())
        Caption("Units not confirmed. The reply has only the low byte of the conversion, so it is not a reliable Celsius value.")
        Caption("AC sense proxy: ${thermal.acProxyMv} mV · not mains voltage or input power.")
    }
    Panel {
        Text("About assigned power", style = MaterialTheme.typography.titleMedium)
        Caption("Output watts = voltage × current. An assigned limit is the maximum that the charger allows for a port. Idle ports can hold reserves, so the sum of the limits is not the total output.")
        Caption("AI uses load history, controller reports and connection order. The firmware thermal stages have internal budgets of 120 / 120 / 90 / 0 W. When the charger cools, the host code requests a new allocation automatically.")
        Pill("ACTIVE THERMAL STAGE NOT REPORTED")
        Caption("The available replies do not show the current stage, the remaining shared budget, the C2 startup-gate state or the exact reason for a limit.")
    }
    state.snapshots.toSortedMap().values.forEach { snapshot -> SnapshotPanel(snapshot, state.nowMs) }
    Panel {
        Text("Protocol and device data", style = MaterialTheme.typography.titleMedium)
        Caption("Protocol labels come from the controller reports and the official app. C1/C2 09 is probably miPPS. The official app shows it as PPS. USB-A 02 is not known. The app keeps the raw pairs for comparison.")
        Caption("The charger detects the device brand, but it does not send the device VID or brand to the app. An Apple or Xiaomi device does not confirm the negotiated protocol.")
        Caption("The firmware contains BEAST artwork and factory display tests. No command to start them is known. The app does not show switches that do not work.")
        OutlinedButton(onClick = actions.copyDiagnostics, enabled = !state.preview) { Text("Copy diagnostic report") }
        Caption("Reports do not include account credentials, the address, tokens or session keys.")
    }
}

// One vendor snapshot with its decoded fields and the raw reply on request.
@Composable
private fun SnapshotPanel(snapshot: DiagnosticSnapshot, nowMs: Long) {
    var raw by remember { mutableStateOf(false) }
    Panel {
        Text(snapshot.reading.title, style = MaterialTheme.typography.titleMedium)
        Caption("Snapshot received ${snapshot.ageText(nowMs)} · mostly cached")
        snapshot.reading.fields.forEach { (label, value) ->
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Caption(label)
                Text(value, style = MaterialTheme.typography.bodyMedium)
            }
        }
        TextButton(onClick = { raw = !raw }) { Text(if (raw) "Hide raw reply" else "Show raw reply") }
        if (raw) Text(snapshot.reading.rawHex, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
    }
}
