package dev.akhilnarang.cuktech.ui.controller

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.akhilnarang.cuktech.proto.MiProto
import dev.akhilnarang.cuktech.proto.PortTelemetry
import dev.akhilnarang.cuktech.theme.NumberStyle
import dev.akhilnarang.cuktech.theme.portColor

/** Scene names, by scene index. */
internal val sceneNames = listOf("AI", "Hybrid", "Single", "Balance")
/** Scene descriptions, by scene index. */
internal val sceneDescriptions = listOf(
    "Sets the assigned limits from the connected ports, load history and controller reports.",
    "Uses the vendor's allocation profile for Apple devices. An Apple device is not necessary.",
    "Gives priority to one port. Other ports can get a smaller assigned limit.",
    "Uses shared-power profiles. Variants with a lower budget also use controller reports.",
)

/**
 * Makes a power series from the history.
 * @param port Port index 0..3, or -1 for the total.
 * @param windowMs Length of the time window before the latest point, in ms.
 */
internal fun historySeries(state: ControllerState, port: Int, color: androidx.compose.ui.graphics.Color, windowMs: Long): ChartSeries {
    val end = state.history.lastOrNull()?.elapsedMs ?: 0
    val values = state.history.filter { it.elapsedMs >= end - windowMs }.map { p ->
        ChartValue(p.elapsedMs, if (port == -1) p.totalW else p.ports[port]?.powerW, p.segment, p.epochMs)
    }
    return ChartSeries(if (port == -1) "Total" else PortTelemetry.PORTS[port], color, values)
}

/** Overview tab: total output, port cards, power trend and the last thermal snapshot. [onHistory] opens the Session tab. */
@Composable
internal fun OverviewContent(state: ControllerState, actions: ControllerActions, wide: Boolean, onHistory: () -> Unit) {
    if (wide) Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
        TotalOutputPanel(state, Modifier.weight(1f))
        PowerTrendPanel(state, onHistory, Modifier.weight(1f))
    } else TotalOutputPanel(state)
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text("Your ports", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
        Caption("Output / assigned limit")
    }
    val columns = if (wide) 4 else 2
    (0..3).toList().chunked(columns).forEach { row ->
        // equal-height cards per row so one port renegotiating doesn't reflow its neighbour
        Row(Modifier.height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            row.forEach { i -> PortOutputCard(state, i, Modifier.weight(1f).fillMaxHeight()) }
        }
    }
    if (!wide) PowerTrendPanel(state, onHistory)
    state.thermalHistory.lastOrNull()?.let { snapshot ->
        Panel {
            Eyebrow("Last thermal snapshot")
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Metric("Shell · NTC2", snapshot.reading.thermal.shellEstimateC?.let { "$it °C" } ?: "—", Modifier.weight(1f))
                Metric("Protection · NTC1", snapshot.reading.thermal.protectionEstimateC?.let { "$it °C" } ?: "—", Modifier.weight(1f))
            }
            Caption("Experimental estimates · received ${snapshot.ageText(state.nowMs)}. Open Insights to get a new snapshot.")
        }
    }
}

@Composable
private fun TotalOutputPanel(state: ControllerState, modifier: Modifier = Modifier) {
    val scene = state.props[MiProto.PIID_SCENE_MODE]?.toInt()?.let(MiProto::sceneModeIndex)
    Card(modifier = modifier, shape = RoundedCornerShape(28.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
        Column(Modifier.fillMaxWidth().background(Brush.linearGradient(listOf(MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.surfaceContainerLowest.copy(alpha = 0.45f)))).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Eyebrow("Total output")
                Pill(if (state.preview) "SAMPLE" else if (state.freshTotalW != null) "LIVE" else "NO LIVE DATA")
            }
            Row(verticalAlignment = Alignment.Bottom) {
                Text(number(state.freshTotalW), style = MaterialTheme.typography.displayLarge)
                Text("W", Modifier.padding(start = 8.dp, bottom = 10.dp), style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            }
            Caption(when {
                state.freshTotalW != null -> "${state.ports.count { it?.inUse == true }} of 4 ports active · output = reported V × A"
                state.ports.any { it != null } -> "The last readings are below. Waiting for new data from all ports."
                else -> "Connect your charger to see live data."
            })
            HorizontalDivider(color = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Metric("Charging scene", scene?.let { sceneNames.getOrNull(it) } ?: "—", Modifier.weight(1f))
                Metric("Session peak", number(state.stats.peakW.takeIf { state.history.isNotEmpty() }, " W"), Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun PowerTrendPanel(state: ControllerState, onHistory: () -> Unit, modifier: Modifier = Modifier) {
    Panel(modifier) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) { Text("Power over time", style = MaterialTheme.typography.titleMedium); Caption("Last 5 minutes · gaps are shown") }
            TextButton(onClick = onHistory) { Text("Session") }
        }
        if (state.history.size < 2) EmptyState("Your graph starts here", "Power history shows when readings arrive.")
        else TelemetryChart(listOf(historySeries(state, -1, MaterialTheme.colorScheme.primary, 300_000)), height = 130, interactive = false)
    }
}

@Composable
private fun PortOutputCard(state: ControllerState, index: Int, modifier: Modifier) {
    val p = state.ports[index]; val color = portColor(index); val fresh = state.isFresh(index)
    val enabled = state.props[MiProto.PIID_PORT_CTL]?.let { it and (1L shl index) != 0L }
    Card(modifier, shape = RoundedCornerShape(22.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
        border = BorderStroke(1.dp, if (p?.inUse == true && fresh) color.copy(alpha = 0.5f) else MaterialTheme.colorScheme.outlineVariant)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            // fixed line count per card: every row always renders, single-line with ellipsis
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(PortTelemetry.PORTS[index], style = MaterialTheme.typography.titleLarge, color = color)
                Caption(if (p == null) "No data" else if (!fresh) "Cached" else if (enabled == false) "Off" else if (p.inUse) "Active" else "Idle", maxLines = 1)
            }
            Text(number(p?.let { if (it.inUse) it.powerW else 0.0 }, " W"), style = MaterialTheme.typography.headlineMedium.merge(NumberStyle), maxLines = 1)
            Caption(if (p == null) "Waiting for readings" else "${number(p.voltageV)} V · ${number(p.currentA)} A", maxLines = 1)
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f))
            val protocol = state.protocols[index]?.takeIf { p?.inUse == true }
            Text(protocol?.label?.substringBefore(" · cap") ?: "No reported protocol",
                style = MaterialTheme.typography.labelLarge, color = color, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
            val allocation = p?.let { PortTelemetry.capDescription(index, it.capCode).replace("max ", "") }
            Caption("Assigned: ${allocation ?: "—"}", maxLines = 1)
            Caption("Code ${protocol?.raw ?: "—"}", maxLines = 1)
        }
    }
}

/** Session tab: statistics, output history chart, port energy, activity log, export and reset. */
@Composable
internal fun HistoryContent(state: ControllerState, actions: ControllerActions) {
    var minutes by rememberSaveable { mutableIntStateOf(5) }
    var selected by rememberSaveable { mutableIntStateOf(-1) }
    var confirmReset by remember { mutableStateOf(false) }
    Panel {
        Text("Session statistics", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Metric("Estimated energy", number(state.stats.energyWh, " Wh", 3), Modifier.weight(1f))
            Metric("Peak output", number(state.stats.peakW.takeIf { state.history.isNotEmpty() }, " W"), Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Metric("Average output", number(state.stats.averageW, " W"), Modifier.weight(1f))
            Metric("Covered time", duration(state.stats.coveredMs), Modifier.weight(1f))
        }
        Caption("Energy and average use only complete, new samples. Reconnects and gaps longer than 5 seconds are not included. This is an output estimate. It does not measure mains or battery power.")
    }
    Panel {
        Text("Output history", style = MaterialTheme.typography.titleMedium)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(1, 5, 15, 60).forEach { m -> FilterChip(selected = minutes == m, onClick = { minutes = m }, label = { Text("${m}m") }) }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            (-1..4).forEach { i -> FilterChip(selected = selected == i, onClick = { selected = i }, label = { Text(if (i == -1) "Total" else if (i == 4) "Compare" else PortTelemetry.PORTS[i]) }) }
        }
        if (state.history.isEmpty()) EmptyState("No session samples yet", "Connect to record power. The session is kept in memory only.")
        else {
            val series = if (selected == 4) (0..3).map { historySeries(state, it, portColor(it), minutes * 60_000L) }
                else listOf(historySeries(state, selected, if (selected == -1) MaterialTheme.colorScheme.primary else portColor(selected), minutes * 60_000L))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) { series.forEach { Pill(it.name, it.color) } }
            TelemetryChart(series)
        }
        Caption("This phone keeps up to 60 minutes of new readings. Statistics cover this session since the last reset. The export contains the kept samples. An app restart clears the session.")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = actions.export, enabled = state.history.isNotEmpty() && !state.preview) { Text("Export CSV") }
            TextButton(onClick = { confirmReset = true }, enabled = !state.preview && state.history.isNotEmpty()) { Text("Reset session") }
        }
    }
    Panel {
        Text("Per-port energy", style = MaterialTheme.typography.titleMedium)
        Caption("Each port uses its own valid intervals, so its coverage can be different from the total.")
        (0..3).forEach { i -> Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(PortTelemetry.PORTS[i], color = portColor(i), style = MaterialTheme.typography.titleSmall)
            Caption("${number(state.stats.portEnergyWh[i], " Wh", 3)} · peak ${number(state.stats.portPeakW[i], " W")}")
        } }
    }
    Panel {
        Text("Session activity", style = MaterialTheme.typography.titleMedium)
        if (state.events.isEmpty()) Caption("Connections, output changes and confirmed settings show here.")
        state.events.takeLast(20).asReversed().forEach { event ->
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) { Text(time(event.epochMs), style = MaterialTheme.typography.labelMedium, fontFamily = FontFamily.Monospace); Text(event.text, style = MaterialTheme.typography.bodyMedium) }
        }
    }
    if (confirmReset) AlertDialog(onDismissRequest = { confirmReset = false }, title = { Text("Reset this session?") },
        text = { Text("This clears the graph, estimated energy and activity on this phone. Charger settings do not change. To keep the samples, export them first.") },
        confirmButton = { TextButton(onClick = { actions.resetSession(); confirmReset = false }) { Text("Reset") } },
        dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Cancel") } })
}
