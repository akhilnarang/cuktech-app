package dev.akhilnarang.cuktech.ui.controller

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.akhilnarang.cuktech.proto.*
import dev.akhilnarang.cuktech.theme.portColor

/** Controls tab: scene, port power and timers, display, protocols and device. [wide] uses two columns. */
@Composable
internal fun ControlsContent(state: ControllerState, actions: ControllerActions, wide: Boolean) {
    if (!state.canControl) Caption(if (state.preview) "Preview controls are read-only." else if (state.ready) "Settings are available when the current operation is complete." else "Connect to read and change settings. The last values read can stay visible.")
    ScenePanel(state, actions)
    if (wide) Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(20.dp)) { PortSettingsPanel(state, actions); ProtocolPanel(state, actions) }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(20.dp)) { DisplayPanel(state, actions); DevicePanel(state, actions) }
    } else { PortSettingsPanel(state, actions); DisplayPanel(state, actions); ProtocolPanel(state, actions); DevicePanel(state, actions) }
}

@Composable
private fun ScenePanel(state: ControllerState, actions: ControllerActions) {
    val scene = state.props[MiProto.PIID_SCENE_MODE]?.toInt()?.let(MiProto::sceneModeIndex)
    Panel {
        Text("Charging scene", style = MaterialTheme.typography.titleMedium)
        Caption("The charger sets the assigned limits. They are not a guaranteed simultaneous output or a measured consumption.")
        (0..3).toList().chunked(2).forEach { row -> Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            row.forEach { i ->
                Card(onClick = { actions.scene(i) }, enabled = state.canControl && scene != null, modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(16.dp), border = BorderStroke(if (scene == i) 2.dp else 1.dp, if (scene == i) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant),
                    colors = CardDefaults.cardColors(containerColor = if (scene == i) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerLowest,
                        disabledContainerColor = if (scene == i) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerLow,
                        disabledContentColor = MaterialTheme.colorScheme.onSurface)) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(sceneNames[i], style = MaterialTheme.typography.titleMedium)
                        Caption(sceneDescriptions[i])
                        if (scene == i) Text("Selected", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                    }
                }
            }
        } }
        Caption("AI also uses load history and destination-voltage reports. Hybrid is the vendor's Apple profile. Balance does not guarantee equal watts. The app reads back each change before it shows success.")
    }
}

@Composable
private fun PortSettingsPanel(state: ControllerState, actions: ControllerActions) {
    var edit by remember { mutableStateOf<Int?>(null) }
    val mask = state.props[MiProto.PIID_PORT_CTL]
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Port power & timers", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = actions.readTimers, enabled = state.canControl) { Text("Read timers") }
        }
        (0..3).forEach { i ->
            val timer = state.props[MiProto.PIID_COUNTDOWN_C1 + i]
            Row(Modifier.fillMaxWidth().heightIn(min = 64.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(PortTelemetry.PORTS[i], style = MaterialTheme.typography.titleLarge, color = portColor(i), modifier = Modifier.width(36.dp))
                Column(Modifier.weight(1f)) {
                    Text(if (mask == null) "Not read" else if (mask and (1L shl i) != 0L) "Enabled" else "Disabled", style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = { edit = i }, enabled = state.canControl && timer != null, contentPadding = PaddingValues(0.dp)) {
                        Text(when { timer == null -> "Read timers first"; timer == 0L -> "Set shutdown timer"; else -> "Off in ${duration(timer * 60_000)}" }, style = MaterialTheme.typography.labelMedium)
                    }
                }
                Switch(checked = mask?.let { it and (1L shl i) != 0L } == true, onCheckedChange = { actions.port(i, it) }, enabled = state.canControl && mask != null)
            }
            if (i < 3) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
        }
        Caption("A disabled port stops charging. Timers show the remaining minutes from the last charger report. Read them again to update.")
        HorizontalDivider()
        SwitchSetting("USB-A keep-on", "Keeps USB-A on when idle, up to the firmware limit of about 4 hours.", state.props[MiProto.PIID_USB_A_ALWAYS_ON], state.canControl, actions.usbA)
    }
    edit?.let { i -> ShutdownDialog(PortTelemetry.PORTS[i], state.props[MiProto.PIID_COUNTDOWN_C1 + i]?.toInt() ?: 0, { edit = null }) { actions.timer(i, it); edit = null } }
}

// Asks for a timer of 1..65535 minutes. 0 cancels the timer.
@Composable
private fun ShutdownDialog(port: String, current: Int, dismiss: () -> Unit, apply: (Int) -> Unit) {
    var minutes by remember { mutableStateOf(current.takeIf { it > 0 }?.toString() ?: "60") }
    val parsed = minutes.toIntOrNull()?.takeIf { it in 1..65535 }
    AlertDialog(onDismissRequest = dismiss, title = { Text("$port shutdown timer") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Turn off this port after a delay. The timer changes charging on $port.")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(30, 60, 120, 240).forEach { m -> FilterChip(selected = minutes == m.toString(), onClick = { minutes = m.toString() }, label = { Text(if (m < 60) "${m}m" else "${m / 60}h") }) }
            }
            OutlinedTextField(minutes, { if (it.length <= 5 && it.all(Char::isDigit)) minutes = it }, singleLine = true,
                label = { Text("Minutes") }, supportingText = { Text("1–65,535 minutes") }, isError = parsed == null,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
            if (current > 0) TextButton(onClick = { apply(0) }) { Text("Cancel timer") }
        }
    }, confirmButton = { TextButton(onClick = { parsed?.let(apply) }, enabled = parsed != null) { Text("Apply timer") } },
        dismissButton = { TextButton(onClick = dismiss) { Text("Back") } })
}

@Composable
private fun DisplayPanel(state: ControllerState, actions: ControllerActions) {
    Panel {
        Text("Charger display", style = MaterialTheme.typography.titleMedium)
        Caption("Screen timeout")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) { ScreenTimeout.values().forEach { option ->
            FilterChip(selected = state.props[MiProto.PIID_SCREEN_SAVE_TIME] == option.wireValue.toLong(), onClick = { actions.screenTime(option.wireValue) },
                enabled = state.canControl && state.props.containsKey(MiProto.PIID_SCREEN_SAVE_TIME), label = { Text(option.label) })
        } }
        Caption("Display language")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { listOf("English", "Chinese").forEachIndexed { i, name ->
            FilterChip(selected = state.props[MiProto.PIID_DEVICE_LANGUAGE] == i.toLong(), onClick = { actions.language(i) }, enabled = state.canControl && state.props.containsKey(MiProto.PIID_DEVICE_LANGUAGE), label = { Text(name) })
        } }
        SwitchSetting("Screen off while idle", "Turn off the charger display when nothing is charging.", state.props[MiProto.PIID_SCREEN_OFF_IDLE], state.canControl, actions.screenOff)
        SwitchSetting("Lock screen orientation", "Keep the charger's display from rotating.", state.props[MiProto.PIID_SCREEN_DIR_LOCK], state.canControl, actions.orientation)
        val artwork = state.snapshots[9]?.reading?.holidayArtwork ?: state.snapshots[2]?.reading?.holidayArtwork
        SwitchSetting("Holiday startup artwork", if (artwork == null) "Read sensors in Insights to get this setting." else "Appears at the next charger restart.",
            artwork?.let { if (it) 1L else 0L }, state.canControl && state.firmware == "2.1.2_0073", actions.artwork)
    }
}

@Composable
private fun ProtocolPanel(state: ControllerState, actions: ControllerActions) {
    val mask = state.props[MiProto.PIID_PROTOCOL_CTL_EXTEND]
    Panel {
        Text("Charging protocols", style = MaterialTheme.typography.titleMedium)
        Pill("ADVANCED")
        Caption("Select the known protocols that each port can offer. The connected device selects its contract. Changes can stop charging or start a new negotiation.")
        (0..3).forEach { i ->
            Text(PortTelemetry.PORTS[i], style = MaterialTheme.typography.titleMedium, color = portColor(i))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ProtocolControls.BITS[i].forEachIndexed { n, bit ->
                    val on = mask != null && mask and (1L shl bit) != 0L
                    FilterChip(selected = on, onClick = { actions.protocol(bit, !on) },
                        enabled = state.canControl && mask != null && state.firmware == "2.1.2_0073", label = { Text(ProtocolControls.LABELS[i][n]) })
                }
            }
        }
        Caption("PPS needs PD. Enabling PPS also enables PD, and disabling PD disables PPS. C3/A changes can need a cable replug. Reserved bits do not change. A saved setting does not prove the negotiated protocol.")
        if (state.firmware != "2.1.2_0073") Caption("These switches are known only for firmware 2.1.2_0073.")
    }
}

@Composable
private fun DevicePanel(state: ControllerState, actions: ControllerActions) {
    var forget by remember { mutableStateOf(false) }
    Panel {
        Text("Device & firmware", style = MaterialTheme.typography.titleMedium)
        Metric("Installed version", state.firmware ?: "Not read")
        Caption("CUKTECH AD1204U · China model. Bluetooth control works locally after setup.")
        Button(onClick = actions.firmware, enabled = !state.busy && !state.preview) { Text("Firmware manager") }
        Caption("Download, import, export and install official signed packages (experimental). The updater then has sole control of Bluetooth.")
        HorizontalDivider()
        if (state.cloudSignedIn) TextButton(onClick = actions.signOutCloud, enabled = !state.busy && !state.preview) { Text("Sign out of Xiaomi") }
        TextButton(onClick = { forget = true }, enabled = !state.busy && !state.preview, colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Forget charger") }
    }
    if (forget) AlertDialog(onDismissRequest = { forget = false }, title = { Text("Forget this charger?") },
        text = { Text("This deletes the token and address stored on this phone. To set up again, you need the owner Xiaomi account or the token. The charger itself is not reset.") },
        confirmButton = { TextButton(onClick = { forget = false; actions.forget() }) { Text("Forget") } },
        dismissButton = { TextButton(onClick = { forget = false }) { Text("Cancel") } })
}

/**
 * Switch row for a boolean prop.
 * @param value Prop value: 0 is off, any other value is on, null is not read (the switch is disabled).
 */
@Composable
internal fun SwitchSetting(title: String, subtitle: String, value: Long?, enabled: Boolean, change: (Boolean) -> Unit) {
    val available = enabled && value != null
    val on = value != null && value != 0L
    Row(Modifier.fillMaxWidth().heightIn(min = 64.dp).toggleable(value = on, enabled = available, role = Role.Switch, onValueChange = change).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) { Text(title, style = MaterialTheme.typography.bodyLarge); Caption(subtitle); if (value == null) Caption("Not read") }
        Switch(checked = on, onCheckedChange = null, enabled = available)
    }
}
