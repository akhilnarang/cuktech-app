package dev.akhilnarang.cuktech.ui.controller

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Dashboard tabs, with the title and subtitle that the header shows. */
enum class DashboardTab(val title: String, val subtitle: String) {
    Overview("Overview", "Charging status"), History("Session", "Trends from received readings"),
    Controls("Controls", "Change charger settings"), Diagnostics("Insights", "Sensors, snapshots and device status")
}

/**
 * Dashboard with adaptive navigation (bar or rail) and four tabs. Back goes to Overview first.
 * Widths of 760 dp and more use the wide layout.
 * @param initialTab Tab to show first. Previews and tests use it.
 */
@Composable
fun DashboardScreen(state: ControllerState, actions: ControllerActions = ControllerActions(), initialTab: DashboardTab = DashboardTab.Overview) {
    var tab by rememberSaveable { mutableStateOf(initialTab) }
    val scrollStates = List(DashboardTab.entries.size) { rememberScrollState() }
    BackHandler(enabled = tab != DashboardTab.Overview) { tab = DashboardTab.Overview }
    val icons = listOf(DashboardIcons.Overview, DashboardIcons.History, DashboardIcons.Controls, DashboardIcons.Diagnostics)
    NavigationSuiteScaffold(
        navigationSuiteItems = {
            DashboardTab.entries.forEachIndexed { index, destination -> item(
                selected = tab == destination, onClick = { tab = destination }, label = { Text(destination.title) },
                icon = { Icon(icons[index], contentDescription = null) },
            ) }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) {
        BoxWithConstraints(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal))) {
            val wide = maxWidth >= 760.dp
            val pageModifier = Modifier.fillMaxSize().verticalScroll(scrollStates[tab.ordinal])
            Column(pageModifier, horizontalAlignment = Alignment.CenterHorizontally) {
                Column(Modifier.widthIn(max = 1240.dp).fillMaxWidth().padding(horizontal = if (wide) 32.dp else 20.dp).padding(top = 20.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = CircleShape) {
                            Icon(DashboardIcons.Bolt, null, Modifier.padding(10.dp).size(24.dp), tint = MaterialTheme.colorScheme.primary)
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text("CUKTECH", style = MaterialTheme.typography.labelLarge, letterSpacing = 2.sp)
                            Caption("UNOFFICIAL  /  AD1204U")
                        }
                        Pill(if (state.preview) "PREVIEW" else "BLUETOOTH")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(tab.title, style = MaterialTheme.typography.headlineLarge)
                            Caption(tab.subtitle)
                        }
                        if (tab == DashboardTab.Overview) IconButton(onClick = actions.refresh, enabled = state.canControl) {
                            Icon(DashboardIcons.Refresh, "Refresh readings")
                        }
                    }
                    ConnectionStrip(state, actions)
                    state.notice?.let { notice ->
                        Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = MaterialTheme.shapes.medium) {
                            Text(notice, Modifier.fillMaxWidth().padding(14.dp), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSecondaryContainer)
                        }
                    }
                    when (tab) {
                        DashboardTab.Overview -> OverviewContent(state, actions, wide) { tab = DashboardTab.History }
                        DashboardTab.History -> HistoryContent(state, actions)
                        DashboardTab.Controls -> ControlsContent(state, actions, wide)
                        DashboardTab.Diagnostics -> DiagnosticsContent(state, actions, wide)
                    }
                }
            }
        }
    }
}

// Status dot, title and caption of the connection, with the connection button.
@Composable
private fun ConnectionStrip(state: ControllerState, actions: ControllerActions) {
    val color = when (state.dot) { Dot.Ok -> MaterialTheme.colorScheme.primary; Dot.Error -> MaterialTheme.colorScheme.error; Dot.Busy -> MaterialTheme.colorScheme.tertiary; Dot.Idle -> MaterialTheme.colorScheme.outline }
    Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainerLow) {
        Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).background(color, CircleShape))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(if (state.preview) "Preview mode" else state.title, style = MaterialTheme.typography.titleSmall, color = color, fontWeight = FontWeight.SemiBold)
                    val caption = when {
                        state.preview -> "Sample data · controls disabled"
                        state.busy -> state.operation ?: "Working…"
                        state.ready && state.freshTotalW != null -> "Receiving output data"
                        state.ready -> "Waiting for new port readings"
                        else -> state.detail
                    }
                    caption?.let { Caption(it) }
                }
                TextButton(onClick = actions.connect, enabled = state.connectionActionEnabled) { Text(if (state.preview) "Exit" else state.connectionAction) }
            }
            if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth().height(2.dp))
        }
    }
}
