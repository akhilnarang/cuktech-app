package dev.akhilnarang.cuktech.ui.controller

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.LifecycleStartEffect
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.akhilnarang.cuktech.ui.appViewModelExtras

/**
 * Live dashboard for the saved charger. It asks for the Bluetooth and notification permissions.
 * @param onForgotten Called after the user forgets the charger, or if the saved token is lost.
 * @param onFirmware Called to open the firmware screen.
 */
@Composable
fun ControllerScreen(onForgotten: () -> Unit, onFirmware: () -> Unit, vm: ControllerViewModel = viewModel(extras = appViewModelExtras())) {
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission(), vm::onPermissionResult)
    LaunchedEffect(vm.needsPermission) {
        if (vm.needsPermission && Build.VERSION.SDK_INT >= 31) permission.launch(Manifest.permission.BLUETOOTH_CONNECT)
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    var notificationAsked by remember { mutableStateOf(false) }
    LaunchedEffect(vm.ready) { if (vm.ready && !notificationAsked && Build.VERSION.SDK_INT >= 33) { notificationAsked = true; notifications.launch(Manifest.permission.POST_NOTIFICATIONS) } }
    LaunchedEffect(vm.credentialsLost) { if (vm.credentialsLost) onForgotten() }
    LifecycleResumeEffect(vm) { vm.onResume(); onPauseOrDispose {} }
    LifecycleStartEffect(vm) { onStopOrDispose { vm.onStop() } }
    val clipboard = LocalClipboardManager.current
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { if (it != null) vm.exportCsv(it) }
    val actions = ControllerActions(
        connect = vm::onConnectClicked, refresh = vm::refreshReadings, scene = vm::setScene, port = vm::setPort,
        readTimers = vm::loadTimers, timer = vm::setTimer, usbA = vm::setUsbA, screenOff = vm::setScreenOff,
        orientation = vm::setDirLock, screenTime = vm::setScreenTime, language = vm::setLanguage,
        artwork = vm::setHolidayArtwork, protocol = vm::setProtocol, sensors = vm::readTemperature,
        diagnostics = vm::readDiagnostics, firmware = { vm.prepareFirmware(); onFirmware() },
        forget = { vm.forget(); onForgotten() }, signOutCloud = vm::signOutCloud, resetSession = vm::resetSession,
        export = { export.launch("cuktech-session-${java.time.LocalDate.now()}.csv") },
        copyDiagnostics = { clipboard.setText(AnnotatedString(vm.diagnosticSummary())) },
    )
    DashboardScreen(vm.state, actions)
}
