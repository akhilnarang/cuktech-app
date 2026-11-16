package dev.akhilnarang.cuktech.ui.firmware

import android.widget.Toast
import android.Manifest
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.akhilnarang.cuktech.ui.appViewModelExtras
import dev.akhilnarang.cuktech.ui.setup.PromptDialog
import dev.akhilnarang.cuktech.ui.setup.regionName

/**
 * Firmware manager screen. Back is blocked while an install runs, and the screen stays on.
 * @param onBack Called to go back to the dashboard.
 */
@Composable
fun FirmwareScreen(onBack: () -> Unit, vm: FirmwareViewModel = viewModel(extras = appViewModelExtras())) {
    val context = LocalContext.current
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var region by remember { mutableStateOf("cn") }
    var confirmInstall by remember { mutableStateOf(false) }
    val view = LocalView.current
    DisposableEffect(vm.installing) {
        val previous = view.keepScreenOn
        if (vm.installing) view.keepScreenOn = true
        onDispose { view.keepScreenOn = previous }
    }
    BackHandler(enabled = vm.installing) { }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
        if (granted.values.all { it }) vm.install()
        else Toast.makeText(context, "Bluetooth permission is needed to install firmware.", Toast.LENGTH_LONG).show()
    }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
        if (it != null) vm.export(it)
    }
    val import = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { if (it != null) vm.importFirmware(it) }
    Box(Modifier.fillMaxSize().safeDrawingPadding().imePadding(), contentAlignment = Alignment.TopCenter) {
    Column(Modifier.widthIn(max = 840.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)) {
        TextButton(onClick = onBack, enabled = !vm.installing) { Text("Back to charger") }
        Text("DEVICE MAINTENANCE", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Text("Firmware manager", style = MaterialTheme.typography.headlineLarge)
        Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = MaterialTheme.shapes.large) {
            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Installed · last read", style = MaterialTheme.typography.labelLarge)
                Text(vm.installedVersion ?: "Connect to read version", style = MaterialTheme.typography.headlineSmall)
                Text("Official signed packages · local Bluetooth installation", style = MaterialTheme.typography.bodySmall)
            }
        }
        Text("Download official firmware and install it directly over Bluetooth. Direct installation is experimental. It is known only for the China AD1204 with 2.1.2_0073.",
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (vm.needsSignIn) {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Sign in for firmware downloads", style = MaterialTheme.typography.titleMedium)
                    Text("Use the account and region linked to this charger. The login session is encrypted on this phone. The app never saves your password.")
                    OutlinedTextField(username, { username = it }, label = { Text("Xiaomi account") },
                        singleLine = true, enabled = !vm.busy, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(password, { password = it }, label = { Text("Password") },
                        singleLine = true, enabled = !vm.busy, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf("cn", "in", "i2", "sg", "de", "us", "ru", "tw").forEach {
                            FilterChip(selected = region == it, onClick = { region = it }, enabled = !vm.busy, label = { Text(regionName(it)) })
                        }
                    }
                    Button(onClick = { vm.signIn(username.trim(), password, region); password = "" },
                        enabled = !vm.busy && username.isNotBlank() && password.isNotEmpty()) { Text("Sign in and check") }
                }
            }
        } else {
            Button(onClick = vm::checkLatest, enabled = !vm.busy) { Text("Check for updates") }
        }
        OutlinedButton(onClick = { import.launch(arrayOf("*/*")) }, enabled = !vm.busy) { Text("Import firmware file") }
        Text("Imported and saved packages work offline. Check for updates uses the owner account to find newer versions.",
            style = MaterialTheme.typography.bodySmall)
        if (vm.busy) {
            val progress = if (vm.installing) vm.installProgress else vm.downloadProgress
            if (progress == null) LinearProgressIndicator(Modifier.fillMaxWidth())
            else LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        }
        vm.installPhase?.let { Text(it, style = MaterialTheme.typography.titleMedium) }
        if (vm.installing) Text("Written to staging: ${((vm.installProgress ?: 0f) * 100).toInt()}%. Keep the charger on power and this phone near it.")
        vm.latest?.let { info ->
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Available: ${info.version}", style = MaterialTheme.typography.titleLarge)
                    Text(info.model, style = MaterialTheme.typography.bodySmall)
                    if (info.changelog.isNotBlank()) Text(info.changelog)
                    Text("MD5: ${info.md5}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    if (info.url.isNotBlank()) Button(onClick = vm::download, enabled = !vm.busy) { Text(if (vm.downloaded) "Download again" else "Download firmware") }
                    if (vm.downloaded) OutlinedButton(onClick = { export.launch(info.fileName) }, enabled = !vm.busy) { Text("Export firmware file") }
                    if (vm.directInstallAvailable) Button(onClick = { confirmInstall = true }, enabled = !vm.busy) {
                        Text(if (info.version == vm.installedVersion) "Reinstall with CUKTECH App" else "Install with CUKTECH App")
                    }
                }
            }
        }
        vm.note?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
        vm.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        OutlinedButton(onClick = {
            val intent = context.packageManager.getLaunchIntentForPackage("com.xiaomi.smarthome")
            if (intent == null) Toast.makeText(context, "Install Xiaomi Home to apply firmware updates.", Toast.LENGTH_LONG).show()
            else context.startActivity(intent)
        }, enabled = !vm.busy) { Text("Open Xiaomi Home") }
        Text("You can also use Xiaomi Home to install firmware. Close Xiaomi Home before you use direct installation.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        TextButton(onClick = vm::forgetLogin, enabled = !vm.busy) { Text("Forget cloud login") }
    }
    }
    if (confirmInstall) AlertDialog(onDismissRequest = { confirmInstall = false },
        title = { Text("Install ${vm.latest?.version}?") },
        text = { Text("Disconnect all devices from the charging ports. Keep the charger on stable mains power and stay near it. WARNING: This updater is experimental and not tested on a real charger. Recovery after an interrupted activation is not verified.") },
        confirmButton = { TextButton(onClick = {
            confirmInstall = false
            permission.launch(if (Build.VERSION.SDK_INT >= 31) arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
                else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION))
        }) { Text("Install firmware") } },
        dismissButton = { TextButton(onClick = { confirmInstall = false }) { Text("Cancel") } })
    vm.prompt?.let { PromptDialog(it, vm::answer) }
}
