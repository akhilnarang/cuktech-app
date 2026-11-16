package dev.akhilnarang.cuktech.ui.setup

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.akhilnarang.cuktech.ChargerAdvert
import dev.akhilnarang.cuktech.ui.appViewModelExtras

private val BLE_PERMISSIONS =
  if (Build.VERSION.SDK_INT >= 31) arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
  else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

private val REGIONS = listOf("cn", "in", "i2", "sg", "de", "us", "ru", "tw")

/** Returns the display name of a Xiaomi cloud region code. An unknown code is returned unchanged. */
internal fun regionName(code: String): String = when (code) {
  "cn" -> "China"; "in" -> "India"; "i2" -> "India (i2)"; "sg" -> "Singapore"
  "de" -> "Europe"; "us" -> "United States"; "ru" -> "Russia"; "tw" -> "Taiwan"; else -> code
}

/**
 * Setup flow: scan, then sign in and bind, fetch the token, or import a token.
 * Back goes to the scan step if no operation runs.
 * @param onDone Called after a token is saved and the user continues.
 * @param onPreview Called to open the dashboard preview.
 */
@Composable
fun SetupScreen(onDone: () -> Unit, onPreview: () -> Unit = {}, vm: SetupViewModel = viewModel(extras = appViewModelExtras())) {
  BackHandler(enabled = vm.step != Step.Scan && !vm.busy) { vm.backToScan() }
  Box(Modifier.fillMaxSize().safeDrawingPadding().imePadding(), contentAlignment = Alignment.TopCenter) {
  Column(Modifier.widthIn(max = 680.dp).fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
    when (val s = vm.step) {
      Step.Scan -> ScanStep(vm, onPreview)
      is Step.SignIn -> SignInStep(vm, s.charger)
      is Step.Import -> ImportStep(vm, s.charger, onDone)
      is Step.Binding -> BindingStep(vm, onDone)
    }
  }
  }
  vm.prompt?.let { PromptDialog(it, vm::answer) }
}

@Composable
private fun Title(text: String, sub: String) {
  Text(text, style = MaterialTheme.typography.headlineMedium)
  Text(sub, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun ScanStep(vm: SetupViewModel, onPreview: () -> Unit) {
  val context = LocalContext.current
  var granted by remember {
    mutableStateOf(BLE_PERMISSIONS.all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED })
  }
  val launcher =
    rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }
  LaunchedEffect(granted) { if (granted) vm.startScan() }

  Text("CUKTECH APP (UNOFFICIAL)", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
  Title("A clearer view of\nyour charging.", "Live output, charging controls and diagnostics for your AD1204U. After setup, it works locally over Bluetooth.")
  OutlinedButton(onClick = onPreview) { Text("Explore the dashboard") }
  Text("Connect your charger", style = MaterialTheme.typography.titleLarge)
  Text("Keep it on power and near this phone.", style = MaterialTheme.typography.bodyMedium)
  if (!granted) {
    Text("Bluetooth permission is needed to find the charger.")
    Button(onClick = { launcher.launch(BLE_PERMISSIONS) }) { Text("Grant permission") }
    return
  }
  vm.scanError?.let {
    Text(it, color = MaterialTheme.colorScheme.error)
    OutlinedButton(onClick = vm::startScan) { Text("Scan again") }
  }
  if (vm.scanError == null) LinearProgressIndicator(Modifier.fillMaxWidth())
  LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
    items(vm.chargers.values.sortedByDescending { it.rssi }, key = { it.address }) { c ->
      ElevatedCard(Modifier.fillMaxWidth().clickable { vm.pick(c) }) {
        ListItem(
          headlineContent = { Text(c.name ?: "CUKTECH charger") },
          supportingContent = { Text(c.address, fontFamily = FontFamily.Monospace) },
          trailingContent = {
            Column {
              Text("${c.rssi} dBm", style = MaterialTheme.typography.labelMedium)
              Text(
                if (c.registered) "bound" else "unbound",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
              )
            }
          },
        )
      }
    }
  }
}

@Composable
private fun SignInStep(vm: SetupViewModel, charger: ChargerAdvert) {
  var username by remember { mutableStateOf("") }
  var password by remember { mutableStateOf("") }
  var showPassword by remember { mutableStateOf(false) }
  var region by remember { mutableStateOf("cn") }
  var keepInAccount by remember { mutableStateOf(false) }
  Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    Title(
      "Sign in to Xiaomi",
      if (charger.registered)
        "${charger.address} is already bound. Sign in with its linked account, and the app reads its token. The app never saves your password. The cloud session is encrypted on this phone for firmware checks."
      else
        "Used one time to bind ${charger.address}. The app never saves your password. The cloud session is encrypted on this phone for firmware checks. After the bind, the app removes the charger from the account, unless you keep it.",
    )
    OutlinedTextField(username, { username = it }, label = { Text("Xiaomi account (email, phone or ID)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
      password,
      { password = it },
      label = { Text("Password") },
      singleLine = true,
      visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
      keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
      trailingIcon = { TextButton(onClick = { showPassword = !showPassword }) { Text(if (showPassword) "Hide" else "Show") } },
      modifier = Modifier.fillMaxWidth(),
    )
    Text("Server region", style = MaterialTheme.typography.labelLarge)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
      REGIONS.forEach { r -> FilterChip(selected = region == r, onClick = { region = r }, label = { Text(regionName(r)) }) }
    }
    Text("Select the Xiaomi Home server that shows the charger. A China-model charger often uses China, also when the phone is in a different region.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (!charger.registered) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
          Text("Keep charger in my Xiaomi account", style = MaterialTheme.typography.bodyLarge)
          Text("The charger stays visible in Mi Home. The app works in both cases.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(keepInAccount, { keepInAccount = it }, enabled = !vm.busy)
      }
    }
    vm.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    if (vm.busy) {
      LinearProgressIndicator(Modifier.fillMaxWidth())
      vm.loginStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
      OutlinedButton(onClick = vm::backToScan, enabled = !vm.busy) { Text("Back") }
      Button(
        onClick = {
          if (charger.registered) vm.signInAndFetch(charger, username.trim(), password, region)
          else vm.signInAndBind(charger, username.trim(), password, region, keepInAccount)
          password = ""
        },
        enabled = !vm.busy && username.isNotBlank() && password.isNotEmpty(),
      ) {
        Text("Sign in")
      }
    }
    if (charger.registered) {
      TextButton(onClick = { vm.showImport(charger) }, enabled = !vm.busy) { Text("Paste a token instead") }
    }
  }
}

@Composable
private fun ImportStep(vm: SetupViewModel, charger: ChargerAdvert, onDone: () -> Unit) {
  var token by remember { mutableStateOf("") }
  var error by remember { mutableStateOf<String?>(null) }
  Title(
    "Import token",
    "${charger.address} is already bound to a Xiaomi account. Paste its 24-hex-character token. The app stores it encrypted on this phone only.",
  )
  OutlinedTextField(
    token,
    { token = it },
    label = { Text("Token (24 hex characters)") },
    singleLine = true,
    visualTransformation = PasswordVisualTransformation(),
    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
    isError = error != null,
    supportingText = error?.let { { Text(it) } },
    modifier = Modifier.fillMaxWidth(),
  )
  Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
    OutlinedButton(onClick = vm::backToScan) { Text("Back") }
    Button(
      onClick = {
        error = vm.importToken(charger, token)
        if (error == null) {
          token = ""
          onDone()
        }
      }
    ) {
      Text("Save")
    }
  }
}

@Composable
private fun BindingStep(vm: SetupViewModel, onDone: () -> Unit) {
  Title("Setting up", "Keep the app open and the charger close.")
  if (vm.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
  Column {
    vm.progress.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
  }
  vm.error?.let {
    Text("Bind failed: $it", color = MaterialTheme.colorScheme.error)
    OutlinedButton(onClick = vm::backToScan) { Text("Back") }
  }
  if (vm.finished) {
    vm.warning?.let { Text(it, color = MaterialTheme.colorScheme.tertiary) }
    Button(onClick = onDone) { Text("Open controller") }
  }
}

/**
 * Dialog for a sign-in or bind [Prompt]. It cannot be dismissed by a tap outside.
 * @param answer Called with the prompt and the answer: the typed code, `true`, or null for cancel.
 */
@Composable
fun PromptDialog(p: Prompt, answer: (Prompt, Any?) -> Unit) {
  var code by remember(p) { mutableStateOf("") }
  val uri = LocalUriHandler.current
  val (title, text) =
    when (p) {
      is Prompt.Captcha -> "Captcha" to "Type the characters shown."
      is Prompt.EmailCode -> "Verification code" to "Enter the code Xiaomi sent to your ${if (p.sms) "phone by SMS" else "email"}."
      is Prompt.Browser -> "Confirm in browser" to "Xiaomi wants you to confirm this sign-in in a browser. Open the link, complete the step there, then tap Done."
      is Prompt.Consent ->
        "Bind charger?" to
          if (p.keepInAccount) "Bind this charger to your Xiaomi account? It stays in the account. The charger also works offline."
          else "Bind this charger to your Xiaomi account? The app then removes it from the account. The charger continues to work offline."
    }
  val cancel = { answer(p, null) }
  AlertDialog(
    onDismissRequest = {},
    title = { Text(title) },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(text)
        if (p is Prompt.Captcha) {
          p.image?.let { Image(it, contentDescription = "Captcha image", modifier = Modifier.fillMaxWidth().height(80.dp)) }
            ?: Text("Cannot show the captcha image.", color = MaterialTheme.colorScheme.error)
        }
        if (p is Prompt.Captcha || p is Prompt.EmailCode) {
          // no autocorrect/auto-caps: the keyboard silently rewrites captcha letters otherwise
          OutlinedTextField(
            code, { code = it }, singleLine = true, label = { Text("Code") }, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, autoCorrectEnabled = false, capitalization = KeyboardCapitalization.None),
          )
        }
        if (p is Prompt.Browser) OutlinedButton(onClick = { uri.openUri(p.url) }) { Text("Open link") }
      }
    },
    confirmButton = {
      when (p) {
        is Prompt.Captcha,
        is Prompt.EmailCode -> TextButton(onClick = { answer(p, code.trim()) }, enabled = code.isNotBlank()) { Text("OK") }
        is Prompt.Browser -> TextButton(onClick = { answer(p, true) }) { Text("Done") }
        is Prompt.Consent -> TextButton(onClick = { answer(p, true) }) { Text("Bind") }
      }
    },
    dismissButton = { TextButton(onClick = cancel) { Text("Cancel") } },
  )
}
