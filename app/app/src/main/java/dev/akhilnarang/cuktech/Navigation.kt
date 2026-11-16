package dev.akhilnarang.cuktech

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import dev.akhilnarang.cuktech.proto.SecureStore
import dev.akhilnarang.cuktech.ui.controller.ControllerScreen
import dev.akhilnarang.cuktech.ui.setup.SetupScreen
import dev.akhilnarang.cuktech.ui.firmware.FirmwareScreen
import dev.akhilnarang.cuktech.ui.controller.DemoScreen

/**
 * Root navigation. It starts at [Controller] if a charger token is saved, else at [Setup].
 * Setup and forget clear the back stack.
 */
@Composable
fun MainNavigation() {
  val context = LocalContext.current
  val start: NavKey = remember { if (SecureStore(context).hasCredentials()) Controller else Setup }
  val backStack = rememberNavBackStack(start)
  fun replaceWith(key: NavKey) {
    backStack.clear()
    backStack.add(key)
  }

  NavDisplay(
    backStack = backStack,
    entryDecorators = listOf(
      rememberSaveableStateHolderNavEntryDecorator(),
      rememberViewModelStoreNavEntryDecorator(),
    ),
    onBack = { backStack.removeLastOrNull() },
    entryProvider =
      entryProvider {
        entry<Setup> { SetupScreen(onDone = { replaceWith(Controller) }, onPreview = { backStack.add(DashboardPreview) }) }
        entry<Controller> { ControllerScreen(onForgotten = { replaceWith(Setup) }, onFirmware = { backStack.add(Firmware) }) }
        entry<Firmware> { FirmwareScreen(onBack = { backStack.removeLastOrNull() }) }
        entry<DashboardPreview> { DemoScreen(onBack = { backStack.removeLastOrNull() }) }
      },
  )
}
