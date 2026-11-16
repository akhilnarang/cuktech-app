package dev.akhilnarang.cuktech.ui

import android.app.Application
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.HasDefaultViewModelProviderFactory
import androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.Companion.APPLICATION_KEY
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewmodel.MutableCreationExtras
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner

/**
 * Returns the [CreationExtras] of the current ViewModel owner, with the [Application] added.
 *
 * The Navigation3 ViewModelStoreOwner of each entry gives default extras (for example saved state).
 * It does not give [APPLICATION_KEY]. Thus `viewModel()` for an `AndroidViewModel` throws
 * "CreationExtras must have an application by `APPLICATION_KEY`". Pass this value as the `extras`
 * argument. It keeps the defaults of the owner and adds the application.
 *
 * @throws IllegalStateException If no ViewModelStoreOwner is present.
 */
@Composable
fun appViewModelExtras(): CreationExtras {
  val owner = checkNotNull(LocalViewModelStoreOwner.current) { "No ViewModelStoreOwner was provided" }
  val base = (owner as? HasDefaultViewModelProviderFactory)?.defaultViewModelCreationExtras ?: CreationExtras.Empty
  val app = LocalContext.current.applicationContext as Application
  return MutableCreationExtras(base).apply { this[APPLICATION_KEY] = app }
}
