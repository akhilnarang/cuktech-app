package dev.akhilnarang.cuktech

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

/** Sign-in and charger setup screen. */
@Serializable data object Setup : NavKey

/** Live dashboard and controls for the saved charger. */
@Serializable data object Controller : NavKey

/** Firmware update screen. */
@Serializable data object Firmware : NavKey

/** Dashboard with demo data. It needs no charger. */
@Serializable data object DashboardPreview : NavKey
