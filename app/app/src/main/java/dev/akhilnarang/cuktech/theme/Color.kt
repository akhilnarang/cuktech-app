package dev.akhilnarang.cuktech.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable

/**
 * Color of a port. Cards, charts and controls use the same color for the same port.
 * @param port Port index: 0 = C1, 1 = C2, 2 = C3, 3 = A.
 */
@Composable
fun portColor(port: Int): Color = if (isSystemInDarkTheme())
    listOf(Color(0xFF6EE7C7), Color(0xFF8EBFFF), Color(0xFFFFC777), Color(0xFFDAABFF))[port]
else listOf(Color(0xFF00775D), Color(0xFF285FBB), Color(0xFF946000), Color(0xFF8543AA))[port]
