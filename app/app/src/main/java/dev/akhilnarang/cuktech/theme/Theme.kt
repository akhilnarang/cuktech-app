package dev.akhilnarang.cuktech.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
  primary = Color(0xFF6EE7C7), onPrimary = Color(0xFF00382C),
  primaryContainer = Color(0xFF164D40), onPrimaryContainer = Color(0xFFB3F9E1),
  secondary = Color(0xFF9CCBFA), secondaryContainer = Color(0xFF223F5C), onSecondaryContainer = Color(0xFFD4E7FF),
  tertiary = Color(0xFFE5BD7A), background = Color(0xFF0C141A), onBackground = Color(0xFFE7EEF2),
  surface = Color(0xFF0C141A), onSurface = Color(0xFFE7EEF2),
  surfaceContainerLowest = Color(0xFF080F14), surfaceContainerLow = Color(0xFF121E26),
  surfaceContainer = Color(0xFF17242D), surfaceContainerHigh = Color(0xFF1E2D37), surfaceContainerHighest = Color(0xFF273740),
  onSurfaceVariant = Color(0xFFA9BBC5), outline = Color(0xFF7A8F9A), outlineVariant = Color(0xFF30434D),
)

private val LightColorScheme =
  lightColorScheme(
    primary = Color(0xFF006B54), onPrimary = Color.White,
    primaryContainer = Color(0xFFCAF5E7), onPrimaryContainer = Color(0xFF00382C),
    secondary = Color(0xFF315E87), secondaryContainer = Color(0xFFD8E9FA), onSecondaryContainer = Color(0xFF163A5A),
    tertiary = Color(0xFF805614), background = Color(0xFFF3F7F8), onBackground = Color(0xFF132731),
    surface = Color(0xFFF3F7F8), onSurface = Color(0xFF132731),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFEDF3F5), surfaceContainer = Color(0xFFE5EEF1),
    surfaceContainerHigh = Color(0xFFDDE8EC), surfaceContainerHighest = Color(0xFFD4E2E7),
    onSurfaceVariant = Color(0xFF4C6572), outline = Color(0xFF70858F), outlineVariant = Color(0xFFCAD9DF),

    /* Other default colors to override
    background = Color(0xFFFFFBFE),
    surface = Color(0xFFFFFBFE),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onTertiary = Color.White,
    onBackground = Color(0xFF1C1B1F),
    onSurface = Color(0xFF1C1B1F),
    */
  )

/**
 * App Material 3 theme with the app colors and [Typography].
 * @param dynamicColor True to use the wallpaper colors on Android 12 and later. Default false.
 */
@Composable
fun CUKTECHLocalTheme(
  darkTheme: Boolean = isSystemInDarkTheme(),
  dynamicColor: Boolean = false,
  content: @Composable () -> Unit,
) {
  val colorScheme =
    when {
      dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
        val context = LocalContext.current
        if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
      }
      darkTheme -> DarkColorScheme
      else -> LightColorScheme
    }

  MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
}
