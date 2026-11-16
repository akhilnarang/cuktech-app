package dev.akhilnarang.cuktech.ui.controller

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.akhilnarang.cuktech.theme.NumberStyle
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.math.abs
import kotlin.math.ceil

/** Formats [value] with [decimals] decimals and [suffix] (`Locale.US`). Shows an em dash for null or not finite. */
internal fun number(value: Double?, suffix: String = "", decimals: Int = 1): String =
    if (value == null || !value.isFinite()) "—" else "%.${decimals}f".format(Locale.US, value) + suffix
/** Formats a duration as `Ns`, `Nm Ns` or `Nh Nm`. */
internal fun duration(ms: Long): String = if (ms < 60_000) "${ms / 1000}s" else if (ms < 3_600_000) "${ms / 60_000}m ${ms / 1000 % 60}s" else "${ms / 3_600_000}h ${ms / 60_000 % 60}m"
/** Formats epoch ms as local `HH:mm:ss`. */
internal fun time(epoch: Long): String = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(epoch))

/** Rounded card with the standard padding and spacing. */
@Composable
internal fun Panel(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Card(modifier.fillMaxWidth(), shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.65f))) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp), content = content)
    }
}

/** Small upper-case label above a section. */
@Composable
internal fun Eyebrow(text: String, modifier: Modifier = Modifier) {
    Text(text.uppercase(Locale.US), modifier, style = MaterialTheme.typography.labelMedium,
        letterSpacing = 1.4.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** Secondary small text. Text after [maxLines] is cut with an ellipsis. */
@Composable
internal fun Caption(text: String, modifier: Modifier = Modifier, maxLines: Int = Int.MAX_VALUE) {
    Text(text, modifier, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = maxLines, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
}

/** Label and large tabular value. */
@Composable
internal fun Metric(label: String, value: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurface) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Caption(label)
        Text(value, style = MaterialTheme.typography.titleLarge.merge(NumberStyle), color = color)
    }
}

/** Small tinted label. */
@Composable
internal fun Pill(text: String, color: Color = MaterialTheme.colorScheme.primary) {
    Surface(color = color.copy(alpha = 0.12f), contentColor = color, shape = RoundedCornerShape(8.dp)) {
        Text(text, Modifier.padding(horizontal = 9.dp, vertical = 5.dp), style = MaterialTheme.typography.labelMedium)
    }
}

/** Placeholder with an icon, a title and a text for an empty chart or list. */
@Composable
internal fun EmptyState(title: String, text: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 26.dp), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(DashboardIcons.History, null, Modifier.size(32.dp), tint = MaterialTheme.colorScheme.outline)
        Text(title, style = MaterialTheme.typography.titleMedium)
        Caption(text)
    }
}

/**
 * One chart point.
 * @property x Position on the time axis, usually monotonic ms.
 * @property value Y value, or null for a gap.
 * @property segment Points in different segments are not joined.
 * @property epochMs Wall-clock time for labels, in ms since the epoch. 0 if not known.
 */
data class ChartValue(val x: Long, val value: Double?, val segment: Int = 0, val epochMs: Long = 0)
/** A named line with its color and points, sorted by x. */
data class ChartSeries(val name: String, val color: Color, val values: List<ChartValue>)

/**
 * Time chart with gaps, optional touch to select a sample, and a summary for screen readers.
 * Each series is reduced to about 240 buckets. Each bucket keeps its first, last, minimum, maximum, gap and segment-change points.
 * @param height Chart height, in dp.
 * @param unit Unit label. For `W` the minimum top is 10, else 50.
 * @param interactive True to let the user touch or drag to select a sample.
 * @param dots True to draw a dot at each point.
 */
@Composable
fun TelemetryChart(series: List<ChartSeries>, modifier: Modifier = Modifier, height: Int = 180, unit: String = "W", interactive: Boolean = true, dots: Boolean = false) {
    val all = series.flatMap { it.values }
    val start = all.minOfOrNull { it.x } ?: 0L
    val end = maxOf(start + 1, all.maxOfOrNull { it.x } ?: 1)
    val maximum = all.mapNotNull { it.value }.maxOrNull() ?: 0.0
    val top = maxOf(if (unit == "W") 10.0 else 50.0, ceil(maximum / 10) * 10)
    val grid = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.55f)
    var selected by remember(series.map { it.name }) { mutableStateOf<Long?>(null) }
    var width by remember { mutableIntStateOf(1) }
    val choose: (Float) -> Unit = { selected = (start + (end - start) * (it / width).coerceIn(0f, 1f)).toLong() }
    Column(modifier, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Caption("${top.toInt()} $unit")
            if (interactive) Caption(if (selected == null) "Touch to see values" else "Received sample")
        }
        Canvas(Modifier.fillMaxWidth().height(height.dp).onSizeChanged { width = it.width }
            .semantics { contentDescription = "${series.joinToString { it.name }} chart. Highest displayed value ${number(maximum)} $unit. Missing data shows as gaps." }
            .pointerInput(start, end, interactive) { if (interactive) detectTapGestures { choose(it.x) } }
            .pointerInput(start, end, interactive) { if (interactive) detectHorizontalDragGestures(onDragStart = { choose(it.x) }) { change, _ -> change.consume(); choose(change.position.x) } }) {
            repeat(4) { i -> val y = size.height * i / 3; drawLine(grid, Offset(0f, y), Offset(size.width, y), 1.dp.toPx()) }
            for (s in series) {
                val path = Path(); var previous: ChartValue? = null
                // Bound drawing cost without discarding discontinuities or per-bucket extrema.
                val step = maxOf(1, s.values.size / 240)
                val values = if (step == 1) s.values else s.values.chunked(step).flatMap { group ->
                    (listOf(group.first(), group.last()) + listOfNotNull(group.minByOrNull { it.value ?: Double.POSITIVE_INFINITY }, group.maxByOrNull { it.value ?: Double.NEGATIVE_INFINITY }) + group.filter { it.value == null } + group.zipWithNext().filter { it.first.segment != it.second.segment }.flatMap { listOf(it.first, it.second) }).distinctBy { it.x }.sortedBy { it.x }
                }
                for (p in values) {
                    val value = p.value
                    if (value == null) { previous = null; continue }
                    val x = ((p.x - start).toDouble() / (end - start) * size.width).toFloat()
                    val y = (size.height * (1 - value.coerceIn(0.0, top) / top)).toFloat()
                    if (previous == null || previous.segment != p.segment) path.moveTo(x, y) else path.lineTo(x, y)
                    if (dots || values.size == 1) drawCircle(s.color, 3.dp.toPx(), Offset(x, y))
                    previous = p
                }
                drawPath(path, s.color, style = Stroke(2.5.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round))
            }
            selected?.let { val x = ((it.coerceIn(start, end) - start).toDouble() / (end - start) * size.width).toFloat(); drawLine(grid, Offset(x, 0f), Offset(x, size.height), 1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(8f, 8f))) }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Caption(all.minByOrNull { it.x }?.epochMs?.takeIf { it > 0 }?.let(::time) ?: "0 $unit")
            Caption(all.maxByOrNull { it.x }?.epochMs?.takeIf { it > 0 }?.let(::time) ?: "Now")
        }
        selected?.let { x ->
            val labels = series.mapNotNull { s -> s.values.minByOrNull { abs(it.x - x) }?.let { "${s.name} ${number(it.value, " $unit")} at ${time(it.epochMs)}" } }
            Caption(labels.joinToString(" · "))
        }
    }
}

/** Line icons of the dashboard, drawn as 24 dp vectors. */
object DashboardIcons {
    private fun icon(name: String, block: androidx.compose.ui.graphics.vector.PathBuilder.() -> Unit): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = null, stroke = SolidColor(Color.Black), strokeLineWidth = 1.8f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round, pathBuilder = block)
        }.build()
    val Overview = icon("Overview") { moveTo(3f, 3f); lineTo(10f, 3f); lineTo(10f, 10f); lineTo(3f, 10f); close(); moveTo(14f, 3f); lineTo(21f, 3f); lineTo(21f, 10f); lineTo(14f, 10f); close(); moveTo(3f, 14f); lineTo(10f, 14f); lineTo(10f, 21f); lineTo(3f, 21f); close(); moveTo(14f, 14f); lineTo(21f, 14f); lineTo(21f, 21f); lineTo(14f, 21f); close() }
    val History = icon("History") { moveTo(3f, 4f); lineTo(3f, 21f); lineTo(21f, 21f); moveTo(6f, 15f); lineTo(10f, 10f); lineTo(14f, 13f); lineTo(20f, 5f) }
    val Controls = icon("Controls") { moveTo(3f, 6f); lineTo(7f, 6f); moveTo(13f, 6f); lineTo(21f, 6f); moveTo(10f, 3f); lineTo(10f, 9f); moveTo(3f, 12f); lineTo(13f, 12f); moveTo(19f, 12f); lineTo(21f, 12f); moveTo(16f, 9f); lineTo(16f, 15f); moveTo(3f, 18f); lineTo(5f, 18f); moveTo(11f, 18f); lineTo(21f, 18f); moveTo(8f, 15f); lineTo(8f, 21f) }
    val Diagnostics = icon("Diagnostics") { moveTo(2f, 12f); lineTo(6f, 12f); lineTo(9f, 4f); lineTo(14f, 20f); lineTo(17f, 12f); lineTo(22f, 12f) }
    val Bolt = icon("Power") { moveTo(14f, 2f); lineTo(5f, 14f); lineTo(11f, 14f); lineTo(10f, 22f); lineTo(20f, 9f); lineTo(13f, 9f); close() }
    val Refresh = icon("Refresh") { moveTo(20f, 7f); lineTo(20f, 3f); moveTo(20f, 7f); lineTo(16f, 7f); moveTo(20f, 7f); curveTo(16f, 0f, 4f, 3f, 4f, 12f); moveTo(4f, 17f); lineTo(4f, 21f); moveTo(4f, 17f); lineTo(8f, 17f); moveTo(4f, 17f); curveTo(8f, 24f, 20f, 21f, 20f, 12f) }
}
