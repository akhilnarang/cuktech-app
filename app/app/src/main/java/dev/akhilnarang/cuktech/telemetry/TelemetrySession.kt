package dev.akhilnarang.cuktech.telemetry

import java.time.Instant
import java.util.Locale

/**
 * One reading of one port, stamped at receive time. In lists, null means missing or old data.
 * The app never puts an invented zero in place of missing data.
 *
 * @property voltageV Output voltage, in volts.
 * @property currentA Output current, in amperes.
 * @property active True if the port reports output.
 * @property capCode Power allocation code that the charger reports.
 * @property protocol Charging protocol that the charger reports, or null.
 */
data class PortSample(
    val voltageV: Double,
    val currentA: Double,
    val active: Boolean,
    val capCode: Int,
    val protocol: String?,
) {
/** Output power, in watts. 0 if the port is not active. */
    val powerW: Double get() = if (active) voltageV * currentA else 0.0
}

/**
 * One history point with the four ports C1, C2, C3 and A.
 *
 * @property elapsedMs Monotonic receive time, in ms.
 * @property epochMs Wall-clock receive time, in ms since the epoch.
 * @property segment Number of the continuous run. It increases after a gap.
 * @property ports Fresh samples. Null for a port with missing or old data.
 */
data class TelemetryPoint(
    val elapsedMs: Long,
    val epochMs: Long,
    val segment: Int,
    val ports: List<PortSample?>,
) {
/** Sum of [PortSample.powerW] of all ports, or null if a port has no fresh sample. */
    val totalW: Double? get() = if (ports.all { it != null }) ports.sumOf { it!!.powerW } else null
}

/**
 * Totals of the current session.
 *
 * @property energyWh Total energy of all ports, in Wh. Only intervals with all four ports fresh count.
 * @property peakW Highest total power, in W.
 * @property coveredMs Time that [energyWh] covers, in ms.
 * @property portEnergyWh Energy for each port, in Wh.
 * @property portPeakW Highest power for each port, in W.
 */
data class SessionStats(
    val energyWh: Double = 0.0,
    val peakW: Double = 0.0,
    val coveredMs: Long = 0,
    val portEnergyWh: List<Double> = List(4) { 0.0 },
    val portPeakW: List<Double> = List(4) { 0.0 },
) {
/** Mean total power over [coveredMs], in W, or null if no time is covered. */
    val averageW: Double? get() = if (coveredMs > 0) energyWh * 3_600_000 / coveredMs else null
}

/** A timestamped session log line. [epochMs] is in ms since the epoch. */
data class SessionEvent(val epochMs: Long, val text: String)

/**
 * History of telemetry points with a size limit, and the session statistics.
 * Energy uses the trapezoid rule only between fresh, continuous points.
 *
 * @param maxPoints Maximum number of points in the history. Minimum 2.
 * @throws IllegalArgumentException If [maxPoints] is less than 2.
 */
class TelemetrySession(private val maxPoints: Int = 3600) {
    init { require(maxPoints >= 2) }
    private val buffer = ArrayDeque<TelemetryPoint>()
    private var segment = 0
    private var previous: TelemetryPoint? = null
    private var lastReceiveTimes = List<Long?>(4) { null }
/** Statistics since the last [clear]. */
    var stats = SessionStats()
        private set

/** Returns a copy of the history, oldest first. */
    fun points(): List<TelemetryPoint> = buffer.toList()

/** Ends the current segment. The next point does not join the previous point. */
    fun pause() { if (previous != null) segment++; previous = null }

/** Deletes the history and the statistics, and starts a new segment. */
    fun clear() {
        buffer.clear(); previous = null; segment++; stats = SessionStats()
        lastReceiveTimes = List(4) { null }
    }

/**
 * Adds a point if new, fresh data is present, and updates [stats].
 *
 * A sample is fresh if it was received a maximum of [FRESH_MS] before [now], and its voltage and
 * current are finite and not negative. A gap longer than [FRESH_MS] starts a new segment.
 * The history keeps a maximum of `maxPoints` points and one hour. Not thread-safe.
 *
 * @param now Monotonic time, in ms. It must not be negative.
 * @param epoch Wall-clock time, in ms since the epoch.
 * @param ports Latest sample for each of the 4 ports, or null.
 * @param receivedAt Monotonic receive time for each of the 4 ports, or null.
 * @return True if a point was added. False if the data did not change, is old, or [now] did not increase.
 * @throws IllegalArgumentException If a list does not have 4 items or [now] is negative.
 */
    fun record(now: Long, epoch: Long, ports: List<PortSample?>, receivedAt: List<Long?>): Boolean {
        require(ports.size == 4 && receivedAt.size == 4 && now >= 0)
        if (receivedAt == lastReceiveTimes) return false
        val fresh = ports.mapIndexed { index, sample ->
            sample?.takeIf {
                val received = receivedAt[index]
                received != null && now - received in 0..FRESH_MS &&
                    it.voltageV.isFinite() && it.currentA.isFinite() && it.voltageV >= 0 && it.currentA >= 0
            }
        }
        if (fresh.all { it == null }) { pause(); return false }
        val old = previous
        if (old != null && now <= old.elapsedMs) return false
        if (old != null && now - old.elapsedMs > FRESH_MS) { segment++; previous = null }
        val point = TelemetryPoint(now, epoch, segment, fresh)
        val before = previous
        val dt = before?.let { now - it.elapsedMs } ?: 0
        val energies = stats.portEnergyWh.toMutableList()
        val peaks = stats.portPeakW.toMutableList()
        for (i in 0..3) {
            val a = before?.ports?.get(i); val b = fresh[i]
            if (dt > 0 && a != null && b != null) energies[i] += (a.powerW + b.powerW) * 0.5 * dt / 3_600_000
            if (b != null) peaks[i] = maxOf(peaks[i], b.powerW)
        }
        val total = point.totalW
        val oldTotal = before?.totalW
        val completeInterval = dt > 0 && total != null && oldTotal != null
        stats = SessionStats(
            energyWh = stats.energyWh + if (completeInterval) (total!! + oldTotal!!) * 0.5 * dt / 3_600_000 else 0.0,
            peakW = maxOf(stats.peakW, total ?: 0.0),
            coveredMs = stats.coveredMs + if (completeInterval) dt else 0,
            portEnergyWh = energies, portPeakW = peaks,
        )
        buffer.addLast(point)
        while (buffer.size > maxPoints || (buffer.size > 1 && now - buffer.first().elapsedMs > 3_600_000)) buffer.removeFirst()
        lastReceiveTimes = receivedAt.toList(); previous = point
        return true
    }

/** Holds [FRESH_MS]: the maximum age of a fresh sample, 5000 ms. */
    companion object { const val FRESH_MS = 5_000L }
}

/** CSV export of the telemetry history. */
object TelemetryCsv {
    private fun cell(value: String?) = "\"${(value ?: "").replace("\"", "\"\"")}\""
/**
 * Encodes [points] as CSV with a header row and one row for each port of each point.
 * All cells are quoted. Missing values are empty. Numbers use `Locale.US`.
 */
    fun encode(points: List<TelemetryPoint>): String = buildString {
        appendLine("sampled_at,elapsed_ms,segment,port,active,voltage_v,current_a,output_w,allocation_code,reported_protocol")
        for (point in points) for (i in 0..3) {
            val p = point.ports[i]
            val fields = listOf(Instant.ofEpochMilli(point.epochMs).toString(), point.elapsedMs.toString(), point.segment.toString(),
                listOf("C1", "C2", "C3", "A")[i], p?.active?.toString(), p?.voltageV?.let { "%.2f".format(Locale.US, it) },
                p?.currentA?.let { "%.2f".format(Locale.US, it) }, p?.powerW?.let { "%.3f".format(Locale.US, it) },
                p?.capCode?.let { "%02x".format(Locale.US, it) }, p?.protocol)
            appendLine(fields.joinToString(",") { cell(it) })
        }
    }
}
