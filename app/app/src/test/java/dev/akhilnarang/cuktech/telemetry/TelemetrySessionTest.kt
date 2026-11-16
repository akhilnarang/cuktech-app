package dev.akhilnarang.cuktech.telemetry

import org.junit.Assert.*
import org.junit.Test

class TelemetrySessionTest {
    private fun ports(w: Double = 10.0): List<PortSample?> = listOf(PortSample(5.0, w / 5, true, 1, "PD Fixed")) + List(3) { PortSample(0.0, 0.0, false, 0, null) }
    @Test fun energyUsesTrapezoidsAndNoRepeatedPackets() {
        val session = TelemetrySession()
        assertTrue(session.record(0, 0, ports(10.0), List(4) { 0L }))
        assertFalse(session.record(500, 500, ports(20.0), List(4) { 0L }))
        session.record(1000, 1000, ports(20.0), List(4) { 1000L })
        assertEquals(15.0 / 3600, session.stats.energyWh, 1e-9)
        assertEquals(15.0, session.stats.averageW!!, 1e-9)
        assertEquals(20.0, session.stats.peakW, 1e-9)
        assertEquals(15.0 / 3600, session.stats.portEnergyWh[0], 1e-9)
    }
    @Test fun gapOfExactlyFreshWindowContinuesTheSegmentAndOneMillisecondMoreSplitsIt() {
        val s = TelemetrySession()
        s.record(0, 0, ports(), List(4) { 0L })
        s.record(5000, 5000, ports(), List(4) { 5000L })
        assertEquals(listOf(0, 0), s.points().map { it.segment })
        assertEquals(5000L, s.stats.coveredMs)
        s.record(10001, 10001, ports(), List(4) { 10001L })
        assertEquals(listOf(0, 0, 1), s.points().map { it.segment })
        assertEquals(5000L, s.stats.coveredMs)
    }
    @Test fun disconnectAndLongGapsNeverIntegrateMissingTime() {
        val s = TelemetrySession()
        s.record(0, 0, ports(), List(4) { 0L }); s.pause()
        s.record(3000, 3000, ports(), List(4) { 3000L })
        s.record(9000, 9000, ports(), List(4) { 9000L })
        assertEquals(0L, s.stats.coveredMs)
        assertEquals(3, s.points().map { it.segment }.distinct().size)
    }
    @Test fun missingPortsAreNotZeroAndHistoryIsBounded() {
        val s = TelemetrySession(2)
        for (n in 0..2) s.record(n * 1000L, n * 1000L, ports().toMutableList().also { it[3] = null }, List(4) { n * 1000L })
        assertEquals(2, s.points().size)
        assertNull(s.points().last().totalW)
        assertEquals(0L, s.stats.coveredMs)
        assertTrue(s.stats.portEnergyWh[0] > 0)
        s.clear(); assertTrue(s.points().isEmpty()); assertEquals(0.0, s.stats.energyWh, 0.0)
    }
    @Test fun staleAndInvalidValuesAreExcluded() {
        val s = TelemetrySession()
        assertFalse(s.record(6000, 6000, ports(), List(4) { 0L }))
        val invalid = ports().toMutableList().also { it[0] = PortSample(Double.NaN, 1.0, true, 1, null) }
        s.record(7000, 7000, invalid, List(4) { 7000L })
        assertNull(s.points().last().ports[0])
    }
    @Test fun csvHasFixedColumnsQuotesTextAndLeavesMissingPortsEmpty() {
        val s = TelemetrySession()
        val sample = ports().toMutableList().also { it[0] = it[0]!!.copy(protocol = "A, \"B\""); it[3] = null }
        s.record(0, 0, sample, List(4) { 0L })
        val lines = TelemetryCsv.encode(s.points()).lines().filter { it.isNotBlank() }
        // The header is the full column set. No identity column (MAC, token, DID) is present.
        assertEquals("sampled_at,elapsed_ms,segment,port,active,voltage_v,current_a,output_w,allocation_code,reported_protocol", lines[0])
        assertEquals(5, lines.size)
        assertTrue(lines[1].endsWith(",\"A, \"\"B\"\"\""))
        assertTrue(lines[4].endsWith(",\"A\",\"\",\"\",\"\",\"\",\"\",\"\""))
    }
    @Test fun sparseHistoryExpiresByTimeAndOutOfOrderSamplesAreRejected() {
        val s = TelemetrySession()
        s.record(1000, 1000, ports(), List(4) { 1000L })
        assertFalse(s.record(500, 500, ports(), List(4) { 500L }))
        s.record(3_602_000, 3_602_000, ports(), List(4) { 3_602_000L })
        assertEquals(1, s.points().size)
        assertEquals(0.0, s.stats.energyWh, 0.0)
    }
}
