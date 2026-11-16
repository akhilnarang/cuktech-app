package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;

/** Captured reply fixtures and receive-time semantics, without hardware. */
public class ThermalMonitoringTest {
    private static byte[] fromHex(String text) {
        byte[] result = new byte[text.length() / 2];
        for (int i = 0; i < result.length; i++) result[i] = (byte)Integer.parseInt(text.substring(2*i, 2*i+2), 16);
        return result;
    }
    private static byte[] capturedSensors() { return fromHex("fedcba01f1020a28242c07020129000000ef"); }

    @Test public void capturedSensorValuesAreSeparatedFromUnreportedThermalState() {
        VendorStatus.Reading reading = VendorStatus.decodeStatus(capturedSensors(), 2);
        VendorStatus.ThermalReading thermal = reading.thermal;
        assertEquals(Integer.valueOf(40), thermal.shellEstimateC);
        assertEquals(Integer.valueOf(41), thermal.protectionEstimateC);
        assertEquals(1836, thermal.acProxyMv);
        assertEquals("22 V", thermal.railText());
        assertEquals("High", thermal.pfcText());
        assertEquals("36 · 0x24", thermal.mcuText());
        assertEquals("36 (low byte; units unconfirmed)", reading.fields.get("MCU temperature candidate"));
        assertEquals("0x24", reading.fields.get("ADC diagnostic byte"));
        assertEquals("Clear", reading.fields.get("Default settings + unbound"));
        assertFalse(reading.fields.containsKey("Thermal stage"));
        assertFalse(reading.fields.containsKey("Protection state"));
    }

    @Test public void unsignedMcuByteAndUnknownControlValuesAreNotPromotedToMeasurements() {
        byte[] frame = capturedSensors();
        frame[7] = 0; frame[13] = (byte)255; frame[8] = (byte)255;
        frame[11] = 3; frame[12] = 2;
        VendorStatus.ThermalReading thermal = VendorStatus.decodeStatus(frame, 2).thermal;
        assertNull(thermal.shellEstimateC);
        assertNull(thermal.protectionEstimateC);
        assertEquals(0, thermal.shellRaw);
        assertEquals(255, thermal.protectionRaw);
        assertEquals("255 · 0xff", thermal.mcuText());
        assertEquals("Unknown · 0x03", thermal.railText());
        assertEquals("Unknown · 0x02", thermal.pfcText());
    }

    @Test public void otherRepliesDoNotCreateThermalSamples() {
        VendorStatus.Reading versions = VendorStatus.decodeStatus(fromHex("fedcba01f10173008d3b200104017f4a04017f4aef"), 1);
        VendorStatus.Reading controllers = VendorStatus.decodeStatus(fromHex("fedcba01f1060a04076060071b083c0000ef"), 6);
        assertNull(versions.thermal);
        assertNull(controllers.thermal);
        assertEquals("0x0073", versions.fields.get("Firmware revision"));
        assertEquals("0x3b8d", versions.fields.get("Boot-record image CRC"));
        assertEquals("0x0120", versions.fields.get("SC2021 software version"));
        assertEquals("0x0104 / 0x4a7f", versions.fields.get("C2 version words"));
        assertEquals("max 55 W · 0x04", controllers.fields.get("C1 allocation"));
        assertEquals("max 70 W · 0x07", controllers.fields.get("C2 allocation"));
        assertEquals("max 22.5 W · 0x60", controllers.fields.get("C3 allocation"));
        assertEquals("PD PPS · cap 60 W · 08·3c", controllers.fields.get("C2 native protocol"));
        // A version reply has no generic length marker, so it must not decode as selector 2.
        assertThrows(IllegalArgumentException.class, () ->
                VendorStatus.decodeStatus(fromHex("fedcba01f10173008d3b200104017f4a04017f4aef"), 2));
    }

    @Test public void receiveAgeIsMonotonicAndIndependentForEachReply() {
        VendorStatus.Reading reading = VendorStatus.decodeStatus(capturedSensors(), 2);
        DiagnosticSnapshot older = new DiagnosticSnapshot(reading, "2026-10-14T15:25:29+05:30", 1000);
        DiagnosticSnapshot newer = new DiagnosticSnapshot(reading, "2026-10-14T15:26:29+05:30", 61000);
        assertEquals("1 min ago", older.ageText(61000));
        assertEquals("0 s ago", newer.ageText(61000));
        assertEquals("1 h ago", older.ageText(3601000));
        assertEquals("0 s ago", older.ageText(0));
        assertThrows(IllegalArgumentException.class, () -> new DiagnosticSnapshot(reading, "now", -1));
    }
}
