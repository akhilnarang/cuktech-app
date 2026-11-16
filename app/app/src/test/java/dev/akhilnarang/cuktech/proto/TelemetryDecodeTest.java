package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;

public class TelemetryDecodeTest {
    @Test public void ppsDependsOnPdWithoutChangingOtherPortsOrReservedBits() {
        assertEquals(3L, ProtocolControls.update(0, 1, true));
        assertEquals(0x300L, ProtocolControls.update(0, 9, true));
        assertEquals(0xf3000000L, ProtocolControls.update(0xf3000003L, 0, false));
        assertEquals(0xf3000003L, ProtocolControls.update(0xf3000303L, 8, false));
    }
    @Test public void scAlternateSevenPointFiveWattAllocationPreservesCodeAndNamespace() {
        // Original 0073 helper 0x4092e0: a0 -> 75 deciwatts. This remains a
        // distinct allocation code from 10 despite their equal watt labels.
        PortTelemetry.Port port = PortTelemetry.decode(2, 0x320aa001L);
        assertEquals("max 7.5 W", port.cap);
        assertEquals(0xa0, port.capCode);
        assertEquals("max 7.5 W", PortTelemetry.capDescription(3, 0xa0));
        assertEquals("max 7.5 W", PortTelemetry.capDescription(2, 0x10));
        assertEquals("Unmapped cap", PortTelemetry.capDescription(0, 0xa0));
        assertEquals("Unmapped cap", PortTelemetry.capDescription(3, 0xa1));
    }
    @Test public void protocolHalvesMatchPortsAndKeepRawDetails() {
        long value = 0x07500837L;
        assertEquals("PD Fixed · cap 80 W", PortProtocol.decode(0, value).label);
        assertEquals("07·50", PortProtocol.decode(0, value).raw);
        assertEquals("PD PPS · cap 55 W", PortProtocol.decode(1, value).label);
        assertEquals("08·37", PortProtocol.decode(1, value).raw);
        assertEquals("PD", PortProtocol.decode(2, value).label);
        assertEquals("PPS", PortProtocol.decode(3, value).label);
    }
    @Test public void tentativeAndConflictingModesKeepVendorEvidence() {
        // Signed official plugin v60 displays 09 as PPS. The C1/C2 miPPS alias
        // stays tentative and its detail must not become an invented watt cap.
        assertEquals("miPPS (likely)", PortProtocol.decode(0, 0x09780000L).label);
        assertEquals("PPS", PortProtocol.decode(0, 0x09780000L).vendorLabel);
        assertEquals("PPS", PortProtocol.decode(2, 0x09780000L).label);
        assertEquals("5V", PortProtocol.decode(0, 0x010f0000L).label);
        assertEquals("01·0f", PortProtocol.decode(0, 0x010f0000L).raw);
        assertEquals("5V", PortProtocol.decode(0, 0x01100000L).label);
        assertEquals("5V", PortProtocol.decode(1, 0x0210L).label);
        assertEquals("5V / QC (unresolved)", PortProtocol.decode(3, 0x0210L).label);
        assertEquals("5V", PortProtocol.decode(3, 0x0210L).vendorLabel);
        assertEquals("UFCS", PortProtocol.decode(1, 0x0a78L).label);
        assertEquals("Protocol not identified", PortProtocol.decode(0, 0x0bff0000L).label);
        assertNull(PortProtocol.decode(0, 0x0bff0000L).vendorLabel);
        assertEquals("Protocol not reported", PortProtocol.decode(0, 0).label);
        // Both halves are non-zero. The C1 half keeps its own raw bytes.
        assertEquals("09·78", PortProtocol.decode(0, 0x09780a78L).raw);
    }

    @Test public void displayedAllocationDoesNotCrossControllerNamespaces() {
        assertEquals("max 120 W", PortTelemetry.decode(0, 0x32010b01L).cap);
        assertEquals("max 22.5 W", PortTelemetry.decode(2, 0x32016001L).cap);
        assertEquals("cap 0x60", PortTelemetry.decode(0, 0x32016001L).cap);
        assertEquals("cap 0x0b", PortTelemetry.decode(2, 0x32010b01L).cap);
        assertEquals("idle", PortTelemetry.decode(2, 0x00000b00L).cap);
    }

    @Test public void nonActivityStatusBitsDoNotMarkOutputActive() {
        assertFalse(PortTelemetry.decode(2, 0x00008080L).inUse);
        assertFalse(PortTelemetry.decode(0, 0x00000b04L).inUse);
        assertTrue(PortTelemetry.decode(0, 0x00000b11L).inUse);
        assertTrue(PortTelemetry.decode(2, 0x00008081L).inUse);
        assertEquals(0x00008080L, PortTelemetry.decode(2, 0x00008080L).raw);
    }

    @Test public void mixedLegacyProtocolWordsUseBothHalvesWithoutTreatingDetailsAsWatts() {
        // Independent fixtures from the official renderer's 3/4/5/6 mapping;
        // the arbitrary detail bytes must survive without protocol-cap guesses.
        assertEquals("QC", PortProtocol.decode(0, 0x033c040fL).label);
        assertEquals("03·3c", PortProtocol.decode(0, 0x033c040fL).raw);
        assertEquals("AFC", PortProtocol.decode(1, 0x033c040fL).label);
        assertEquals("FCP", PortProtocol.decode(2, 0x05ff0601L).label);
        assertEquals("SCP", PortProtocol.decode(3, 0x05ff0601L).label);
        assertEquals("06·01", PortProtocol.decode(3, 0x05ff0601L).raw);
    }
    @Test public void temperatureDecoderRequiresMappedFrame() {
        byte[] frame = temperature(45);
        assertEquals(45, VendorStatus.decodeTemperature(frame));
        for (int offset : new int[]{0, 3, 4, 5, 6, 17}) {
            byte[] bad = frame.clone(); bad[offset] ^= 1;
            assertThrows(IllegalArgumentException.class, () -> VendorStatus.decodeTemperature(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> VendorStatus.decodeTemperature(new byte[19]));
        assertThrows(IllegalArgumentException.class, () -> VendorStatus.decodeTemperature(temperature(0)));
        assertThrows(IllegalArgumentException.class, () -> VendorStatus.decodeTemperature(temperature(255)));
    }
    static byte[] temperature(int raw) {
        byte[] frame = new byte[18];
        byte[] prefix = {(byte)0xfe, (byte)0xdc, (byte)0xba, 1, (byte)0xf1, 2, 10};
        System.arraycopy(prefix, 0, frame, 0, prefix.length);
        frame[7] = (byte)raw; frame[17] = (byte)0xef;
        return frame;
    }

    @Test public void statusExposesBothSensorsAndKeepsUnknownUnitsRaw() {
        byte[] frame = temperature(45);
        frame[13] = 80;
        frame[9] = 0x14; frame[10] = 5; // 1300 mV proxy, not 1300 V mains.
        frame[11] = 2; frame[12] = 1;
        VendorStatus.Reading reading = VendorStatus.decodeStatus(frame, 2);
        assertEquals("45 °C (experimental)", reading.fields.get("NTC2 · shell input"));
        assertEquals("80 °C (experimental)", reading.fields.get("NTC1 · protection input"));
        assertEquals("1300 mV (not mains volts)", reading.fields.get("AC sense ADC proxy"));
        assertEquals("22 V", reading.fields.get("Power rail state"));
        assertEquals("Set", reading.fields.get("PFC high state"));
        frame[7] = 0;
        assertTrue(VendorStatus.decodeStatus(frame, 2).fields.get("NTC2 · shell input").startsWith("Unavailable"));
    }

    @Test public void protocolMaskPreservesReservedAndUnsignedBits() {
        // Hand-computed: bit 25 is 0x02 in the top byte 0xf3, so clearing it gives 0xf1.
        assertEquals(0xf1ff8f8fL, ProtocolControls.update(0xf3ff8f8fL, 25, false));
        // Bit 8 is clear in 0x8e. Setting it gives 0x8f. The top byte stays unsigned.
        assertEquals(0xf3ff8f8fL, ProtocolControls.update(0xf3ff8e8fL, 8, true));
        assertThrows(IllegalArgumentException.class, () -> ProtocolControls.update(0xf3ff8f8fL, 31, true));
        assertThrows(IllegalArgumentException.class, () -> ProtocolControls.update(0xf3ff8f8fL, 18, false));
    }

    @Test public void holidayBuilderCannotConstructAdjacentFactoryCommands() {
        assertArrayEquals(new byte[]{(byte)0xfe,(byte)0xdc,(byte)0xba,1,(byte)0xf1,0,1,9,1}, VendorStatus.holidayRequest(true));
        assertThrows(IllegalArgumentException.class, () -> VendorStatus.statusRequest(9));
        assertThrows(IllegalArgumentException.class, () -> VendorStatus.statusRequest(4));
        byte[] reply = {(byte)0xfe,(byte)0xdc,(byte)0xba,1,(byte)0xf1,9,1,1,(byte)0xef};
        assertEquals(Boolean.TRUE, VendorStatus.decodeStatus(reply,9).holidayArtwork);
    }
}
