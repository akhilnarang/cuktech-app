package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;

public class ScreenTimeoutTest {
    @Test public void optionsMatchTheOriginalOneBasedSecondsTable() {
        // Raw firmware table 0x424f70: 2c01 5802 0807 0000 3c00.
        int[] secondsByWire = {300, 600, 1800, 0, 60};
        for (int wire = 1; wire <= 5; wire++) {
            ScreenTimeout option = ScreenTimeout.fromWireValue(wire);
            assertNotNull(option);
            assertEquals(secondsByWire[wire - 1], option.seconds);
        }
        assertEquals(5, ScreenTimeout.ONE_MINUTE.wireValue);
        assertEquals(4, ScreenTimeout.ALWAYS_ON.wireValue);
        for (int invalid : new int[]{-1, 0, 6, 255, 256}) assertNull(ScreenTimeout.fromWireValue(invalid));
    }

    @Test public void oneMinuteSendsWireValueFiveAndInvalidValuesSendNothing() {
        Charger charger = Charger.loggedIn(23);
        int writes = charger.writes.size();
        assertThrows(IllegalArgumentException.class, () -> charger.engine.setScreenSaveTime(0));
        assertThrows(IllegalArgumentException.class, () -> charger.engine.setScreenSaveTime(6));
        assertEquals(writes, charger.writes.size());
        charger.engine.setScreenSaveTime(ScreenTimeout.ONE_MINUTE.wireValue);
        byte[] set = charger.lastRequest();
        // set u8: 0c 20 seq 00 01 | siid 2, piid 6 LE16, type 1, marker 0x10, wire value 5
        assertArrayEquals(new byte[]{0x0c, 0x20, set[2], set[3], 0, 1, 2, 6, 0, 1, 0x10, 0x05}, set);
    }
}
