package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;

/** The RX replay window: 64 counters below the highest accepted counter. */
public class MiotReplayWindowTest {
    private static final String REPLAY = "MIOT RX counter replay (duplicate or too old). Reconnect.";

    // 0f 20 telemetry push with one entry: siid 2, piid 1 (port C1), u32 value.
    private static byte[] port1(int value) {
        return new byte[]{0x0f, 0x20, 0, 0, 0, 1, 2, 1, 0, 4, 0x50,
                (byte) value, (byte) (value >> 8), (byte) (value >> 16), (byte) (value >> 24)};
    }

    private static long port1Raw(Charger charger) { return charger.engine.getPorts()[0].raw; }

    @Test public void outOfOrderCounterInsideTheWindowIsAcceptedOnce() {
        Charger charger = Charger.loggedIn(23);
        charger.results.allowFatal = true;
        charger.inline(10, port1(0x0b01));
        charger.inline(5, port1(0x0b02));
        assertEquals(0x0b02L, port1Raw(charger));
        assertNull(charger.results.fatalStage);
        charger.inline(5, port1(0x0b03));
        assertEquals("security", charger.results.fatalStage);
        assertEquals(REPLAY, charger.results.fatalMessage);
        assertEquals(0x0b02L, port1Raw(charger));
    }

    @Test public void counterSixtyFourBehindIsTooOld() {
        Charger charger = Charger.loggedIn(23);
        charger.results.allowFatal = true;
        charger.inline(70, port1(0x0b01));
        // Highest accepted is 70. Counter 7 is 63 behind it: the oldest slot in the window.
        charger.inline(7, port1(0x0b02));
        assertEquals(0x0b02L, port1Raw(charger));
        assertNull(charger.results.fatalStage);
        // Counter 6 is 64 behind: outside the window.
        charger.inline(6, port1(0x0b03));
        assertEquals("security", charger.results.fatalStage);
        assertEquals(REPLAY, charger.results.fatalMessage);
        assertEquals(0x0b02L, port1Raw(charger));
    }

    @Test public void duplicateOfTheHighestCounterIsReplay() {
        Charger charger = Charger.loggedIn(23);
        charger.results.allowFatal = true;
        charger.inline(10, port1(0x0b01));
        charger.inline(10, port1(0x0b02));
        assertEquals("security", charger.results.fatalStage);
        assertEquals(REPLAY, charger.results.fatalMessage);
        assertEquals(0x0b01L, port1Raw(charger));
    }

    @Test public void counterFarBehindIsTooOldEvenWhenItsWindowBitIsClear() {
        // Counters 65 and 68 behind 70 were never accepted, so only the age limit rejects them.
        for (int counter : new int[]{5, 2}) {
            Charger charger = Charger.loggedIn(23);
            charger.results.allowFatal = true;
            charger.inline(70, port1(0x0b01));
            charger.inline(counter, port1(0x0b02));
            assertEquals("counter " + counter, "security", charger.results.fatalStage);
            assertEquals(REPLAY, charger.results.fatalMessage);
            assertEquals(0x0b01L, port1Raw(charger));
        }
    }
}
