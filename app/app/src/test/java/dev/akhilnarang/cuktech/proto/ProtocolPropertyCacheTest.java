package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Map;

/** Regression for the dropped-property bug, with a telemetry push from the charger. */
public class ProtocolPropertyCacheTest {
    @Test public void pushedProtocolPropertiesReachTheCache() {
        Charger charger = Charger.loggedIn(23);
        // 0f 20 push, 4 entries without status: siid, piid LE16, type, marker, value LE.
        charger.reply(new byte[]{0x0f, 0x20, 0, 0, 0, 4,
                2, 0x07, 0, 1, 0x10, 6,
                2, 0x11, 0, 4, 0x50, 0x3c, 0x08, 0x1b, 0x07,
                2, 0x12, 0, 4, 0x50, 0, 0, 0x0f, 0x07,
                2, 0x15, 0, 4, 0x50, 0x0f, 0x0f, 0x03, 0x03});
        Map<Integer, Long> cached = charger.engine.getProps();
        assertEquals(Long.valueOf(6), cached.get(0x07));
        assertEquals(Long.valueOf(0x071b083cL), cached.get(0x11));
        assertEquals(Long.valueOf(0x070f0000L), cached.get(0x12));
        assertEquals(Long.valueOf(0x03030f0fL), cached.get(0x15));
        cached.clear();
        assertEquals(4, charger.engine.getProps().size()); // The UI snapshot cannot erase the engine cache.
    }
}
