package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;

public class ControlVerificationTest {
    private static void exerciseReadback(int actual, boolean expected) {
        Charger charger = Charger.loggedIn(23);
        charger.holdRcvOk = true;
        charger.engine.setPortMask(7);
        byte[] set = charger.lastRequest();
        // set u8: 0c 20 seq 00 01 | siid 2, piid 0x10 LE16, type 1, marker 0x10, value 7
        assertArrayEquals(new byte[]{0x0c, 0x20, set[2], set[3], 0, 1, 2, 0x10, 0, 1, 0x10, 7}, set);
        int requests = charger.requests.size();
        int seq = Charger.seq(set);
        charger.reply(new byte[]{0x0b, 0x20, (byte)seq, (byte)(seq >> 8), 1, 1, 2, 16, 0, 0, 0});
        assertEquals("early response must not overwrite RCV_OK wait", requests, charger.requests.size());
        assertNull(charger.results.last("port power"));
        charger.rcvOk();
        assertEquals("readback begins only after transport completion", requests + 1, charger.requests.size());
        byte[] read = charger.lastRequest();
        assertEquals(0x33, read[0]);
        seq = Charger.seq(read);
        charger.reply(new byte[]{(byte)0x93, 0x20, (byte)seq, (byte)(seq >> 8), 3, 1,
                2, 16, 0, 0, 0, 1, 0x10, (byte)actual});
        assertNull(charger.results.last("port power"));
        charger.rcvOk();
        assertEquals(Boolean.valueOf(expected), charger.results.last("port power"));
        assertEquals(Long.valueOf(actual), charger.engine.getProps().get(16));
    }

    @Test public void ackBeforeTransportCompletionStillVerifiesSetting() {
        exerciseReadback(7, true);
    }
    @Test public void zeroStatusAckDoesNotHideAnIgnoredSetting() {
        exerciseReadback(15, false);
    }
}
