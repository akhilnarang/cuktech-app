package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.List;

public class TemperatureQueryTest {
    /** A logged-in charger and the index of its first write after login. */
    private static final class Session {
        final Charger charger;
        final MiController engine;
        final int base;
        Session(int mtu) {
            charger = Charger.loggedIn(mtu);
            engine = charger.engine;
            base = charger.writes.size();
        }
        /** Writes after login. Each one must go to the vendor channel. */
        List<byte[]> writes() {
            List<byte[]> out = new ArrayList<>();
            for (Charger.Write w : charger.writes.subList(base, charger.writes.size())) {
                assertEquals(VendorStatus.WRITE_UUID, w.uuid);
                out.add(w.data);
            }
            return out;
        }
        void subscribed(boolean ok) { charger.cb.onSubscribed(VendorStatus.NOTIFY_UUID, ok); }
        void reply(byte[] frame) { charger.cb.onNotify(VendorStatus.NOTIFY_UUID, frame); }
    }

    @Test public void mappedQueryReconnectsAndBlocksInterleavedControls() {
        Session s = new Session(23);
        s.engine.requestTemperature();
        assertEquals(VendorStatus.NOTIFY_UUID, s.charger.vendorSubscription);
        s.engine.setSceneMode(2);
        assertTrue(s.writes().isEmpty());
        s.subscribed(true);
        // 9 bytes: firmware 2.1.2_0079 drops AF07 writes shorter than 9 bytes (dispatcher 0x4203b4: cmp #9).
        assertArrayEquals(new byte[]{(byte)0xfe,(byte)0xdc,(byte)0xba,1,(byte)0xf1,0,1,2,0}, s.writes().get(0));
        s.reply(TelemetryDecodeTest.temperature(45));
        assertEquals(Integer.valueOf(45), s.charger.results.temperature);
        assertEquals(Boolean.TRUE, s.charger.results.last("temperature"));
        assertEquals(1, s.charger.disconnects);
        assertFalse(s.engine.isReady());
        assertNull(s.charger.clock.diagnostic);
        s.reply(TelemetryDecodeTest.temperature(60));
        assertEquals(Integer.valueOf(45), s.charger.results.temperature);
    }

    @Test public void missingServiceDoesNotSendOrDisconnect() {
        Session s = new Session(23);
        s.engine.requestTemperature();
        s.subscribed(false);
        assertEquals(Boolean.FALSE, s.charger.results.last("temperature"));
        assertTrue(s.writes().isEmpty());
        assertEquals(0, s.charger.disconnects);
        assertTrue(s.engine.isReady());
        assertFalse(s.engine.isBusy());
    }

    @Test public void timeoutAfterQueryDisconnectsToClearFirmwareFlag() {
        Session s = new Session(23);
        s.engine.requestTemperature();
        s.subscribed(true);
        s.charger.clock.diagnostic.run();
        assertEquals(Boolean.FALSE, s.charger.results.last("temperature"));
        assertEquals(1, s.charger.disconnects);
        assertNull(s.charger.results.temperature);
    }

    @Test public void diagnosticsAtDefaultMtuSkipOversizedVersionReply() {
        Session s = new Session(23);
        s.engine.requestDiagnostics();
        s.subscribed(true);
        s.reply(TelemetryDecodeTest.temperature(45));
        assertEquals(2, s.writes().size());
        assertEquals(6, s.writes().get(1)[7]);
        assertEquals(0, s.charger.disconnects);
        byte[] protocol = TelemetryDecodeTest.temperature(45);
        protocol[5] = 6;
        s.reply(protocol);
        assertEquals(2, s.writes().size());
        assertEquals(1, s.charger.disconnects);
    }

    @Test public void diagnosticsAtLargerMtuReadVersionsBeforeReconnect() {
        Session s = new Session(247);
        s.engine.requestDiagnostics();
        s.subscribed(true);
        s.reply(TelemetryDecodeTest.temperature(45));
        byte[] protocol = TelemetryDecodeTest.temperature(45); protocol[5] = 6;
        s.reply(protocol);
        assertEquals(3, s.writes().size());
        assertEquals(1, s.writes().get(2)[7]);
        byte[] versions = new byte[21];
        byte[] header = {(byte)0xfe,(byte)0xdc,(byte)0xba,1,(byte)0xf1,1};
        System.arraycopy(header,0,versions,0,6); versions[20] = (byte)0xef;
        s.reply(versions);
        assertEquals(1, s.charger.disconnects);
    }

    @Test public void failedHolidayReadbackReconnectsAndBusyRequestCannotChangeCommand() {
        Session s = new Session(23);
        s.engine.setHolidayArtwork(true);
        s.engine.requestDiagnostics(); // busy: must not erase the pending setter argument.
        s.subscribed(true);
        assertArrayEquals(new byte[]{(byte)0xfe,(byte)0xdc,(byte)0xba,1,(byte)0xf1,0,1,9,1}, s.writes().get(0));
        byte[] reply = {(byte)0xfe,(byte)0xdc,(byte)0xba,1,(byte)0xf1,9,1,0,(byte)0xef};
        s.reply(reply);
        assertEquals("startup artwork", s.charger.results.what.get(s.charger.results.what.size() - 1));
        assertEquals(Boolean.FALSE, s.charger.results.last("startup artwork"));
        assertEquals(1, s.charger.disconnects);
        assertFalse(s.engine.isReady());
    }
}
