package dev.akhilnarang.cuktech.proto;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Fake charger at the GattPort boundary. It does the charger side of the a4 greeting,
 * the CMD_LOGIN mutual HMAC and the MIOT transport. Tests then send CCM-encrypted
 * frames on MIOT_NOTIFY_UUID and read the decrypted requests that the engine sent.
 *
 * <p>The charger crypto uses the production MiCrypto and AesCcm. Thus these tests prove
 * framing, ordering and engine state. They do not prove the crypto.
 *
 * <p>Port callbacks go into a queue. {@link #pump()} delivers them one at a time, as the
 * Android main thread does.
 */
final class Charger implements GattPort {
    /** One write from the engine. */
    static final class Write {
        final String uuid;
        final byte[] data;
        Write(String uuid, byte[] data) { this.uuid = uuid; this.data = data; }
    }

    /** Manual timer. It keeps the vendor diagnostic task (7000 ms) so that a test can run it. */
    static final class Clock implements MiController.Scheduler {
        Runnable diagnostic;
        public void postDelayed(Runnable r, long ms) { if (ms == 7000) diagnostic = r; }
        public void cancel(Runnable r) { if (r == diagnostic) diagnostic = null; }
    }

    /** Records engine events. A fatal error fails the test, unless the test allows it. */
    static final class Results implements MiController.Listener {
        final List<String> what = new ArrayList<>();
        final List<Boolean> ok = new ArrayList<>();
        Integer temperature;
        int portsChanged;
        boolean allowFatal;
        String fatalStage;
        String fatalMessage;
        public void onStatus(String text) {}
        public void onPortsChanged() { portsChanged++; }
        public void onPropsChanged() {}
        public void onResult(String w, boolean result, String error) { what.add(w); ok.add(result); }
        public void onFatal(String stage, String message) {
            if (!allowFatal) fail(stage + ": " + message);
            fatalStage = stage;
            fatalMessage = message;
        }
        public void onTemperatureReading(int value) { temperature = value; }
        Boolean last(String name) {
            for (int i = what.size() - 1; i >= 0; i--) if (what.get(i).equals(name)) return ok.get(i);
            return null;
        }
    }

    final byte[] token = new byte[12];
    final byte[] devRand = new byte[16];
    final Clock clock = new Clock();
    final Results results = new Results();
    final List<Write> writes = new ArrayList<>();
    /** Decrypted MIOT requests from the engine, in send order. */
    final List<byte[]> requests = new ArrayList<>();
    /** If true, the charger does not send RCV_OK after a MIOT request. Use {@link #rcvOk()}. */
    boolean holdRcvOk;
    String vendorSubscription;
    int disconnects;
    Callbacks cb;

    private final int mtu;
    private final ArrayDeque<Runnable> queue = new ArrayDeque<>();
    private int challenges;
    private byte[] appRand;
    private MiCrypto.SessionKeys keys;
    private int authCode;
    private int authCount;
    private ByteArrayOutputStream authData;
    private int miotCount;
    private int miotSeen;
    private int miotCounter;
    private ByteArrayOutputStream miotData;
    private int devCounter;

    private Charger(int mtu) {
        this.mtu = mtu;
        for (int i = 0; i < 12; i++) token[i] = (byte) (i + 1);
        for (int i = 0; i < 16; i++) devRand[i] = (byte) (i + 30);
    }

    /**
     * Makes an engine, logs it in, and answers the first refresh with an empty response.
     *
     * @param mtu MTU that the charger reports.
     */
    static Charger loggedIn(int mtu) {
        Charger charger = new Charger(mtu);
        charger.engine = new MiController(charger, charger.clock, charger.results);
        charger.engine.connect(charger.token, "00:11:22:33:44:55");
        charger.pump();
        assertTrue("login must finish", charger.engine.isReady());
        byte[] refresh = charger.lastRequest();
        assertEquals("refresh is a get request", 0x33, refresh[0]);
        charger.reply(new byte[]{(byte) 0x93, 0x20, refresh[2], refresh[3], 3, 0});
        assertEquals(Boolean.TRUE, charger.results.last("refresh"));
        return charger;
    }

    MiController engine;

    /** Delivers queued callbacks until the queue is empty. */
    void pump() {
        Runnable r;
        while ((r = queue.poll()) != null) r.run();
    }

    /** Sends an encrypted inline frame with the next charger counter. */
    void reply(byte[] plaintext) { inline(devCounter++, plaintext); }

    /** Sends an encrypted inline frame with a chosen charger counter. */
    void inline(int counter, byte[] plaintext) {
        devCounter = Math.max(devCounter, counter + 1);
        byte[] ct = new AesCcm(keys.devKey, 4).encrypt(nonce(keys.devIv, counter), plaintext, null);
        byte[] frame = new byte[6 + ct.length];
        frame[2] = 2;
        frame[4] = (byte) counter;
        frame[5] = (byte) (counter >> 8);
        System.arraycopy(ct, 0, frame, 6, ct.length);
        notify(MiProto.MIOT_NOTIFY_UUID, frame);
    }

    /** Sends RCV_OK for a MIOT request that {@link #holdRcvOk} held back. */
    void rcvOk() { notify(MiProto.MIOT_WRITE_UUID, MiProto.RCV_OK); }

    /** Sends a notification and delivers it. */
    void notify(String uuid, byte[] data) {
        queue.add(() -> cb.onNotify(uuid, data.clone()));
        pump();
    }

    /** Delivers queued callbacks, then returns the last decrypted MIOT request. */
    byte[] lastRequest() {
        pump();
        return requests.get(requests.size() - 1);
    }

    static int seq(byte[] request) { return (request[2] & 255) | ((request[3] & 255) << 8); }

    List<byte[]> writesTo(String uuid) {
        List<byte[]> out = new ArrayList<>();
        for (Write w : writes) if (w.uuid.equals(uuid)) out.add(w.data);
        return out;
    }

    // Nonce layout from MiotFraming: IV(4) + 4 zero bytes + counter LE16 + 2 zero bytes.
    private static byte[] nonce(byte[] iv, int counter) {
        return new byte[]{iv[0], iv[1], iv[2], iv[3], 0, 0, 0, 0, (byte) counter, (byte) (counter >> 8), 0, 0};
    }

    private void later(Runnable r) { queue.add(r); }

    // ---------------------------------------------------------------- GattPort

    public void setCallbacks(Callbacks value) { cb = value; }
    public void connect(String mac) { later(cb::onConnected); }
    public void discoverServices() { later(() -> cb.onServicesDiscovered(true)); }
    public void requestMtu(int requested) { later(() -> cb.onMtu(mtu)); }
    public void subscribe(String uuid) {
        if (uuid.equals(VendorStatus.NOTIFY_UUID)) vendorSubscription = uuid;
        else later(() -> cb.onSubscribed(uuid, true));
    }
    public void disconnect() { disconnects++; }
    public void close() {}

    public boolean write(String uuid, byte[] data) {
        writes.add(new Write(uuid, data.clone()));
        if (uuid.equals(MiProto.UPNP_UUID)) {
            if (Arrays.equals(data, MiProto.GREETING_TRIGGER)) challenge();
        } else if (uuid.equals(MiProto.AVDTP_UUID)) {
            avdtp(data);
        } else if (uuid.equals(MiProto.MIOT_WRITE_UUID)) {
            miot(data);
        }
        return true;
    }

    private void challenge() {
        later(() -> cb.onNotify(MiProto.AVDTP_UUID, new byte[]{0, 0, 4, 0, 6, (byte) 0xf2}));
    }

    private void avdtp(byte[] b) {
        if (b.length >= 3 && b[0] == 0 && b[1] == 0 && b[2] == 5) {
            // The engine echoes each a4 challenge. It expects two challenges.
            if (++challenges == 1) challenge();
        } else if (b.length == 6 && b[0] == 0 && b[1] == 0 && b[2] == 0) {
            authCode = b[3] & 255;
            authCount = (b[4] & 255) | ((b[5] & 255) << 8);
            authData = new ByteArrayOutputStream();
            later(() -> cb.onNotify(MiProto.AVDTP_UUID, MiProto.RCV_RDY));
        } else if (Arrays.equals(b, MiProto.OFFICIAL_ACK)) {
            // The engine consumed an inline login payload.
        } else if (authData != null) {
            authData.write(b, 2, b.length - 2);
            int idx = (b[0] & 255) | ((b[1] & 255) << 8);
            if (idx == authCount) authDone();
        }
    }

    private void authDone() {
        byte[] data = authData.toByteArray();
        authData = null;
        later(() -> cb.onNotify(MiProto.AVDTP_UUID, MiProto.RCV_OK));
        if (authCode == 0x0b) {
            appRand = data;
            keys = MiCrypto.deriveLogin(token, appRand, devRand);
            byte[] devProof = MiCrypto.hmacSha256(keys.devKey, concat(devRand, appRand));
            later(() -> cb.onNotify(MiProto.AVDTP_UUID, concat(new byte[]{0, 0, 2, 0x0d}, devRand)));
            later(() -> cb.onNotify(MiProto.AVDTP_UUID, concat(new byte[]{0, 0, 2, 0x0c}, devProof)));
        } else if (authCode == 0x0a) {
            assertArrayEquals("app proof", MiCrypto.hmacSha256(keys.appKey, concat(appRand, devRand)), data);
            later(() -> cb.onNotify(MiProto.UPNP_UUID, MiProto.CFM_LOGIN_OK));
        }
    }

    private void miot(byte[] b) {
        if (b.length == 6 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) {
            miotCount = (b[4] & 255) | ((b[5] & 255) << 8);
            miotSeen = 0;
            miotData = new ByteArrayOutputStream();
            later(() -> cb.onNotify(MiProto.MIOT_WRITE_UUID, MiProto.RCV_RDY));
            return;
        }
        if (miotData == null) return;
        // Outbound parcel: idx LE16, counter LE16, chunk.
        miotCounter = (b[2] & 255) | ((b[3] & 255) << 8);
        miotData.write(b, 4, b.length - 4);
        if (++miotSeen < miotCount) return;
        byte[] plain;
        try {
            plain = new AesCcm(keys.appKey, 4).decrypt(nonce(keys.appIv, miotCounter), miotData.toByteArray(), null);
        } catch (AesCcm.BadTagException e) {
            throw new AssertionError("engine sent a request that does not decrypt", e);
        }
        miotData = null;
        requests.add(plain);
        if (!holdRcvOk) later(() -> cb.onNotify(MiProto.MIOT_WRITE_UUID, MiProto.RCV_OK));
        // The init request {05 20 seq f0} is echoed by the charger.
        if (plain[0] == 0x05 && plain[1] == 0x20) later(() -> reply(plain));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
