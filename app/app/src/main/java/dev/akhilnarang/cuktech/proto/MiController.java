package dev.akhilnarang.cuktech.proto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;

/**
 * Pure-Java protocol engine for the AD1204U controller. It does the token login
 * (a4 greeting → CMD_LOGIN + app_rand → mutual HMAC), then the encrypted MIOT
 * session (bulk reads, telemetry, verified controls). Adapted from ha-cuk-ble
 * (https://github.com/zuyan9/ha-cuk-ble), Apache-2.0 (auth.py/session.py).
 * This class does the login only. The token comes from the bind flow in the bind/ package.
 *
 * <p>Threading: the class is not thread-safe. Call all methods, and deliver all port
 * callbacks and scheduler tasks, on one thread (the main thread in production).
 * Listener callbacks come on the same thread.
 *
 * <p>Safety rules:
 * <ul>
 * <li>One GATT operation in flight at a time. Every step has a timeout.
 * <li>The TX nonce is used up BEFORE the first write of a request. A failure during
 *   the send is fatal for the session, because a nonce must never be used again.
 * <li>The RX counter must always increase. A regression (replay or desync) or a failed
 *   AES-CCM tag is fatal. This is stricter than the HA integration, because this
 *   app controls the charger. The only recovery is a new connection and a new login.
 * <li>The engine checks all inbound headers, counts and indices. It drops and counts
 *   malformed AUTHENTICATED telemetry. A malformed response fails the request.
 * <li>The token and the MAC never appear in a listener callback or an error message.
 * </ul>
 *
 * <p>Each instance does one session only. After a fatal error, {@link #userDisconnect()}
 * or {@link #close()}, make a new instance.
 */
public final class MiController {

    /** Timer interface. Production uses a Handler. Tests use a manual clock. */
    public interface Scheduler {
        /**
         * @param r Task to run once on the engine thread.
         * @param ms Delay in ms.
         */
        void postDelayed(Runnable r, long ms);
        /** @param r Task to remove, if it did not run. */
        void cancel(Runnable r);
    }

    /** Engine events. All calls come on the engine thread. */
    public interface Listener {
        /**
         * State changes and diagnostic lines. The text never contains secrets.
         * "ready: logged in, telemetry active" shows the end of the login, and "closed"
         * shows the end of {@link #userDisconnect()}.
         *
         * @param text Status text.
         */
        void onStatus(String text);
        /** The port values changed. Read them with {@link #getPorts()}. */
        void onPortsChanged();
        /** The cached properties changed. Read them with {@link #getProps()}. */
        void onPropsChanged();
        /**
         * Result of a user request (refresh, control set or diagnostic).
         *
         * @param what Name of the request, for example "refresh" or "scene".
         * @param ok True if the request was successful. For a set, true means the
         *        charger read back the requested value.
         * @param error Reason for the failure, or null if ok.
         */
        void onResult(String what, boolean ok, String error);
        /**
         * The session is dead. The UI must disable the controls. This is called at most once.
         *
         * @param stage Stage that failed, for example "connect", "login" or "transport".
         * @param message Reason for the failure.
         */
        void onFatal(String stage, String message);
        /**
         * Firmware version from characteristic 0x0004, read before the login.
         *
         * @param version Version in the format "N.N.N_N".
         */
        default void onFirmwareVersion(String version) {}
        /**
         * Shell temperature from a selector-2 diagnostic reply.
         *
         * @param value Temperature in degrees C, range 24..124.
         */
        default void onTemperatureReading(int value) {}
        /**
         * One decoded vendor diagnostic reply.
         *
         * @param reading The decoded reply.
         */
        default void onVendorStatus(VendorStatus.Reading reading) {}
    }

    private static final long CONNECT_TIMEOUT = 15_000L;
    private static final long DISCOVER_TIMEOUT = 10_000L;
    private static final long MTU_TIMEOUT = 5_000L;
    private static final long SUBSCRIBE_TIMEOUT = 5_000L;
    private static final long GREET_TIMEOUT = 5_000L;
    private static final long CONTROL_FRAME_TIMEOUT = 5_000L;
    private static final long VARIANT_TIMEOUT = 10_000L;
    private static final long REQUEST_TIMEOUT = 10_000L;
    private static final long DISCONNECT_TIMEOUT = 5_000L;

    private static final int MAX_AUTH_PARCELS = 64;

    private final GattPort port;
    private final Scheduler sched;
    private final Listener listener;
    private final SecureRandom random = new SecureRandom();

    private byte[] token;
    private MiCrypto.SessionKeys keys;
    private AesCcm appCcm;
    private AesCcm devCcm;
    private int mtu = 23;

    private boolean started;
    private boolean closed;
    private boolean ready;
    private boolean userClosing;
    private String stage = "idle";

    // foreground wait mechanism (one serialized step at a time)
    private String waitChan;
    private java.util.function.Predicate<byte[]> waitMatch;
    private Consumer<byte[]> waitThen;

    // THREE independent bounded-timeout slots:
    // arming one must never cancel another. A telemetry parcel burst arriving
    // while a request is pending (or a send is in flow control) arms the
    // collect slot; the request/flow slots keep their own deadlines, so a
    // lost response still times out and a stalled burst still fails closed.
    private Runnable waitTimerTask;    // login steps + tx flow control (RCV_RDY/OK)
    private Runnable requestTimerTask; // pending request response deadline
    private Runnable collectTimerTask; // inbound parcel-burst assembly deadline
    private boolean mtuPending;        // guards late onMtu after fallback ran
    private boolean firmwareReadPending;
    private boolean temperaturePending;
    private boolean temperatureSubscribing;
    private boolean temperatureRequiresReconnect;
    private Runnable temperatureTimerTask;
    private int[] diagnosticSelectors = {2};
    private int diagnosticIndex;
    private String diagnosticName = "temperature";
    private Boolean requestedHolidayArtwork;

    /** Bound on interleaved inline frames buffered during a burst (upstream MAX_CAPTURED_FRAMES). */
    private static final int MAX_DEFERRED = 16;

    // subscribe handshake
    private String subWaitUuid;
    private Runnable subThen;

    // MIOT session state
    private int txCounter;
    private int rxCounter;
    /** Bit i set = counter (rxCounter - 1 - i) already accepted (replay window). */
    private long rxWindow;
    private int requestSeq = 2;
    private Pending pending;
    private int inExpected;
    private TreeMap<Integer, byte[]> inParts;
    private int inCounter = -1;
    private final List<int[]> deferredFrames = new ArrayList<>(); // {counter} + ct pairs

    // cached state for the UI
    private final PortTelemetry.Port[] ports = new PortTelemetry.Port[4];
    private final Map<Integer, Long> props = new HashMap<>();

    private static final class Pending {
        final byte seq0, seq1;
        final int[] opcodes; // 2-byte LE opcode pairs as {b0,b1,...}
        final Consumer<byte[]> onResponse;
        final String what;

        Pending(int seq, int[] opcodes, Consumer<byte[]> onResponse, String what) {
            this.seq0 = (byte) seq;
            this.seq1 = (byte) (seq >> 8);
            this.opcodes = opcodes;
            this.onResponse = onResponse;
            this.what = what;
        }
    }

    /**
     * @param port BLE transport. The engine sets its callbacks in {@link #connect}.
     * @param sched Timer for all timeouts.
     * @param listener Gets the engine events.
     */
    public MiController(GattPort port, Scheduler sched, Listener listener) {
        this.port = port;
        this.sched = sched;
        this.listener = listener;
    }

    // ================================================================ public API

    /**
     * Starts connect, service discovery, firmware read, MTU 247, login, MIOT init and a
     * bulk read. Each step has a timeout. Works once for each instance: later calls do
     * nothing. The engine keeps a copy of the token. A bad token length gives onFatal("setup").
     *
     * @param token12 12-byte bind token.
     * @param mac BLE address of the charger.
     */
    public void connect(byte[] token12, String mac) {
        if (started) return;
        started = true;
        if (token12 == null || token12.length != MiCrypto.TOKEN_LEN) {
            fatal("setup", "token must be 12 bytes");
            return;
        }
        this.token = token12.clone();
        port.setCallbacks(portCb);
        stage("connecting");
        port.connect(mac);
        armWait(CONNECT_TIMEOUT, "connect", () -> fatal("connect", "timeout: no connection"));
    }

    /** @return True after the MIOT init, until a fatal error, a disconnect or close. */
    public boolean isReady() { return ready && !closed && !userClosing; }

    /** @return True if a MIOT request or a diagnostic is in progress. */
    public boolean isBusy() { return pending != null || temperaturePending; }

    /**
     * @return True if the last diagnostic sent a vendor command. The engine then
     *         disconnects when the diagnostic ends, and the app must connect again.
     */
    public boolean getTemperatureRequiresReconnect() { return temperatureRequiresReconnect; }

    /**
     * Reads the shell temperature (selector 2) on the vendor channel. Use for a manual
     * diagnostic only: vendor commands pause MIOT updates until disconnect. When the reply
     * comes, or after 7 s, the engine calls onResult("temperature") and then disconnects.
     */
    public void requestTemperature() {
        startDiagnostic("temperature", new int[]{2}, null);
    }

    /**
     * Reads selectors 2 and 6, and 1 if the MTU is 24 or more, on the vendor channel.
     * Each reply goes to onVendorStatus. Then onResult("diagnostics") comes and the engine
     * disconnects, as for {@link #requestTemperature()}.
     */
    public void requestDiagnostics() {
        startDiagnostic("diagnostics", mtu >= 24 ? new int[]{2,6,1} : new int[]{2,6}, null);
    }

    /**
     * Sets the holiday startup artwork (selector 9) and checks the readback.
     * Then onResult("startup artwork") comes and the engine disconnects.
     *
     * @param enabled True to show the holiday artwork.
     */
    public void setHolidayArtwork(boolean enabled) {
        startDiagnostic("startup artwork", new int[]{9}, enabled);
    }

    private void startDiagnostic(String name, int[] selectors, Boolean holidayArtwork) {
        if (!requireReady(name)) return;
        requestedHolidayArtwork = holidayArtwork;
        diagnosticName = name;
        diagnosticSelectors = selectors;
        diagnosticIndex = 0;
        temperaturePending = true;
        temperatureSubscribing = true;
        temperatureRequiresReconnect = false;
        armDiagnosticTimer();
        port.subscribe(VendorStatus.NOTIFY_UUID);
    }

    private void armDiagnosticTimer() {
        cancelTemperatureTimer();
        temperatureTimerTask = () -> finishTemperature(false, "No diagnostic reply from the charger");
        sched.postDelayed(temperatureTimerTask, 7_000L);
    }

    private void sendDiagnosticQuery() {
        armDiagnosticTimer();
        temperatureRequiresReconnect = true;
        byte[] request = requestedHolidayArtwork == null ? VendorStatus.statusRequest(diagnosticSelectors[diagnosticIndex])
                : VendorStatus.holidayRequest(requestedHolidayArtwork);
        if (!port.write(VendorStatus.WRITE_UUID, request))
            finishTemperature(false, "Diagnostic query could not be sent");
    }

    private void finishTemperature(boolean ok, String error) {
        if (!temperaturePending || closed) return;
        temperaturePending = false;
        temperatureSubscribing = false;
        cancelTemperatureTimer();
        listener.onResult(diagnosticName, ok, error);
        if (temperatureRequiresReconnect && !closed && !userClosing) userDisconnect();
    }

    private void cancelTemperatureTimer() {
        if (temperatureTimerTask != null) {
            sched.cancel(temperatureTimerTask);
            temperatureTimerTask = null;
        }
    }

    /** @return A copy of the last port values, by port index 0..3. An item is null until the first value. */
    public PortTelemetry.Port[] getPorts() { return ports.clone(); }

    /** @return A copy of the cached siid 2 properties, piid to unsigned value. */
    public Map<Integer, Long> getProps() { return new HashMap<>(props); }

    /**
     * Reads the ports and the settings again with {@link MiProto#BULK_TUPLES}.
     * The result comes through onResult("refresh").
     */
    public void requestRefresh() {
        sendGet("refresh", MiProto.BULK_TUPLES);
    }

    /**
     * Reads only the protocol words of the ports again (2.17 C1/C2, 2.18 C3/A).
     * The result comes through onResult("protocols").
     */
    public void requestProtocols() {
        sendGet("protocols", new int[][]{{MiProto.SIID, 0x11}, {MiProto.SIID, 0x12}});
    }

    /**
     * Sets scene_mode (2.5). The result comes through onResult("scene") after the readback.
     *
     * @param value Wire value 1..4. See {@link MiProto#sceneModeValue}. A value out of
     *        range gives a failed onResult.
     */
    public void setSceneMode(int value) {
        if (value < 1 || value > 4) {
            listener.onResult("scene", false, "scene value " + value + " out of range 1..4");
            return;
        }
        sendSetU8("scene", MiProto.PIID_SCENE_MODE, value);
    }

    /**
     * Sets usb_a_always_on (2.15). The result comes through onResult after the readback.
     *
     * @param on New value.
     */
    public void setUsbAAlwaysOn(boolean on) {
        sendSetBool("usb_a_always_on", MiProto.PIID_USB_A_ALWAYS_ON, on);
    }

    /**
     * Sets screenoff_while_idle (2.19). The result comes through onResult after the readback.
     *
     * @param on New value.
     */
    public void setScreenOffIdle(boolean on) {
        sendSetBool("screenoff_while_idle", MiProto.PIID_SCREEN_OFF_IDLE, on);
    }

    /**
     * Sets screen_dir_lock (2.20). The result comes through onResult after the readback.
     *
     * @param on New value.
     */
    public void setScreenDirLock(boolean on) {
        sendSetBool("screen_dir_lock", MiProto.PIID_SCREEN_DIR_LOCK, on);
    }

    /**
     * Sets screen_save_time (2.6). The result comes through onResult after the readback.
     *
     * @param value A {@link ScreenTimeout#wireValue}.
     * @throws IllegalArgumentException If the value is not a known ScreenTimeout.
     */
    public void setScreenSaveTime(int value) {
        if (ScreenTimeout.fromWireValue(value) == null) throw new IllegalArgumentException("screen timeout");
        sendSetU8("screen timeout", MiProto.PIID_SCREEN_SAVE_TIME, value);
    }

    /**
     * Sets device_language (2.13). The result comes through onResult after the readback.
     *
     * @param value 0 or 1.
     * @throws IllegalArgumentException If the value is not 0 or 1.
     */
    public void setDeviceLanguage(int value) {
        if (value < 0 || value > 1) throw new IllegalArgumentException("language");
        sendSetU8("display language", MiProto.PIID_DEVICE_LANGUAGE, value);
    }

    /**
     * Sets port_ctl (2.16), the port power mask. The result comes through onResult after
     * the readback.
     *
     * @param value Mask 0..255.
     * @throws IllegalArgumentException If the value is out of range.
     */
    public void setPortMask(int value) {
        if (value < 0 || value > 255) throw new IllegalArgumentException("port mask");
        sendSetU8("port power", MiProto.PIID_PORT_CTL, value);
    }

    /**
     * Changes one bit of protocol_ctl_extend (2.21) with {@link ProtocolControls#update}.
     * The cached value must be known from an earlier read. The result comes through
     * onResult("protocol setting") after the readback.
     *
     * @param bit Bit number from {@link ProtocolControls#BITS}.
     * @param enabled True to enable the protocol.
     * @throws IllegalArgumentException If the bit is not in {@link ProtocolControls#BITS}.
     */
    public void setProtocolFlag(int bit, boolean enabled) {
        if (!requireReady("protocol setting")) return;
        Long previous = props.get(MiProto.PIID_PROTOCOL_CTL_EXTEND);
        if (previous == null) {
            listener.onResult("protocol setting", false, "read the protocol settings first");
            return;
        }
        long value = ProtocolControls.update(previous, bit, enabled);
        sendEncodedSet("protocol setting", MiProto.PIID_PROTOCOL_CTL_EXTEND, value,
                MiotProperties.encodeSetU32(nextSequence(), MiProto.SIID, MiProto.PIID_PROTOCOL_CTL_EXTEND, value));
    }

    /**
     * Reads the countdown timers 2.9..2.12. This read is optional and separate from the
     * default bulk request that is verified on hardware. The result comes through
     * onResult("timers").
     */
    public void readCountdowns() {
        sendGet("timers", new int[][]{{2, 9}, {2, 10}, {2, 11}, {2, 12}});
    }

    /**
     * Sets the countdown timer of one port (2.9 + portIndex). The result comes through
     * onResult("timer") after the readback.
     *
     * @param portIndex Port index 0..3.
     * @param minutes Countdown in minutes, 0..65535.
     * @throws IllegalArgumentException If a value is out of range.
     */
    public void setCountdown(int portIndex, int minutes) {
        if (portIndex < 0 || portIndex > 3 || minutes < 0 || minutes > 65535)
            throw new IllegalArgumentException("countdown");
        if (!requireReady("timer")) return;
        int piid = MiProto.PIID_COUNTDOWN_C1 + portIndex;
        int seq = nextSequence();
        byte[] req = MiotProperties.encodeSetU16(seq, MiProto.SIID, piid, minutes);
        sendEncodedSet("timer", piid, minutes, req);
    }

    /**
     * Disconnect that the user started. Stops all requests and waits up to 5 s for the
     * disconnect. Then it closes the port and calls onStatus("closed") once. Does nothing
     * before {@link #connect} or after close.
     */
    public void userDisconnect() {
        if (closed || !started) return;
        userClosing = true;
        stage("disconnecting");
        cancelAllTimers();
        clearWaitState();
        pending = null;
        port.disconnect();
        armWait(DISCONNECT_TIMEOUT, "disconnect", this::finishClosed);
    }

    /** Lifecycle teardown. Stops everything and closes the port with no listener callbacks. */
    public void close() {
        if (closed) return;
        closed = true;
        cancelAllTimers();
        clearWaitState();
        pending = null;
        port.close();
    }

    // ================================================================ port callbacks (single thread)

    private final GattPort.Callbacks portCb = new GattPort.Callbacks() {
        @Override public void onConnected() {
            if (closed) return;
            cancelWaitTimer();
            stage("discovering services");
            port.discoverServices();
            armWait(DISCOVER_TIMEOUT, "discover", () -> fatal("discover", "timeout"));
        }

        @Override public void onDisconnected(int status) {
            if (closed) return;
            if (userClosing) {
                finishClosed();
            } else {
                fatal("connection", "device disconnected (status " + status + ")");
            }
        }

        @Override public void onWriteFailed(String uuid, String reason) {
            // Generic transport failure: never phrased as a
            // token or MTU problem — those have their own accurate messages.
            if (closed) return;
            fatal("transport", "GATT write to " + shortUuid(uuid) + " failed: " + reason);
        }

        @Override public void onServicesDiscovered(boolean ok) {
            if (closed) return;
            if (!ok) {
                fatal("discover", "service discovery failed");
                return;
            }
            cancelWaitTimer();
            firmwareReadPending = true;
            if (port.read(MiProto.FIRMWARE_VERSION_UUID)) {
                armWait(5_000L, "firmware version", () -> {
                    firmwareReadPending = false;
                    requestInitialMtu();
                });
            } else {
                firmwareReadPending = false;
                requestInitialMtu();
            }
        }

        @Override public void onRead(String uuid, byte[] data, boolean ok) {
            if (closed || !firmwareReadPending || !MiProto.FIRMWARE_VERSION_UUID.equals(uuid)) return;
            firmwareReadPending = false;
            cancelWaitTimer();
            if (ok && data != null) {
                int end = 0;
                while (end < data.length && data[end] != 0) end++;
                String version = new String(data, 0, end, java.nio.charset.StandardCharsets.US_ASCII).trim();
                if (version.matches("[0-9]+\\.[0-9]+\\.[0-9]+_[0-9]+")) listener.onFirmwareVersion(version);
            }
            requestInitialMtu();
        }

        @Override public void onMtu(int negotiated) {
            if (closed) return;
            // Late callback after the timeout fallback already ran: ignore
            // instead of re-running the subscribe chain.
            if (!mtuPending) return;
            mtuPending = false;
            cancelWaitTimer();
            mtu = Math.max(23, negotiated);
            afterMtu();
        }

        @Override public void onSubscribed(String uuid, boolean ok) {
            if (closed) return;
            if (VendorStatus.NOTIFY_UUID.equals(uuid)) {
                if (!temperaturePending || !temperatureSubscribing) return;
                temperatureSubscribing = false;
                if (!ok) {
                    finishTemperature(false, "Temperature diagnostics unavailable on this charger");
                    return;
                }
                sendDiagnosticQuery();
                return;
            }
            if (subWaitUuid != null && subWaitUuid.equals(uuid)) {
                cancelWaitTimer();
                Runnable then = subThen;
                subWaitUuid = null;
                subThen = null;
                if (!ok) {
                    fatal("subscribe", "failed on " + shortUuid(uuid));
                    return;
                }
                if (then != null) then.run();
            }
        }

        @Override public void onNotify(String uuid, byte[] data) {
            if (closed || data == null) return;
            if (VendorStatus.NOTIFY_UUID.equals(uuid)) {
                if (!temperaturePending || temperatureSubscribing || !temperatureRequiresReconnect) return;
                try {
                    int selector = diagnosticSelectors[diagnosticIndex];
                    VendorStatus.Reading status = VendorStatus.decodeStatus(data, selector);
                    if (requestedHolidayArtwork != null && !requestedHolidayArtwork.equals(status.holidayArtwork))
                        throw new IllegalArgumentException("Startup artwork setting did not match readback");
                    listener.onVendorStatus(status);
                    if (selector == 2) {
                        if (diagnosticName.equals("temperature")) {
                            listener.onTemperatureReading(VendorStatus.decodeTemperature(data));
                        } else if ((data[7] & 255) >= 24 && (data[7] & 255) <= 124) {
                            listener.onTemperatureReading(data[7] & 255);
                        }
                    }
                    if (++diagnosticIndex == diagnosticSelectors.length) finishTemperature(true, null);
                    else sendDiagnosticQuery();
                } catch (IllegalArgumentException e) {
                    finishTemperature(false, e.getMessage());
                }
                return;
            }
            if (uuid.equals(MiProto.AVDTP_UUID)) deliverWait(uuid, data);
            else if (uuid.equals(MiProto.UPNP_UUID)) handleUpnp(data);
            else if (uuid.equals(MiProto.MIOT_WRITE_UUID)) deliverWait(uuid, data);
            else if (uuid.equals(MiProto.MIOT_NOTIFY_UUID)) handleMiotData(data);
        }
    };

    // ================================================================ login sequence

    private void requestInitialMtu() {
        if (closed) return;
        stage("requesting MTU 247");
        mtuPending = true;
        port.requestMtu(247);
        armWait(MTU_TIMEOUT, "mtu", () -> {
            mtuPending = false;
            mtu = 23;
            afterMtu();
        });
    }

    private void afterMtu() {
        stage("subscribing auth channel");
        subscribe(MiProto.AVDTP_UUID, this::stepGreet);
    }

    private void stepGreet() {
        stage("greeting");
        w(MiProto.UPNP_UUID, MiProto.GREETING_TRIGGER);
        waitChallenge(1);
    }

    private void waitChallenge(final int n) {
        waitFrame(MiProto.AVDTP_UUID, GREET_TIMEOUT, "greeting",
                f -> f.length >= 3 && f[0] == 0 && f[1] == 0 && f[2] == 0x04,
                f -> {
                    byte[] echo = new byte[f.length];
                    System.arraycopy(f, 0, echo, 0, 3);
                    echo[2] = 0x05;
                    System.arraycopy(f, 3, echo, 3, f.length - 3);
                    w(MiProto.AVDTP_UUID, echo);
                    if (n == 1) {
                        waitChallenge(2);
                    } else {
                        stage("subscribing control channel");
                        subscribe(MiProto.UPNP_UUID, this::stepLogin);
                    }
                });
    }

    private void stepLogin() {
        stage("logging in");
        byte[] appRand = new byte[MiCrypto.RAND_LEN];
        random.nextBytes(appRand);
        // CMD_LOGIN and the random announcement go back-to-back with no delay:
        // pausing here makes the device answer with an e0 reject (upstream).
        w(MiProto.UPNP_UUID, MiProto.CMD_LOGIN);
        sendAuthParcel(MiProto.CMD_SEND_KEY, appRand, () -> recvVariant(0x0d, devRand -> {
            if (devRand == null || devRand.length != MiCrypto.RAND_LEN) {
                fatal("login", "device random has wrong length");
                return;
            }
            recvVariant(0x0c, devInfo -> {
                // A truncated/oversized HMAC is malformed input, not a wrong
                // token — report it accurately
                if (devInfo == null || devInfo.length != 32) {
                    fatal("login", "malformed device HMAC (got "
                            + (devInfo == null ? -1 : devInfo.length) + " bytes, expected 32)");
                    return;
                }
                keys = MiCrypto.deriveLogin(token, appRand, devRand);
                byte[] expect = MiCrypto.hmacSha256(keys.devKey, concat(devRand, appRand));
                if (!MiCrypto.constantTimeEquals(expect, devInfo)) {
                    fatal("login", "device HMAC mismatch. The token is wrong or the device is not bound.");
                    return;
                }
                byte[] appInfo = MiCrypto.hmacSha256(keys.appKey, concat(appRand, devRand));
                sendAuthParcel(MiProto.CMD_SEND_INFO, appInfo, () ->
                        waitControl(MiProto.UPNP_UUID, MiProto.CFM_LOGIN_OK, VARIANT_TIMEOUT,
                                "login", () -> {
                                    // the 23-answer window closes here: a later
                                    // stray 23 is an anomaly, not a token error
                                    loginConfirmed = true;
                                    stepAfterLogin();
                                }));
            });
        }));
    }

    private void stepAfterLogin() {
        appCcm = new AesCcm(keys.appKey, 4);
        devCcm = new AesCcm(keys.devKey, 4);
        stage("subscribing MIOT channels");
        subscribe(MiProto.MIOT_WRITE_UUID, () ->
                subscribe(MiProto.MIOT_NOTIFY_UUID, this::stepMiotInit));
    }

    private void stepMiotInit() {
        stage("entering MIOT session");
        final int seq = nextSequence();
        final byte[] req = {0x05, 0x20, (byte) seq, (byte) (seq >> 8), (byte) 0xf0};
        sendMiotRequest(req, new int[]{0x05, 0x20}, pt -> {
            if (!Arrays.equals(pt, req)) {
                fatal("miot-init", "unexpected init echo");
                return;
            }
            ready = true;
            stage("ready");
            listener.onStatus("ready: logged in, telemetry active");
            requestRefresh();
        }, "init");
    }

    // ================================================================ requests (MIOT)

    private void sendGet(String what, int[][] tuples) {
        if (!requireReady(what)) return;
        int seq = nextSequence();
        byte[] req = MiotProperties.encodeGetProperties(seq, tuples);
        // null: any non-push xx 20 opcode with our sequence (see parseResponse)
        sendMiotRequest(req, null, pt -> {
            try {
                applyProps(MiotProperties.parseResponse(pt));
                listener.onPropsChanged();
                listener.onPortsChanged();
                listener.onResult(what, true, null);
            } catch (MiotProperties.ParseException e) {
                listener.onResult(what, false, e.getMessage());
            }
        }, what);
    }

    private void sendSetU8(String what, int piid, int value) {
        if (!requireReady(what)) return;
        sendEncodedSet(what, piid, value,
                MiotProperties.encodeSetU8(nextSequence(), MiProto.SIID, piid, value));
    }

    private void sendSetBool(String what, int piid, boolean value) {
        if (!requireReady(what)) return;
        sendEncodedSet(what, piid, value ? 1L : 0L,
                MiotProperties.encodeSetBool(nextSequence(), MiProto.SIID, piid, value));
    }

    private void sendEncodedSet(String what, int piid, long value, byte[] req) {
        sendMiotRequest(req, new int[]{0x0b, 0x20}, pt -> {
            try {
                int status = MiotProperties.parseSetResponse(pt, MiProto.SIID, piid);
                if (status != 0) {
                    listener.onResult(what, false, "device returned status 0x" + Integer.toHexString(status));
                    return;
                }
                // This firmware can ACK unsupported writes with status zero.
                // Read the device state back before reporting a successful change.
                int[][] tuples = piid >= 9 && piid <= 12
                        ? new int[][]{{2, 9}, {2, 10}, {2, 11}, {2, 12}}
                        : MiProto.BULK_TUPLES;
                byte[] read = MiotProperties.encodeGetProperties(nextSequence(), tuples);
                sendMiotRequest(read, null, response -> {
                    try {
                        List<MiotProperties.PropValue> entries = MiotProperties.parseResponse(response);
                        boolean confirmed = false;
                        for (MiotProperties.PropValue prop : entries) {
                            if (prop.siid == MiProto.SIID && prop.piid == piid && prop.status == 0 && prop.value == value)
                                confirmed = true;
                        }
                        applyProps(entries);
                        listener.onPropsChanged();
                        listener.onPortsChanged();
                        listener.onResult(what, confirmed, confirmed ? null : "charger did not confirm the requested value");
                    } catch (MiotProperties.ParseException e) {
                        listener.onResult(what, false, e.getMessage());
                    }
                }, what);
            } catch (MiotProperties.ParseException e) {
                listener.onResult(what, false, e.getMessage());
            }
        }, what);
    }

    private boolean requireReady(String what) {
        if (!isReady()) {
            listener.onResult(what, false, "not connected");
            return false;
        }
        if (pending != null || sendBusy || temperaturePending) {
            listener.onResult(what, false, "busy. Send one request at a time.");
            return false;
        }
        return true;
    }

    /** True from the first write of a request until its response is routed (or it fails). */
    private boolean sendBusy;
    /** A response may arrive before RCV_OK; callbacks must not start a new send yet. */
    private Runnable responseAfterSend;

    /** Pending-request timeout action + bounded deadline extensions. */
    private Runnable requestTimeoutAction;
    private int requestExtensions;
    private static final int MAX_REQUEST_EXTENSIONS = 3;

    /** True once the device confirmed login (21) — scopes later error semantics. */
    private boolean loginConfirmed;

    /**
     * Serialized write helper: a rejected submit (queue closed/full) is a
     * generic transport fatal, propagated immediately.
     */
    private void w(String uuid, byte[] data) {
        if (!port.write(uuid, data)) {
            fatal("transport", "GATT write to " + shortUuid(uuid) + " rejected (queue closed or full)");
        }
    }

    /**
     * Encrypt and send one MIOT request; resolve via routed response.
     * The TX nonce is burned before the first write — any failure past that
     * point is fatal (nonce reuse is never acceptable). The pending request
     * is registered BEFORE the send flow (upstream registers its future
     * before sending): a response that arrives ahead of RCV_OK is routed
     * instead of dropped.
     */
    private void sendMiotRequest(byte[] plaintext, int[] expectOpcodes,
                                 Consumer<byte[]> onResponse, String what) {
        final int counter = txCounter;
        if (counter > MiotFraming.MAX_COUNTER) {
            fatal("counter", "MIOT TX counter exhausted. Reconnect and log in again.");
            return;
        }
        sendBusy = true;
        txCounter = counter + 1; // burn before any fallible operation
        byte[] nonce = MiotFraming.nonce(keys.appIv, counter);
        byte[] ct = appCcm.encrypt(nonce, plaintext, null);
        int cap = Math.max(16, mtu - 7);
        List<byte[]> parcels;
        int count;
        try {
            parcels = MiotFraming.outboundParcels(counter, ct, cap);
            count = parcels.size();
        } catch (IllegalArgumentException e) {
            fatal("miot", e.getMessage());
            return;
        }
        // Register the response wait before anything is sent; the request
        // deadline covers the whole send+response cycle.
        int seq = (plaintext[2] & 0xFF) | ((plaintext[3] & 0xFF) << 8);
        pending = new Pending(seq, expectOpcodes, onResponse, what);
        requestExtensions = 0;
        requestTimeoutAction = () -> {
            if (pending != null) {
                pending = null;
                listener.onResult(what, false,
                        "timeout: no response (seq 0x" + Integer.toHexString(seq) + ")");
            }
        };
        armRequest(REQUEST_TIMEOUT, requestTimeoutAction);
        w(MiProto.MIOT_WRITE_UUID, MiotFraming.announcement(0, count));
        // The nonce is burned: if the flow below stalls, the session is closed.
        // Message explains the known MTU-23 failure mode explicitly — a stall
        // here is a transport problem, never "unsupported device"/"bad token".
        final String stall = "MIOT send stalled at flow control (negotiated MTU=" + mtu
                + "). The AD1204U intermittently rejects multi-parcel uploads at the"
                + " default ATT MTU 23. This is a transport failure. The device is supported"
                + " and the token is not wrong.";
        waitControlMsg(MiProto.MIOT_WRITE_UUID, MiotFraming.rcvRdy(), CONTROL_FRAME_TIMEOUT,
                "miot-send", stall, () -> {
                    for (byte[] p : parcels) w(MiProto.MIOT_WRITE_UUID, p);
                    waitControlMsg(MiProto.MIOT_WRITE_UUID, MiotFraming.rcvOk(),
                            CONTROL_FRAME_TIMEOUT, "miot-send", stall,
                            () -> {
                                sendBusy = false;
                                Runnable response = responseAfterSend;
                                responseAfterSend = null;
                                if (!closed && response != null) response.run();
                            });
                });
    }

    // ================================================================ inbound MIOT (0x001b)

    private void handleMiotData(byte[] data) {
        if (inExpected > 0) {
            collectParcel(data);
            return;
        }
        if (data.length >= 6 && data[0] == 0 && data[1] == 0 && data[2] == 2 && data[3] == 0) {
            // inline frame
            w(MiProto.MIOT_NOTIFY_UUID, MiotFraming.ack());
            processFrame(le16(data, 4), MiotFraming.slice(data, 6, data.length));
        } else if (data.length >= 6 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0) {
            // announcement → parcel collection
            int n = le16(data, 4);
            if (n < 1 || n > MiotFraming.MAX_PARCELS) {
                fatal("miot", "invalid MIOT parcel count " + n);
                return;
            }
            w(MiProto.MIOT_NOTIFY_UUID, MiotFraming.rcvRdy());
            inExpected = n;
            inParts = new TreeMap<>();
            inCounter = -1;
            // collect slot: independent of any pending request deadline, so a
            // stalled burst fails closed on its own timer
            armCollect(VARIANT_TIMEOUT, () ->
                    fatal("miot", "timeout collecting inbound parcels"));
            // the pending response may be inside this burst — extend its
            // deadline while collection is under way, bounded (no false
            // timeout from a slow burst)
            if (pending != null && requestTimeoutAction != null
                    && requestExtensions < MAX_REQUEST_EXTENSIONS) {
                requestExtensions++;
                armRequest(REQUEST_TIMEOUT, requestTimeoutAction);
            }
        }
        // anything else: unknown shape, ignore
    }

    private void collectParcel(byte[] data) {
        if (data.length >= 6 && data[0] == 0 && data[1] == 0 && data[2] == 2 && data[3] == 0) {
            // interleaved inline frame: ACK now, process after the parcel burst
            if (deferredFrames.size() >= MAX_DEFERRED) {
                // upstream bounds deferral at MAX_CAPTURED_FRAMES; a peer that
                // interleaves more than 16 inlines into one burst is misbehaving
                // (or hostile) — fail closed instead of growing without bound
                fatal("miot", "too many inline frames interleaved with MIOT parcel burst");
                return;
            }
            w(MiProto.MIOT_NOTIFY_UUID, MiotFraming.ack());
            deferredFrames.add(new int[]{le16(data, 4)});
            deferredCts.add(MiotFraming.slice(data, 6, data.length));
            return;
        }
        if (data.length < 2) return; // skip, as upstream does
        int idx = le16(data, 0);
        if (idx < 1 || idx > inExpected) {
            fatal("miot", "MIOT parcel index " + idx + " outside 1.." + inExpected);
            return;
        }
        if (inParts.containsKey(idx)) {
            fatal("miot", "duplicate MIOT parcel index " + idx);
            return;
        }
        if (idx == 1) {
            if (data.length < 4) {
                fatal("miot", "first MIOT parcel is missing counter");
                return;
            }
            inCounter = le16(data, 2);
            inParts.put(idx, MiotFraming.slice(data, 4, data.length));
        } else {
            inParts.put(idx, MiotFraming.slice(data, 2, data.length));
        }
        if (inParts.size() == inExpected) {
            w(MiProto.MIOT_NOTIFY_UUID, MiotFraming.rcvOk());
            cancelCollectTimer();
            int len = 0;
            for (byte[] p : inParts.values()) len += p.length;
            byte[] ct = new byte[len];
            int off = 0;
            for (byte[] p : inParts.values()) {
                System.arraycopy(p, 0, ct, off, p.length);
                off += p.length;
            }
            int counter = inCounter;
            List<int[]> deferred = new ArrayList<>(deferredFrames);
            List<byte[]> deferredCt = new ArrayList<>(deferredCts);
            inExpected = 0;
            inParts = null;
            inCounter = -1;
            deferredFrames.clear();
            deferredCts.clear();
            processFrame(counter, ct);
            for (int i = 0; i < deferred.size(); i++) {
                processFrame(deferred.get(i)[0], deferredCt.get(i));
            }
        }
    }

    private final List<byte[]> deferredCts = new ArrayList<>();

    /** Decrypt + authenticate one inbound frame; enforce the RX counter. */
    private void processFrame(int counter, byte[] ct) {
        if (closed) return;
        // a 0x001b frame cannot arrive before login (not subscribed yet), but
        // a race or a framework quirk must never NPE
        if (keys == null || devCcm == null) return;
        // frames may arrive out of order (an inline reply can overtake a parcel burst, e.g. after
        // a port toggle), so accept any not-yet-seen counter within a 64-frame window
        int behind = rxCounter - 1 - counter;
        if (behind >= 64 || (behind >= 0 && ((rxWindow >>> behind) & 1) != 0)) {
            fatal("security", "MIOT RX counter replay (duplicate or too old). Reconnect.");
            return;
        }
        byte[] pt;
        try {
            pt = devCcm.decrypt(MiotFraming.nonce(keys.devIv, counter), ct, null);
        } catch (AesCcm.BadTagException e) {
            fatal("security", "MIOT frame authentication failed. Reconnect.");
            return;
        }
        if (behind < 0) {
            int shift = counter - rxCounter + 1;
            rxWindow = (shift >= 64 ? 0 : rxWindow << shift) | 1;
            rxCounter = counter + 1;
        } else {
            rxWindow |= 1L << behind;
        }
        if (rxCounter > MiotFraming.MAX_COUNTER + 1) {
            fatal("counter", "MIOT RX counter exhausted. Reconnect.");
            return;
        }
        routePlaintext(pt);
    }

    private void routePlaintext(byte[] pt) {
        if (pt == null || pt.length < 2) return;
        Pending p = pending;
        if (p != null && pt.length >= 4 && pt[2] == p.seq0 && pt[3] == p.seq1 && opcodeMatch(pt, p)) {
            pending = null;
            cancelRequestTimer();
            if (sendBusy) {
                byte[] snapshot = pt.clone();
                responseAfterSend = () -> p.onResponse.accept(snapshot);
            } else {
                p.onResponse.accept(pt);
            }
            return;
        }
        if (pt[0] == 0x0f && pt[1] == 0x20) {
            handleTelemetry(pt);
        } else if (pt.length >= 5 && pt[0] == 0x0c && pt[1] == 0x20 && pt[4] == 0x04) {
            handleEcho(pt);
        }
        // unhandled frames are ignored (upstream logs and moves on)
    }

    private void handleTelemetry(byte[] pt) {
        try {
            applyProps(MiotProperties.parseNotification(pt));
        } catch (MiotProperties.ParseException e) {
            // authenticated but malformed: drop the frame, keep the session
            return;
        }
        listener.onPortsChanged();
    }

    private void handleEcho(byte[] pt) {
        try {
            applyProps(MiotProperties.parseNotification(pt));
        } catch (MiotProperties.ParseException e) {
            return;
        }
        listener.onPropsChanged();
    }

    private void applyProps(List<MiotProperties.PropValue> values) {
        for (MiotProperties.PropValue v : values) {
            if (v.siid != MiProto.SIID || v.status != 0) continue;
            if (v.piid >= 1 && v.piid <= 4) {
                ports[v.piid - 1] = PortTelemetry.decode(v.piid - 1, v.value);
            } else if (v.piid == MiProto.PIID_SCENE_MODE || v.piid == MiProto.PIID_USB_A_ALWAYS_ON
                    || v.piid == MiProto.PIID_SCREEN_OFF_IDLE || v.piid == MiProto.PIID_SCREEN_DIR_LOCK
                    || v.piid == MiProto.PIID_SCREEN_SAVE_TIME || v.piid == MiProto.PIID_DEVICE_LANGUAGE
                    || v.piid == MiProto.PIID_PORT_CTL || (v.piid >= 9 && v.piid <= 12)
                    // protocol_ctl, c1c2/c3a protocol words, protocol_ctl_extend (port protocol
                    // labels and protocol switches read these; they were dropped before)
                    || v.piid == 0x07 || v.piid == 0x11 || v.piid == 0x12
                    || v.piid == MiProto.PIID_PROTOCOL_CTL_EXTEND) {
                props.put(v.piid, v.value);
            }
        }
    }

    // ================================================================ auth parcel IO (login)

    /** Send announcement → RCV_RDY → parcels → RCV_OK on the AVDTP channel. */
    private void sendAuthParcel(byte[] announcement, byte[] data, Runnable then) {
        int chunk = Math.max(MiotFraming.PARCEL_CHUNK_SIZE, mtu - 5);
        List<byte[]> frames = chunkBytes(data, chunk);
        if (frames.size() > MAX_AUTH_PARCELS) {
            fatal("login", "auth payload needs " + frames.size() + " parcels; max " + MAX_AUTH_PARCELS);
            return;
        }
        byte[] ann = new byte[6];
        System.arraycopy(announcement, 0, ann, 0, 4);
        ann[4] = (byte) frames.size();
        ann[5] = (byte) (frames.size() >> 8);
        w(MiProto.AVDTP_UUID, ann);
        waitControl(MiProto.AVDTP_UUID, MiotFraming.rcvRdy(), CONTROL_FRAME_TIMEOUT,
                "login", () -> {
                    for (int i = 0; i < frames.size(); i++) {
                        byte[] f = new byte[2 + frames.get(i).length];
                        f[0] = (byte) (i + 1);
                        f[1] = (byte) ((i + 1) >> 8);
                        System.arraycopy(frames.get(i), 0, f, 2, frames.get(i).length);
                        w(MiProto.AVDTP_UUID, f);
                    }
                    waitControl(MiProto.AVDTP_UUID, MiotFraming.rcvOk(), CONTROL_FRAME_TIMEOUT,
                            "login", then);
                });
    }

    /**
     * Receive one login payload: official-inline (00 00 02 CODE payload → ACK)
     * or dash-app parcel (00 00 00 CODE NN NN → RCV_RDY / parcels / RCV_OK).
     */
    private void recvVariant(int code, Consumer<byte[]> then) {
        waitFrame(MiProto.AVDTP_UUID, VARIANT_TIMEOUT, "login", f -> f.length >= 4,
                f -> {
                    int variant = f[2] & 0xFF;
                    int c = f[3] & 0xFF;
                    if (c != code) {
                        fatal("login", "expected variant code 0x" + Integer.toHexString(code)
                                + ", got 0x" + Integer.toHexString(c));
                        return;
                    }
                    if (variant == 0x02) {
                        w(MiProto.AVDTP_UUID, MiotFraming.ack());
                        then.accept(MiotFraming.slice(f, 4, f.length));
                    } else if (variant == 0x00) {
                        // dash-app announcement needs the 2-byte count at [4:6];
                        // a shorter frame is malformed → clean fatal, never an
                        // array overrun
                        if (f.length < 6) {
                            fatal("login", "short auth announcement: " + MiotFraming.hex(f));
                            return;
                        }
                        int n = le16(f, 4);
                        if (n < 1 || n > MAX_AUTH_PARCELS) {
                            fatal("login", "invalid auth parcel count " + n);
                            return;
                        }
                        w(MiProto.AVDTP_UUID, MiotFraming.rcvRdy());
                        collectAuthParcels(n, new TreeMap<>(), then);
                    } else {
                        fatal("login", "unknown variant byte 0x" + Integer.toHexString(variant));
                    }
                });
    }

    private void collectAuthParcels(int expected, TreeMap<Integer, byte[]> parts,
                                    Consumer<byte[]> then) {
        waitFrame(MiProto.AVDTP_UUID, VARIANT_TIMEOUT, "login", f -> f.length >= 2,
                f -> {
                    int idx = le16(f, 0);
                    if (idx < 1 || idx > expected) {
                        fatal("login", "auth parcel index " + idx + " outside 1.." + expected);
                        return;
                    }
                    if (parts.containsKey(idx)) {
                        fatal("login", "duplicate auth parcel index " + idx);
                        return;
                    }
                    parts.put(idx, MiotFraming.slice(f, 2, f.length));
                    if (parts.size() == expected) {
                        w(MiProto.AVDTP_UUID, MiotFraming.rcvOk());
                        int len = 0;
                        for (byte[] p : parts.values()) len += p.length;
                        byte[] out = new byte[len];
                        int off = 0;
                        for (byte[] p : parts.values()) {
                            System.arraycopy(p, 0, out, off, p.length);
                            off += p.length;
                        }
                        then.accept(out);
                    } else {
                        collectAuthParcels(expected, parts, then);
                    }
                });
    }

    // ================================================================ UPNP notifications

    /**
     * UPNP error frames are scoped to the login phase:
     * exact 4-byte codes only (upstream AUTH_ERRORS + CFM_LOGIN_ERR), never
     * prefix/first-byte matches, and post-login stray UPNP frames are ignored
     * instead of killing a healthy MIOT session.
     */
    private void handleUpnp(byte[] data) {
        if (!ready) {
            if (Arrays.equals(data, MiProto.CFM_LOGIN_ERR)) {
                // a 23 answering our app-HMAC submission is the classic wrong-
                // token / not-bound rejection (upstream semantics); a 23 after
                // the device already confirmed login is a protocol anomaly
                fatal("login", loginConfirmed
                        ? "device reported login failure after confirming login (protocol anomaly)"
                        : "device reported login failure. The token is wrong or the device is not bound.");
                return;
            }
            if (isAuthError(data)) {
                fatal("login", authErrorText(data));
                return;
            }
        }
        deliverWait(MiProto.UPNP_UUID, data);
    }

    /**
     * Makes the error text for an auth error frame.
     * e0 = charger not bound, e2 = it still holds a logged-in session (fw 0x419658).
     *
     * @param data Auth error frame, at least 1 byte.
     * @return Error text with the frame as hex.
     */
    static String authErrorText(byte[] data) {
        String hex = MiotFraming.hex(data);
        if ((data[0] & 0xFF) == 0xe2) return "charger still has the previous session open (" + hex + ")";
        if ((data[0] & 0xFF) == 0xe0) return "charger is not bound (" + hex + ")";
        return "device auth error: " + hex;
    }

    /** Exact upstream AUTH_ERRORS membership: e0–e3 00 00 00, 4 bytes. */
    private static boolean isAuthError(byte[] data) {
        if (data == null || data.length != 4) return false;
        int b = data[0] & 0xFF;
        return b >= 0xe0 && b <= 0xe3 && data[1] == 0 && data[2] == 0 && data[3] == 0;
    }

    // ================================================================ wait / timeout machinery

    private void waitControl(String chan, byte[] expected, long ms, String stageName, Runnable then) {
        waitFrame(chan, ms, stageName, f -> Arrays.equals(f, expected), f -> then.run());
    }

    /** waitControl with a custom timeout message (used for the MTU-sensitive MIOT send path). */
    private void waitControlMsg(String chan, byte[] expected, long ms, String stageName,
                                String timeoutMessage, Runnable then) {
        waitChan = chan;
        waitMatch = f -> Arrays.equals(f, expected);
        waitThen = f -> then.run();
        armWait(ms, stageName, () -> fatal(stageName, timeoutMessage));
    }

    private void waitFrame(String chan, long ms, String stageName,
                           java.util.function.Predicate<byte[]> match, Consumer<byte[]> then) {
        waitChan = chan;
        waitMatch = match;
        waitThen = then;
        armWait(ms, stageName, () -> fatal(stageName, "timeout waiting on " + shortUuid(chan)));
    }

    private void deliverWait(String chan, byte[] data) {
        // upstream raises on AUTH_ERRORS on either auth channel during login;
        // mirror that before any variant/wait matching so the diagnostic is
        // phase-accurate, and only pre-login
        if (!ready && isAuthError(data)) {
            fatal("login", authErrorText(data));
            return;
        }
        if (waitChan != null && waitChan.equals(chan) && waitMatch != null && waitMatch.test(data)) {
            cancelWaitTimer();
            Consumer<byte[]> then = waitThen;
            clearWait();
            if (then != null) then.accept(data);
        }
        // non-matching frames on the waited channel are discarded (recv_until)
    }

    private void clearWait() {
        waitChan = null;
        waitMatch = null;
        waitThen = null;
    }

    private void clearWaitState() {
        clearWait();
        subWaitUuid = null;
        subThen = null;
    }

    private void subscribe(String uuid, Runnable then) {
        subWaitUuid = uuid;
        subThen = then;
        port.subscribe(uuid);
        armWait(SUBSCRIBE_TIMEOUT, "subscribe", () -> fatal("subscribe", "timeout on " + shortUuid(uuid)));
    }

    private void armWait(long ms, String stageName, Runnable r) {
        cancelWaitTimer();
        waitTimerTask = r;
        sched.postDelayed(r, ms);
    }

    private void cancelWaitTimer() {
        if (waitTimerTask != null) {
            sched.cancel(waitTimerTask);
            waitTimerTask = null;
        }
    }

    private void armRequest(long ms, Runnable r) {
        cancelRequestTimer();
        requestTimerTask = r;
        sched.postDelayed(r, ms);
    }

    private void cancelRequestTimer() {
        if (requestTimerTask != null) {
            sched.cancel(requestTimerTask);
            requestTimerTask = null;
        }
    }

    private void armCollect(long ms, Runnable r) {
        cancelCollectTimer();
        collectTimerTask = r;
        sched.postDelayed(r, ms);
    }

    private void cancelCollectTimer() {
        if (collectTimerTask != null) {
            sched.cancel(collectTimerTask);
            collectTimerTask = null;
        }
    }

    private void cancelAllTimers() {
        cancelWaitTimer();
        cancelRequestTimer();
        cancelCollectTimer();
        cancelTemperatureTimer();
    }

    // ================================================================ termination

    private void finishClosed() {
        if (closed) return;
        closed = true;
        cancelAllTimers();
        clearWaitState();
        pending = null;
        responseAfterSend = null;
        port.close();
        listener.onStatus("closed");
    }

    private void fatal(String stageName, String message) {
        if (closed) return;
        closed = true;
        cancelAllTimers();
        clearWaitState();
        pending = null;
        responseAfterSend = null;
        port.close();
        listener.onFatal(stageName, message);
    }

    // ================================================================ helpers

    private void stage(String s) {
        stage = s;
        listener.onStatus(s);
    }

    private int nextSequence() {
        int v = requestSeq;
        requestSeq = (v + 1) & 0xFFFF;
        if (requestSeq == 0) requestSeq = 1;
        return v;
    }

    private static boolean opcodeMatch(byte[] pt, Pending p) {
        if (p.opcodes == null) return pt[1] == 0x20 && pt[0] != 0x0f && pt[0] != 0x0c;
        for (int i = 0; i + 1 < p.opcodes.length; i += 2) {
            if (pt[0] == (byte) p.opcodes[i] && pt[1] == (byte) p.opcodes[i + 1]) return true;
        }
        return false;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static List<byte[]> chunkBytes(byte[] data, int chunk) {
        List<byte[]> out = new ArrayList<>();
        if (data.length == 0) {
            out.add(new byte[0]);
            return out;
        }
        for (int i = 0; i < data.length; i += chunk) {
            out.add(MiotFraming.slice(data, i, Math.min(i + chunk, data.length)));
        }
        return out;
    }

    private static int le16(byte[] d, int off) {
        return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8);
    }

    /**
     * @param uuid Full UUID string, or null.
     * @return "0xNNNN" for a Bluetooth base UUID, the input for other UUIDs, or "?" for null.
     */
    static String shortUuid(String uuid) {
        if (uuid == null) return "?";
        return uuid.startsWith("0000") && uuid.endsWith("-0000-1000-8000-00805f9b34fb")
                ? "0x" + uuid.substring(4, 8) : uuid;
    }
}
