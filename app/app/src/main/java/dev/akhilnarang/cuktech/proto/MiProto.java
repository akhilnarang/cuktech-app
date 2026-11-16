package dev.akhilnarang.cuktech.proto;

/**
 * Wire constants for the AD1204U Mi BLE login and the MIOT transport. Adapted from
 * ha-cuk-ble (https://github.com/zuyan9/ha-cuk-ble), Apache-2.0
 * (lib/xiaomi/protocol.py, docs/protocol.md).
 *
 * <p>GATT characteristics. All are in the FE95 service. Find them by UUID, never by handle.
 * <pre>
 *   0x0010 "UPNP"  auth control   — write commands, notify confirmations
 *   0x0019 "AVDTP" auth parcels   — write parcels, notify announcements/parcels
 *   0x001a          MIOT write    — encrypted requests; RCV_RDY/RCV_OK notify
 *   0x001b          MIOT notify   — encrypted responses + telemetry pushes
 * </pre>
 *
 * <p>This class has only the LOGIN path. The register (bind) flow is in the bind/
 * package. Do not change the arrays.
 */
public final class MiProto {
    private MiProto() {}

    public static final String UPNP_UUID  = "00000010-0000-1000-8000-00805f9b34fb";
    public static final String AVDTP_UUID = "00000019-0000-1000-8000-00805f9b34fb";
    public static final String MIOT_WRITE_UUID  = "0000001a-0000-1000-8000-00805f9b34fb";
    public static final String MIOT_NOTIFY_UUID = "0000001b-0000-1000-8000-00805f9b34fb";
    /** Characteristic 0x0004 with the firmware version string. */
    public static final String FIRMWARE_VERSION_UUID = "00000004-0000-1000-8000-00805f9b34fb";

    // UPNP commands (host → device control channel)
    public static final byte[] CMD_LOGIN = {0x24, 0, 0, 0};
    public static final byte[] GREETING_TRIGGER = {(byte) 0xa4};

    // AVDTP announcements for the login handshake (host → device)
    public static final byte[] CMD_SEND_KEY  = {0, 0, 0, 0x0b, 1, 0}; // send 16-byte rand
    public static final byte[] CMD_SEND_INFO = {0, 0, 0, 0x0a, 2, 0}; // send 32-byte HMAC

    // Control frames
    public static final byte[] RCV_RDY = {0, 0, 1, 1};
    public static final byte[] RCV_OK  = {0, 0, 1, 0};
    public static final byte[] OFFICIAL_ACK = {0, 0, 3, 0};

    // UPNP confirmations (device → host)
    public static final byte[] CFM_LOGIN_OK  = {0x21, 0, 0, 0};
    public static final byte[] CFM_LOGIN_ERR = {0x23, 0, 0, 0};

    // ---------------------------------------------------------------- MIOT properties (siid=2)

    /** MIOT service id of all charger properties. */
    public static final int SIID = 2;

    /**
     * Bulk-read set: the DEFAULT_READ_TUPLES of ha-cuk-ble, unchanged. They are
     * verified on hardware. The charger selects the response opcode from the request
     * shape. A smaller 8-tuple read got no reply on hardware (2026-10-12).
     * Each item is {siid, piid}.
     */
    public static final int[][] BULK_TUPLES = {
            {SIID, 1}, {SIID, 2}, {SIID, 3}, {SIID, 4},       // port C1/C2/C3/A (u32)
            {SIID, 0x05}, {SIID, 0x06}, {SIID, 0x07},        // scene_mode, screen_save_time, protocol_ctl
            {SIID, 0x0d},                                    // device_language
            {SIID, 0x0f},                                    // usb_a_always_on (bool)
            {SIID, 0x10},                                    // port_ctl
            {SIID, 0x11}, {SIID, 0x12},                      // c1c2/c3a protocol (u32)
            {SIID, 0x13}, {SIID, 0x14},                      // screenoff_while_idle, screen_dir_lock (bool)
            {SIID, 0x15},                                    // protocol_ctl_extend (u32)
    };

    // piid values in siid 2.
    public static final int PIID_SCENE_MODE = 0x05;
    public static final int PIID_SCREEN_SAVE_TIME = 0x06;
    public static final int PIID_COUNTDOWN_C1 = 0x09;
    public static final int PIID_DEVICE_LANGUAGE = 0x0d;
    public static final int PIID_PORT_CTL = 0x10;
    public static final int PIID_USB_A_ALWAYS_ON = 0x0f;
    public static final int PIID_SCREEN_OFF_IDLE = 0x13;
    public static final int PIID_SCREEN_DIR_LOCK = 0x14;
    public static final int PIID_PROTOCOL_CTL_EXTEND = 0x15;

    /**
     * scene_mode labels by UI index. Reverse-engineered from a Mi Home tablet capture
     * (ha-cuk-ble select.py).
     */
    public static final String[] SCENE_MODES = {"AI", "Apple", "Single", "Balance"};
    /**
     * @param index Index in {@link #SCENE_MODES}.
     * @return The scene_mode wire value (index + 1).
     */
    public static int sceneModeValue(int index) { return index + 1; }
    /**
     * @param value scene_mode wire value.
     * @return The index in {@link #SCENE_MODES} (value - 1). The caller checks the range.
     */
    public static int sceneModeIndex(int value) { return value - 1; }
}
