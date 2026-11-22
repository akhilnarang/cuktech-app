package dev.akhilnarang.cuktech.proto;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Builds and decodes the small set of AD1204 0073 diagnostic queries that the app uses.
 * Frames go on the vendor service 0xAF00: requests on 0xAF07, replies on 0xAF08.
 * Each frame starts with fe dc ba 01 f1 and a reply ends with ef.
 * See docs/firmware/findings-telemetry.md. All methods are stateless.
 */
public final class VendorStatus {
    /** Vendor GATT service 0xAF00. */
    public static final String SERVICE_UUID = "0000af00-0000-1000-8000-00805f9b34fb";
    /** Characteristic 0xAF07 for requests. */
    public static final String WRITE_UUID = "0000af07-0000-1000-8000-00805f9b34fb";
    /** Characteristic 0xAF08 for replies. */
    public static final String NOTIFY_UUID = "0000af08-0000-1000-8000-00805f9b34fb";

    private VendorStatus() {}

    /**
     * Builds a status request.
     *
     * @param selector 1 = controller versions, 2 = sensors and power state,
     *        6 = charging controllers.
     * @return A 9-byte request frame. The last byte is padding: firmware 2.1.2_0079 drops
     *         writes shorter than 9 bytes, and 2.1.2_0073 ignores the 9th byte for these selectors.
     * @throws IllegalArgumentException If the selector is not 1, 2 or 6.
     */
    public static byte[] statusRequest(int selector) {
        if (selector != 1 && selector != 2 && selector != 6)
            throw new IllegalArgumentException("unsupported diagnostic selector");
        return new byte[]{(byte)0xfe, (byte)0xdc, (byte)0xba, 1, (byte)0xf1, 0, 1, (byte)selector, 0};
    }

    /**
     * Builds the request that sets the holiday startup artwork (selector 9).
     *
     * @param enabled True to show the holiday artwork at startup.
     * @return A 9-byte request frame.
     */
    public static byte[] holidayRequest(boolean enabled) {
        return new byte[]{(byte)0xfe, (byte)0xdc, (byte)0xba, 1, (byte)0xf1, 0, 1, 9, (byte)(enabled ? 1 : 0)};
    }

    /** One decoded diagnostic reply. Immutable. */
    public static final class Reading {
        /** Selector of the reply: 1, 2, 6 or 9. */
        public final int selector;
        /** Section title for the UI. */
        public final String title;
        /** Field label to display text, in display order. Unmodifiable. */
        public final Map<String,String> fields;
        /** Full reply frame as lowercase hex. */
        public final String rawHex;
        /** Holiday artwork flag from selector 2 or 9, or null if not known. */
        public final Boolean holidayArtwork;
        /** Sensor values for selector 2, else null. */
        public final ThermalReading thermal;
        private Reading(int selector, String title, Map<String,String> fields, byte[] frame) {
            this.selector = selector;
            this.title = title;
            this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
            StringBuilder raw = new StringBuilder();
            for (byte b : frame) raw.append(String.format(Locale.US, "%02x", b & 255));
            this.rawHex = raw.toString();
            int flag = selector == 2 ? frame[16]&255 : selector == 9 ? frame[7]&255 : 255;
            this.holidayArtwork = flag <= 1 ? flag == 1 : null;
            this.thermal = selector == 2 ? new ThermalReading(frame) : null;
        }
    }

    /**
     * Values from one validated selector-2 sensor reply. The class does not infer a
     * thermal stage.
     */
    public static final class ThermalReading {
        /**
         * Raw bytes: shell NTC2 (byte 7), protection NTC1 (byte 13), MCU low byte (byte 8),
         * AC sense ADC proxy in mV (bytes 9-10 LE, not mains volts), rail state (byte 11),
         * PFC flag (byte 12).
         */
        public final int shellRaw, protectionRaw, mcuLowByte, acProxyMv, railState, pfcFlag;
        /** Experimental temperature in degrees C, or null if the raw value is outside 24..124. */
        public final Integer shellEstimateC, protectionEstimateC;
        private ThermalReading(byte[] frame) {
            shellRaw = frame[7] & 255;
            protectionRaw = frame[13] & 255;
            mcuLowByte = frame[8] & 255;
            acProxyMv = le16(frame, 9);
            railState = frame[11] & 255;
            pfcFlag = frame[12] & 255;
            shellEstimateC = ntcEstimate(shellRaw);
            protectionEstimateC = ntcEstimate(protectionRaw);
        }
        /** @return Rail voltage text: "9 V", "16 V", "22 V", or "Unknown" with the hex value. */
        public String railText() { return railState == 0 ? "9 V" : railState == 1 ? "16 V" : railState == 2 ? "22 V" : "Unknown · " + hex(railState); }
        /** @return "Low", "High", or "Unknown" with the hex value. */
        public String pfcText() { return pfcFlag == 0 ? "Low" : pfcFlag == 1 ? "High" : "Unknown · " + hex(pfcFlag); }
        /** @return The MCU low byte as decimal and hex. The unit is not confirmed. */
        public String mcuText() { return mcuLowByte + " · " + hex(mcuLowByte); }
    }

    /**
     * Validates and decodes a status reply.
     *
     * @param frame Reply frame: 21 bytes for selector 1, 9 bytes for 9, 18 bytes for 2 and 6.
     * @param selector Selector of the request: 1, 2, 6 or 9.
     * @return The decoded reading.
     * @throws IllegalArgumentException If the selector is not supported, or the frame
     *         length, header, selector echo or terminator is wrong.
     */
    public static Reading decodeStatus(byte[] frame, int selector) {
        if (selector != 1 && selector != 2 && selector != 6 && selector != 9)
            throw new IllegalArgumentException("unsupported diagnostic selector");
        int length = selector == 1 ? 21 : selector == 9 ? 9 : 18;
        if (frame == null || frame.length != length ||
                (frame[0] & 255) != 0xfe || (frame[1] & 255) != 0xdc ||
                (frame[2] & 255) != 0xba || frame[3] != 1 ||
                (frame[4] & 255) != 0xf1 || (frame[5] & 255) != selector ||
                (frame[length-1] & 255) != 0xef || (selector != 1 && frame[6] != (selector == 9 ? 1 : 10)))
            throw new IllegalArgumentException("unexpected diagnostic status reply");
        Map<String,String> fields = new LinkedHashMap<>();
        String title;
        if (selector == 2) {
            title = "Internal sensors and power state";
            fields.put("NTC2 · shell input", temperatureText(frame[7] & 255));
            fields.put("NTC1 · protection input", temperatureText(frame[13] & 255));
            fields.put("AC sense ADC proxy", le16(frame, 9) + " mV (not mains volts)");
            int rail = frame[11] & 255;
            fields.put("Power rail state", rail == 0 ? "9 V" : rail == 1 ? "16 V" : rail == 2 ? "22 V" : hex(rail));
            fields.put("PFC high state", flag(frame[12] & 255));
            fields.put("Global hardware flag", flag(frame[15] & 255));
            fields.put("Default settings + unbound", flag(frame[14] & 255));
            fields.put("ADC diagnostic byte", hex(frame[8] & 255));
            fields.put("MCU temperature candidate", (frame[8] & 255) + " (low byte; units unconfirmed)");
            fields.put("Holiday startup artwork", flag(frame[16] & 255));
        } else if (selector == 6) {
            title = "Charging controllers";
            for (int port = 0; port < 4; port++) {
                int cap = frame[7+port] & 255;
                fields.put(PortTelemetry.PORTS[port] + " allocation", PortTelemetry.capDescription(port, cap) + " · " + hex(cap));
            }
            for (int port = 0; port < 2; port++) {
                int offset = 11+2*port;
                long pair = ((frame[offset] & 255) << 8) | (frame[offset+1] & 255);
                PortProtocol protocol = PortProtocol.decode(port, port == 0 ? pair << 16 : pair);
                fields.put(PortTelemetry.PORTS[port] + " native protocol", protocol.label + " · " + protocol.raw);
            }
            fields.put("C3 native SC2021 code", hex(frame[15] & 255));
            fields.put("USB-A native SC2021 code", hex(frame[16] & 255));
        } else if (selector == 1) {
            title = "Controller versions";
            fields.put("Firmware revision", word(le16(frame, 6)));
            fields.put("Boot-record image CRC", word(le16(frame, 8)));
            fields.put("SC2021 software version", versionWord(le16(frame, 10)));
            fields.put("C1 version words", versionWord(le16(frame, 12)) + " / " + versionWord(le16(frame, 14)));
            fields.put("C2 version words", versionWord(le16(frame, 16)) + " / " + versionWord(le16(frame, 18)));
        } else {
            title = "Startup artwork";
            fields.put("Holiday startup artwork", flag(frame[7] & 255));
        }
        return new Reading(selector, title, fields, frame);
    }

    private static int le16(byte[] frame, int offset) { return (frame[offset]&255) | ((frame[offset+1]&255)<<8); }
    private static String hex(int value) { return String.format(Locale.US, "0x%02x", value); }
    private static String word(int value) { return String.format(Locale.US, "0x%04x", value); }
    private static String versionWord(int value) { return value == 0 || value == 0xffff ? "Unavailable (" + word(value) + ")" : word(value); }
    private static String flag(int value) { return value == 0 ? "Clear" : value == 1 ? "Set" : hex(value); }
    private static String temperatureText(int value) {
        return ntcEstimate(value) != null ? value + " °C (experimental)" : "Unavailable · " + hex(value);
    }
    // Only 24..124 is a mapped NTC value. Other values mean the sensor is not ready.
    private static Integer ntcEstimate(int value) { return value >= 24 && value <= 124 ? value : null; }

    /**
     * Validates a selector-2 reply and returns the shell temperature.
     *
     * @param frame 18-byte reply frame.
     * @return Converted, filtered NTC reading in degrees C, range 24..124.
     * @throws IllegalArgumentException If the frame is not a valid selector-2 reply, or
     *         the value is outside 24..124 (sensor not ready).
     */
    public static int decodeTemperature(byte[] frame) {
        // 3-byte envelope + 14-byte status payload + terminator.
        if (frame == null || frame.length != 18 ||
                (frame[0] & 255) != 0xfe || (frame[1] & 255) != 0xdc ||
                (frame[2] & 255) != 0xba || frame[3] != 1 ||
                (frame[4] & 255) != 0xf1 || frame[5] != 2 || frame[6] != 10 ||
                (frame[17] & 255) != 0xef)
            throw new IllegalArgumentException("unexpected temperature status reply");
        int raw = frame[7] & 255; // RAM 0x2000ceb0: converted, filtered NTC reading.
        if (raw < 24 || raw > 124)
            throw new IllegalArgumentException("temperature sensor not ready or outside mapped range");
        return raw;
    }
}
