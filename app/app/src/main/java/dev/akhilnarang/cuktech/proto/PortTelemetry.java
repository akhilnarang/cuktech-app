package dev.akhilnarang.cuktech.proto;

import java.util.HashMap;
import java.util.Map;

/**
 * Decodes AD1204U telemetry for each port. Adapted from ha-cuk-ble
 * (https://github.com/zuyan9/ha-cuk-ble), Apache-2.0 (lib/ports.py).
 * Each port has one u32 (siid=2 piid=1..4) with these bytes:
 * <pre>
 *   b0 = status flags. Bit 0 shows active output. The other bits do not show activity.
 *   b1 = power cap that the charger gave this port (firmware cap code, not the protocol;
 *        see docs/firmware/findings-phone.md)
 *   b2 = current in deciamps (A * 10)
 *   b3 = voltage in decivolts (V * 10)
 * </pre>
 * Verified upstream with 15+ datapoints from 0.5 W to 100 W and 5 V to 20 V.
 */
public final class PortTelemetry {

    /** Port names by port index 0..3. */
    public static final String[] PORTS = {"C1", "C2", "C3", "A"};
    /** piid for each port index. */
    public static final int[] PORT_PIIDS = {1, 2, 3, 4};

    /** Cap code -> watts: 0x01..0x0b for C1/C2, 0x10..0xa0 for C3/A (fw 0x4093a2 / 0x4092e0). */
    private static final Map<Integer, String> CAP_WATTS = new HashMap<>();
    static {
        String[][] caps = {
            {"01", "22.5"}, {"02", "33"}, {"03", "45"}, {"04", "55"}, {"05", "60"}, {"06", "65"},
            {"07", "70"}, {"08", "80"}, {"09", "90"}, {"0a", "100"}, {"0b", "120"},
            {"10", "7.5"}, {"20", "10"}, {"30", "12"}, {"40", "15"}, {"50", "18"}, {"60", "22.5"},
            {"70", "33"}, {"80", "45"}, {"90", "24"}, {"a0", "7.5"},
        };
        for (String[] c : caps) CAP_WATTS.put(Integer.parseInt(c[0], 16), c[1]);
    }

    /** One decoded port word. Immutable. */
    public static final class Port {
        /** Port name from {@link #PORTS}. */
        public final String name;
        /** The raw u32 word. */
        public final long raw;
        /** True if status bit 0 (active output) is set. */
        public final boolean inUse;
        /** Firmware cap code (byte b1). */
        public final int capCode;
        /** Cap text, for example "max 120 W" or "cap 0x2c". "idle" if the port is not in use. */
        public final String cap;
        /** Output voltage in V, resolution 0.1 V. */
        public final double voltageV;
        /** Output current in A, resolution 0.1 A. */
        public final double currentA;
        /** Voltage times current in W, rounded to 0.01 W. */
        public final double powerW;

        Port(String name, long raw, boolean inUse, int capCode, String cap,
             double voltageV, double currentA, double powerW) {
            this.name = name;
            this.raw = raw;
            this.inUse = inUse;
            this.capCode = capCode;
            this.cap = cap;
            this.voltageV = voltageV;
            this.currentA = currentA;
            this.powerW = powerW;
        }
    }

    private PortTelemetry() {}

    /**
     * Changes a cap code to display text. C1/C2 use codes 0x01..0x0b. C3/A use codes
     * 0x10..0xa0 in steps of 0x10.
     *
     * @param port Port index 0..3.
     * @param code Cap code 0..255.
     * @return "max N W", "Disabled / no allocation" for code 0, or "Unmapped cap".
     * @throws IllegalArgumentException If the port or the code is out of range.
     */
    public static String capDescription(int port, int code) {
        if (port < 0 || port > 3 || code < 0 || code > 255) throw new IllegalArgumentException("cap code");
        // Controller code spaces differ; do not apply C1/C2 codes to C3/A.
        boolean namespace = port < 2 ? code >= 1 && code <= 11 : code >= 0x10 && code <= 0xa0 && (code & 15) == 0;
        String watts = namespace ? CAP_WATTS.get(code) : null;
        return code == 0 ? "Disabled / no allocation" : watts != null ? "max " + watts + " W" : "Unmapped cap";
    }

    /**
     * Decodes one port word.
     *
     * @param portIndex Port index 0..3.
     * @param value Unsigned 32-bit port word.
     * @return The decoded port.
     * @throws IllegalArgumentException If the index or the value is out of range.
     */
    public static Port decode(int portIndex, long value) {
        if (portIndex < 0 || portIndex >= PORTS.length) {
            throw new IllegalArgumentException("port index " + portIndex);
        }
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("value out of uint32 range");
        }
        int b0 = (int) (value & 0xFF);
        int b1 = (int) ((value >> 8) & 0xFF);
        int b2 = (int) ((value >> 16) & 0xFF);
        int b3 = (int) ((value >> 24) & 0xFF);
        double voltage = b3 / 10.0;
        double current = b2 / 10.0;
        // Firmware UI 0x4065c8 tests status bit 0 separately from 0x1fc
        // protection/state bits. Nonzero flags alone do not mean output is active.
        boolean inUse = (b0 & 1) != 0;
        String allocation = capDescription(portIndex, b1);
        String cap = !inUse ? "idle" : allocation.equals("Unmapped cap")
                ? String.format("cap 0x%02x", b1) : allocation;
        return new Port(PORTS[portIndex], value, inUse, b1, cap,
                voltage, current, Math.round(voltage * current * 100.0) / 100.0);
    }
}
