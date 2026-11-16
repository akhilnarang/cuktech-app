package dev.akhilnarang.cuktech.proto;

import java.util.Locale;

/**
 * Decodes the negotiated protocol from MIOT 2.17 (C1/C2) and 2.18 (C3/A). This is
 * separate from the power-cap byte in the port telemetry. Immutable.
 */
public final class PortProtocol {
    /** Protocol code (high byte of the 16-bit half). 0 = not reported. */
    public final int code;
    /** Detail byte (low byte). For PD and PPS on C1/C2 it is the cap in W. */
    public final int detail;
    /** Display label. It can include "· cap N W". */
    public final String label;
    /** Code and detail as "cc·dd" hex. */
    public final String raw;
    /** Literal display name in the official AD1204 plugin v60, if mapped. */
    public final String vendorLabel;

    private PortProtocol(int code, int detail, String label, String vendorLabel) {
        this.code = code;
        this.detail = detail;
        this.label = label;
        this.vendorLabel = vendorLabel;
        this.raw = String.format(Locale.US, "%02x·%02x", code, detail);
    }

    /**
     * Decodes the protocol of one port. Even ports (C1, C3) use bits 16..31, odd ports
     * (C2, A) use bits 0..15.
     *
     * @param port Port index 0..3.
     * @param value Unsigned 32-bit property word.
     * @return The decoded protocol.
     * @throws IllegalArgumentException If the port or the value is out of range.
     */
    public static PortProtocol decode(int port, long value) {
        if (port < 0 || port > 3 || value < 0 || value > 0xffffffffL)
            throw new IllegalArgumentException("invalid port protocol word");
        int shift = port % 2 == 0 ? 16 : 0;
        int half = (int) ((value >>> shift) & 0xffff);
        int code = half >>> 8;
        int detail = half & 0xff;
        String vendorLabel = vendorLabel(code);
        String label;
        if (code == 0) label = "Protocol not reported";
        else if (port < 2 && code == 7) label = "PD Fixed";
        else if (port < 2 && code == 8) label = "PD PPS";
        // Tentative alias: Xiaomi/PPS-like firmware paths support
        // miPPS, while the official plugin calls 09 PPS. Neither is a wire capture.
        else if (port < 2 && code == 9) label = "miPPS (likely)";
        // Official shared renderer says 5V; an upstream USB-A experiment says QC.
        else if (port == 3 && code == 2) label = "5V / QC (unresolved)";
        else if (vendorLabel != null) label = vendorLabel;
        else label = "Protocol not identified";
        // Controlled upstream SINK240 sweeps corroborate cap watts for 07/08;
        // firmware consumes this byte as ProtocolPower. It is not output watts,
        // a decoded PDO/APDO, or a meaning established for other protocol codes.
        // Vendor names: docs/firmware/mihome-charger-plugin.md, MainPage module
        // 10010. These are displayed labels, not independent negotiation proof.
        if (port < 2 && (code == 7 || code == 8) && detail > 0)
            label += " · cap " + detail + " W";
        return new PortProtocol(code, detail, label, vendorLabel);
    }

    private static String vendorLabel(int code) {
        switch (code) {
            case 1: case 2: return "5V";
            case 3: return "QC";
            case 4: return "AFC";
            case 5: return "FCP";
            case 6: return "SCP";
            case 7: return "PD";
            case 8: case 9: return "PPS";
            case 10: return "UFCS";
            default: return null;
        }
    }
}
