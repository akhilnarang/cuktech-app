package dev.akhilnarang.cuktech.proto;

import java.util.ArrayList;
import java.util.List;

/**
 * Encodes and parses MIOT property get and set frames in the siid=2 wire format.
 * Adapted from ha-cuk-ble (https://github.com/zuyan9/ha-cuk-ble), Apache-2.0
 * (lib/xiaomi/properties.py).
 *
 * <pre>
 * get request   33 20 <seq LE2> 02 <count> (<siid> <piid LE2>)*
 * get response  93/1c/0e 20 <seq LE2> .. <count> then typed entries WITH a
 *               2-byte status per entry
 * notification  0f 20 (telemetry) / 0c 20 flag 04 (setting echo): entries
 *               WITHOUT status
 * set request   0c 20 <seq LE2> 00 01 <siid> <piid LE2> <type> <marker> <value>
 * set response  0b 20 <seq LE2> 01 <count> (<siid> <piid LE2> <status LE2>)*
 *
 * </pre>
 * Multi-byte values are little-endian. Every parse checks lengths, counts, types and
 * trailing bytes. The class accepts no unchecked data. All methods are stateless.
 */
public final class MiotProperties {

    /** The frame does not have the expected format. */
    public static final class ParseException extends Exception {
        ParseException(String m) { super(m); }
    }

    /** One property entry from a response or a notification. Immutable. */
    public static final class PropValue {
        public final int siid;
        public final int piid;
        /** Status word of a get response (0 = ok). Always 0 for a notification. */
        public final int status;
        /** Value size in bytes: 0x01, 0x02 or 0x04. */
        public final int typeByte;
        /** Type marker byte, for example 0x00 bool, 0x10 u8, 0x30 u16, 0x50 u32. */
        public final int marker;
        /** Unsigned value. */
        public final long value;
        /** True if the type is 0x01 and the marker is 0x00. */
        public final boolean isBool;

        PropValue(int siid, int piid, int status, int typeByte, int marker, long value, boolean isBool) {
            this.siid = siid;
            this.piid = piid;
            this.status = status;
            this.typeByte = typeByte;
            this.marker = marker;
            this.value = value;
            this.isBool = isBool;
        }
    }

    private MiotProperties() {}

    // ------------------------------------------------------------- get

    /**
     * Encodes a get request.
     *
     * @param seq Sequence number. The low 16 bits are sent.
     * @param tuples {siid, piid} pairs, 1..255 items.
     * @return The plaintext request.
     * @throws IllegalArgumentException If the tuple count is out of range.
     */
    public static byte[] encodeGetProperties(int seq, int[][] tuples) {
        if (tuples == null || tuples.length == 0 || tuples.length > 255) {
            throw new IllegalArgumentException("1..255 tuples required");
        }
        byte[] body = new byte[6 + tuples.length * 3];
        body[0] = 0x33;
        body[1] = 0x20;
        body[2] = (byte) seq;
        body[3] = (byte) (seq >> 8);
        body[4] = 0x02;
        body[5] = (byte) tuples.length;
        int off = 6;
        for (int[] t : tuples) {
            body[off++] = (byte) t[0];
            body[off++] = (byte) t[1];
            body[off++] = (byte) (t[1] >> 8);
        }
        return body;
    }

    /**
     * Parses a get response. The known opcodes 0x93/0x1c/0x0e use the same body
     * layout, and the charger changes the opcode with the request shape. Thus, this
     * method parses any other {@code xx 20} frame that the caller matched by sequence
     * in the same way. It rejects only push frames (0f 20 telemetry, 0c 20 echo).
     *
     * @param pt Decrypted frame.
     * @return The entries, with status.
     * @throws ParseException If the header, an entry or the length is not valid.
     */
    public static List<PropValue> parseResponse(byte[] pt) throws ParseException {
        if (pt == null || pt.length < 6 || pt[1] != 0x20
                || pt[0] == 0x0f || pt[0] == 0x0c) {
            throw new ParseException("bad response header: " + hex6(pt));
        }
        return parseEntries(pt, pt[5] & 0xFF, true);
    }

    /**
     * Parses a telemetry push (0f 20) or a setting echo (0c 20 flag 04). These entries
     * have no status field.
     *
     * @param pt Decrypted frame.
     * @return The entries. Each status is 0.
     * @throws ParseException If the header, the flag, an entry or the length is not valid.
     */
    public static List<PropValue> parseNotification(byte[] pt) throws ParseException {
        if (pt == null || pt.length < 6 || pt[1] != 0x20
                || (pt[0] != 0x0f && pt[0] != 0x0c)) {
            throw new ParseException("bad notification header: " + hex6(pt));
        }
        if (pt[0] == 0x0c && pt[4] != 0x04) {
            throw new ParseException("0c 20 notification without event flag 04: " + hex6(pt));
        }
        return parseEntries(pt, pt[5] & 0xFF, false);
    }

    private static List<PropValue> parseEntries(byte[] pt, int count, boolean includesStatus)
            throws ParseException {
        List<PropValue> out = new ArrayList<>(count);
        int i = 6;
        for (int n = 0; n < count; n++) {
            int prefix = includesStatus ? 7 : 5;
            if (i + prefix > pt.length) {
                throw new ParseException("truncated property entry at offset " + i);
            }
            int siid = pt[i] & 0xFF;
            int piid = le16(pt, i + 1);
            int status = 0;
            int typeByte, marker, valueOffset;
            if (includesStatus) {
                status = le16(pt, i + 3);
                typeByte = pt[i + 5] & 0xFF;
                marker = pt[i + 6] & 0xFF;
                valueOffset = i + 7;
            } else {
                typeByte = pt[i + 3] & 0xFF;
                marker = pt[i + 4] & 0xFF;
                valueOffset = i + 5;
            }
            int size = sizeOf(typeByte);
            if (size < 0) {
                throw new ParseException("unknown type 0x" + Integer.toHexString(typeByte)
                        + " at offset " + i);
            }
            if (valueOffset + size > pt.length) {
                throw new ParseException("truncated property value at offset " + valueOffset);
            }
            long value = 0;
            for (int b = size - 1; b >= 0; b--) {
                value = (value << 8) | (pt[valueOffset + b] & 0xFF);
            }
            boolean isBool = typeByte == 0x01 && marker == 0x00;
            out.add(new PropValue(siid, piid, status, typeByte, marker, value, isBool));
            i = valueOffset + size;
        }
        if (i != pt.length) {
            throw new ParseException("unexpected trailing data: " + i + " != " + pt.length);
        }
        return out;
    }

    // ------------------------------------------------------------- set

    /**
     * Encodes a set request for a bool (type 0x01, marker 0x00).
     *
     * @param seq Sequence number. The low 16 bits are sent.
     * @param siid Service id.
     * @param piid Property id.
     * @param value New value.
     * @return The plaintext request.
     */
    public static byte[] encodeSetBool(int seq, int siid, int piid, boolean value) {
        return encodeSet(seq, siid, piid, 0x01, 0x00, value ? 1 : 0, 1);
    }

    /**
     * Encodes a set request for a u8 (type 0x01, marker 0x10).
     *
     * @param seq Sequence number. The low 16 bits are sent.
     * @param siid Service id.
     * @param piid Property id.
     * @param value New value, 0..255.
     * @return The plaintext request.
     * @throws IllegalArgumentException If the value is out of range.
     */
    public static byte[] encodeSetU8(int seq, int siid, int piid, int value) {
        if (value < 0 || value > 255) throw new IllegalArgumentException("u8 out of range");
        return encodeSet(seq, siid, piid, 0x01, 0x10, value, 1);
    }

    /**
     * Encodes a set request for a u16 (type 0x02, marker 0x30).
     *
     * @param seq Sequence number. The low 16 bits are sent.
     * @param siid Service id.
     * @param piid Property id.
     * @param value New value, 0..65535.
     * @return The plaintext request.
     * @throws IllegalArgumentException If the value is out of range.
     */
    public static byte[] encodeSetU16(int seq, int siid, int piid, int value) {
        if (value < 0 || value > 65535) throw new IllegalArgumentException("u16 out of range");
        return encodeSet(seq, siid, piid, 0x02, 0x30, value, 2);
    }

    /**
     * Encodes a set request for a u32 (type 0x04, marker 0x50).
     *
     * @param seq Sequence number. The low 16 bits are sent.
     * @param siid Service id.
     * @param piid Property id.
     * @param value New value, 0..0xffffffff.
     * @return The plaintext request.
     * @throws IllegalArgumentException If the value is out of range.
     */
    public static byte[] encodeSetU32(int seq, int siid, int piid, long value) {
        if (value < 0 || value > 0xffffffffL) throw new IllegalArgumentException("u32 out of range");
        return encodeSet(seq, siid, piid, 0x04, 0x50, value, 4);
    }

    private static byte[] encodeSet(int seq, int siid, int piid, int type, int marker,
                                    long value, int size) {
        // 6 header + siid(1) + piid(2) + type(1) + marker(1) + value(size)
        byte[] body = new byte[11 + size];
        body[0] = 0x0c;
        body[1] = 0x20;
        body[2] = (byte) seq;
        body[3] = (byte) (seq >> 8);
        body[4] = 0x00;
        body[5] = 0x01;
        body[6] = (byte) siid;
        body[7] = (byte) piid;
        body[8] = (byte) (piid >> 8);
        body[9] = (byte) type;
        body[10] = (byte) marker;
        for (int b = 0; b < size; b++) body[11 + b] = (byte) (value >>> (8 * b));
        return body;
    }

    /**
     * Parses a set response for exactly one property. Checks the count, the echoed
     * siid/piid and that there are no trailing bytes.
     *
     * @param pt Decrypted 11-byte frame.
     * @param siid Expected service id.
     * @param piid Expected property id.
     * @return The status word (0 = ok).
     * @throws ParseException If the frame is not valid or is for a different property.
     */
    public static int parseSetResponse(byte[] pt, int siid, int piid) throws ParseException {
        if (pt == null || pt.length < 6 || pt[0] != 0x0b || pt[1] != 0x20 || pt[4] != 0x01) {
            throw new ParseException("bad set-response header: " + hex6(pt));
        }
        int count = pt[5] & 0xFF;
        if (count != 1) throw new ParseException("expected exactly 1 result, got " + count);
        if (pt.length != 11) throw new ParseException("truncated or padded set-response: length " + pt.length);
        int rSiid = pt[6] & 0xFF;
        int rPiid = le16(pt, 7);
        if (rSiid != siid || rPiid != piid) {
            throw new ParseException("result for siid=" + rSiid + " piid=0x"
                    + Integer.toHexString(rPiid) + ", expected siid=" + siid + " piid=0x"
                    + Integer.toHexString(piid));
        }
        return le16(pt, 9);
    }

    // ------------------------------------------------------------- helpers

    private static int sizeOf(int typeByte) {
        switch (typeByte) {
            case 0x01: return 1;
            case 0x02: return 2;
            case 0x04: return 4;
            default: return -1;
        }
    }

    private static int le16(byte[] d, int off) {
        return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8);
    }

    private static String hex6(byte[] pt) {
        if (pt == null) return "null";
        int n = Math.min(6, pt.length);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", pt[i] & 0xFF));
        return sb.toString();
    }
}
