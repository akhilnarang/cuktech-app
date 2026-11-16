package dev.akhilnarang.cuktech.proto;

import java.util.ArrayList;
import java.util.List;

/**
 * MIOT GATT transport framing for the outbound side. MiController parses inbound
 * frames itself. Adapted from ha-cuk-ble
 * (https://github.com/zuyan9/ha-cuk-ble), Apache-2.0.
 *
 * <p>Write on UUID 0x001a, notify on 0x001b:
 * <pre>
 *   announcement    00 00 00 00 NN NN   (NN NN = parcel count LE16)
 *   RCV_RDY 00 00 01 01   RCV_OK 00 00 01 00   ACK 00 00 03 00
 *   inline frame    00 00 02 00 CC CC <ct>  (CC CC = 16-bit LE counter)
 *   outbound parcel (host→device): idx LE16 + counter LE16 + chunk on EVERY
 *                   parcel. This is how the session.py client sends them (tested on hardware).
 *   inbound parcel  (device→host): idx + counter + chunk on parcel 1,
 *                   idx + chunk on parcels 2+ (strip-4 / strip-2 rule)
 *   nonce           IV(4) + 00000000 + counter(4 LE) = 12 bytes
 * </pre>
 */
public final class MiotFraming {

    /** Maximum parcels in one transfer. */
    public static final int MAX_PARCELS = 64;
    /** Maximum value of the 16-bit message counter. */
    public static final int MAX_COUNTER = 0xFFFF;
    /** Ciphertext bytes in one outbound parcel. */
    public static final int PARCEL_CHUNK_SIZE = 18;

    private static final byte[] EMPTY = new byte[0];

    /**
     * Builds a parcel announcement: 00 00 00 code count_lo count_hi.
     *
     * @param code Announcement code 0..255.
     * @param parcelCount Number of parcels that follow, 1..{@link #MAX_PARCELS}.
     * @return A 6-byte frame.
     * @throws IllegalArgumentException If a value is out of range.
     */
    public static byte[] announcement(int code, int parcelCount) {
        if (code < 0 || code > 0xFF || parcelCount < 1 || parcelCount > MAX_PARCELS) {
            throw new IllegalArgumentException(
                    "bad announcement code=" + code + " parcels=" + parcelCount);
        }
        return new byte[]{0, 0, 0, (byte) code, (byte) parcelCount, (byte) (parcelCount >> 8)};
    }

    /** @return A new RCV_RDY frame, 00 00 01 01. */
    public static byte[] rcvRdy() { return new byte[]{0, 0, 1, 1}; }
    /** @return A new RCV_OK frame, 00 00 01 00. */
    public static byte[] rcvOk() { return new byte[]{0, 0, 1, 0}; }
    /** @return A new ACK frame, 00 00 03 00. */
    public static byte[] ack() { return new byte[]{0, 0, 3, 0}; }

    /**
     * Splits ciphertext into outbound MIOT parcels. Each frame has idx LE16, counter LE16
     * and a chunk (as session.py). Empty ciphertext gives one frame with no chunk.
     *
     * @param counter Message counter, 0..{@link #MAX_COUNTER}.
     * @param ciphertext Encrypted request. Must not be null.
     * @param payloadCap Maximum chunk length in bytes, 1 or more.
     * @return The frames, with idx starting at 1.
     * @throws IllegalArgumentException If a value is out of range, or the data needs more
     *         than {@link #MAX_PARCELS} parcels.
     */
    public static List<byte[]> outboundParcels(int counter, byte[] ciphertext, int payloadCap) {
        if (counter < 0 || counter > MAX_COUNTER) {
            throw new IllegalArgumentException("counter out of range: " + counter);
        }
        if (ciphertext == null) throw new IllegalArgumentException("ciphertext required");
        if (payloadCap < 1) throw new IllegalArgumentException("payloadCap must be positive");
        List<byte[]> chunks = new ArrayList<>();
        if (ciphertext.length == 0) {
            chunks.add(EMPTY);
        } else {
            for (int i = 0; i < ciphertext.length; i += payloadCap) {
                chunks.add(slice(ciphertext, i, Math.min(i + payloadCap, ciphertext.length)));
            }
        }
        if (chunks.size() > MAX_PARCELS) {
            throw new IllegalArgumentException(
                    "needs " + chunks.size() + " parcels; max " + MAX_PARCELS);
        }
        List<byte[]> frames = new ArrayList<>(chunks.size());
        for (int i = 0; i < chunks.size(); i++) {
            int idx = i + 1;
            byte[] chunk = chunks.get(i);
            byte[] frame = new byte[4 + chunk.length];
            frame[0] = (byte) idx;
            frame[1] = (byte) (idx >> 8);
            frame[2] = (byte) counter;
            frame[3] = (byte) (counter >> 8);
            System.arraycopy(chunk, 0, frame, 4, chunk.length);
            frames.add(frame);
        }
        return frames;
    }

    /**
     * Builds the MIOT nonce: IV(4) + 4 zero bytes + counter(4 LE) = 12 bytes.
     *
     * @param iv 4-byte IV from the session keys.
     * @param counter Message counter, 0..{@link #MAX_COUNTER}.
     * @return A 12-byte nonce.
     * @throws IllegalArgumentException If the IV is not 4 bytes or the counter is out of range.
     */
    public static byte[] nonce(byte[] iv, int counter) {
        if (iv == null || iv.length != 4) {
            throw new IllegalArgumentException("iv must be 4 bytes");
        }
        if (counter < 0 || counter > MAX_COUNTER) {
            throw new IllegalArgumentException("counter out of range: " + counter);
        }
        return new byte[]{iv[0], iv[1], iv[2], iv[3], 0, 0, 0, 0,
                (byte) counter, (byte) (counter >> 8), 0, 0};
    }

    // ------------------------------------------------------------- helpers

    static byte[] slice(byte[] data, int from, int to) {
        byte[] out = new byte[Math.max(0, to - from)];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }

    /**
     * @param bytes Bytes to encode, or null.
     * @return Lowercase hex, or "" for null.
     */
    public static String hex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}
