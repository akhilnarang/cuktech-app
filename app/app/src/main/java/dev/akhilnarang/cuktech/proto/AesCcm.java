package dev.akhilnarang.cuktech.proto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * Minimal standalone AES-CCM (RFC 3610) with a 12-byte nonce. It uses only the
 * "AES/ECB/NoPadding" JCA cipher, which is always available.
 *
 * <p>The JCA "AES/CCM/NoPadding" provider is not available on all OEM builds and
 * API levels. Thus, this class does the CCM construction itself: CBC-MAC + CTR per
 * RFC 3610 with L=3. MIOT uses tag length 4, a 12-byte nonce and empty AAD.
 *
 * <p>An instance holds one AES cipher and is not thread-safe.
 */
public final class AesCcm {

    /** Thrown if a decrypted frame fails the tag check. Callers must never ignore it. */
    public static final class BadTagException extends Exception {
        BadTagException(String m) { super(m); }
    }

    private final Cipher aes;
    private final int tagLen;

    /**
     * @param key16 16-byte AES key.
     * @param tagLen Tag length in bytes: an even number, 4..16.
     * @throws IllegalArgumentException If the key or the tag length is not valid.
     * @throws IllegalStateException If the platform has no AES/ECB cipher.
     */
    public AesCcm(byte[] key16, int tagLen) {
        if (key16 == null || key16.length != 16) {
            throw new IllegalArgumentException("CCM key must be 16 bytes");
        }
        if (tagLen < 4 || tagLen > 16 || tagLen % 2 != 0) {
            throw new IllegalArgumentException("tag length must be even, 4..16");
        }
        try {
            aes = Cipher.getInstance("AES/ECB/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/ECB unavailable", e);
        }
        this.tagLen = tagLen;
    }

    /**
     * Encrypts and authenticates.
     *
     * @param nonce12 12-byte nonce. Do not use the same nonce two times with one key.
     * @param plaintext Data to encrypt.
     * @param aad Additional authenticated data, or null or empty for none.
     * @return ciphertext || tag (tagLen bytes).
     * @throws IllegalArgumentException If the nonce is not 12 bytes.
     */
    public byte[] encrypt(byte[] nonce12, byte[] plaintext, byte[] aad) {
        checkNonce(nonce12);
        byte[] mac = cbcMac(nonce12, plaintext, aad);
        byte[] ct = ctr(nonce12, plaintext, 1);
        byte[] s0 = ctr(nonce12, new byte[tagLen], 0);
        byte[] out = new byte[ct.length + tagLen];
        System.arraycopy(ct, 0, out, 0, ct.length);
        for (int i = 0; i < tagLen; i++) out[ct.length + i] = (byte) (mac[i] ^ s0[i]);
        return out;
    }

    /**
     * Checks the tag and decrypts. The tag check is constant-time.
     *
     * @param nonce12 12-byte nonce.
     * @param ctAndTag ciphertext || tag.
     * @param aad Additional authenticated data, or null or empty for none.
     * @return The plaintext.
     * @throws IllegalArgumentException If the nonce is not 12 bytes.
     * @throws BadTagException If the input is shorter than the tag or the tag is wrong.
     *         Callers must treat this as fatal for the session (key desync or tampering).
     */
    public byte[] decrypt(byte[] nonce12, byte[] ctAndTag, byte[] aad) throws BadTagException {
        checkNonce(nonce12);
        if (ctAndTag == null || ctAndTag.length < tagLen) {
            throw new BadTagException("ciphertext shorter than tag");
        }
        int ctLen = ctAndTag.length - tagLen;
        byte[] ct = new byte[ctLen];
        System.arraycopy(ctAndTag, 0, ct, 0, ctLen);
        byte[] tag = new byte[tagLen];
        System.arraycopy(ctAndTag, ctLen, tag, 0, tagLen);
        byte[] pt = ctr(nonce12, ct, 1);
        byte[] mac = cbcMac(nonce12, pt, aad);
        byte[] s0 = ctr(nonce12, new byte[tagLen], 0);
        int diff = 0;
        for (int i = 0; i < tagLen; i++) diff |= (mac[i] ^ s0[i]) ^ tag[i];
        if (diff != 0) throw new BadTagException("authentication failed");
        return pt;
    }

    // ------------------------------------------------------------- RFC 3610 internals (N=12, L=3)

    private static void checkNonce(byte[] n) {
        if (n == null || n.length != 12) {
            throw new IllegalArgumentException("CCM nonce must be 12 bytes");
        }
    }

    private byte[] cbcMac(byte[] nonce12, byte[] msg, byte[] aad) {
        boolean hasAad = aad != null && aad.length > 0;
        int flags = (hasAad ? 0x40 : 0) | (((tagLen - 2) / 2) << 3) | 2;
        byte[] x = new byte[16];
        x[0] = (byte) flags;
        System.arraycopy(nonce12, 0, x, 1, 12);
        x[13] = (byte) (msg.length >>> 16);
        x[14] = (byte) (msg.length >>> 8);
        x[15] = (byte) msg.length;
        x = block(x);
        if (hasAad) {
            // aad length header: 2-byte BE (aad.length < 0xFF00 always here)
            byte[] a = new byte[2 + aad.length];
            a[0] = (byte) (aad.length >>> 8);
            a[1] = (byte) aad.length;
            System.arraycopy(aad, 0, a, 2, aad.length);
            x = absorb(x, a);
        }
        x = absorb(x, msg);
        return x;
    }

    private byte[] absorb(byte[] x, byte[] data) {
        for (int off = 0; off < data.length; off += 16) {
            int n = Math.min(16, data.length - off);
            byte[] b = new byte[16];
            System.arraycopy(data, off, b, 0, n);
            for (int i = 0; i < 16; i++) b[i] ^= x[i];
            x = block(b);
        }
        return x;
    }

    private byte[] ctr(byte[] nonce12, byte[] data, int startCounter) {
        byte[] out = new byte[data.length];
        byte[] a = new byte[16];
        a[0] = 2; // L-1
        System.arraycopy(nonce12, 0, a, 1, 12);
        for (int off = 0, ctr = startCounter; off < data.length; off += 16, ctr++) {
            a[13] = (byte) (ctr >>> 16);
            a[14] = (byte) (ctr >>> 8);
            a[15] = (byte) ctr;
            byte[] s = block(a);
            int n = Math.min(16, data.length - off);
            for (int i = 0; i < n; i++) out[off + i] = (byte) (data[off + i] ^ s[i]);
        }
        return out;
    }

    private byte[] block(byte[] in) {
        try {
            return aes.doFinal(in);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES block failed", e);
        }
    }
}
