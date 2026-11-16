package dev.akhilnarang.cuktech.proto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * Mi BLE login crypto. Adapted from ha-cuk-ble
 * (https://github.com/zuyan9/ha-cuk-ble), Apache-2.0 (lib/xiaomi/crypto.py).
 * This class has the login path only. The register (ECDH) crypto is in bind/BindCrypto.
 *
 * <p>deriveLogin: HKDF-SHA256(ikm = 12-byte token, salt = app_rand(16) ‖ dev_rand(16),
 * info = "mible-login-info", L = 64) → dev_key[0:16], app_key[16:32],
 * dev_iv[32:36], app_iv[36:40]. Mutual HMACs: dev = HMAC(dev_key,
 * dev_rand‖app_rand), app = HMAC(app_key, app_rand‖dev_rand).
 *
 * <p>Comparisons are constant-time. All methods are stateless and thread-safe.
 */
public final class MiCrypto {

    /** HKDF info string for the login keys. Do not change the array. */
    public static final byte[] LOGIN_INFO = "mible-login-info".getBytes();
    /** Length of the bind token, in bytes. */
    public static final int TOKEN_LEN = 12;
    /** Length of each login random, in bytes. */
    public static final int RAND_LEN = 16;

    /** MIOT session keys from {@link #deriveLogin}. The IVs are the first 4 nonce bytes. */
    public static final class SessionKeys {
        public final byte[] devKey = new byte[16];  // device → app (decrypt)
        public final byte[] appKey = new byte[16];  // app → device (encrypt)
        public final byte[] devIv = new byte[4];
        public final byte[] appIv = new byte[4];
    }

    private MiCrypto() {}

    /**
     * Calculates HMAC-SHA256.
     *
     * @param key HMAC key, any length.
     * @param data Data to authenticate.
     * @return The 32-byte MAC.
     * @throws IllegalStateException If the platform has no HmacSHA256.
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /**
     * RFC 5869 HKDF with SHA-256. Supply the salt: this method does not replace a missing
     * salt with zeros. The login always has a salt.
     *
     * @param ikm Input key material.
     * @param salt Salt. Must not be null.
     * @param info Context info, or null for none.
     * @param length Output length in bytes, 1 to 8160.
     * @return {@code length} bytes of output key material.
     * @throws IllegalArgumentException If {@code length} is 0 or less.
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length <= 0) throw new IllegalArgumentException("length must be positive");
        byte[] prk = hmacSha256(salt, ikm);
        byte[] out = new byte[length];
        int filled = 0, round = 0;
        byte[] t = new byte[0];
        while (filled < length) {
            round++;
            byte[] in = new byte[t.length + (info == null ? 0 : info.length) + 1];
            System.arraycopy(t, 0, in, 0, t.length);
            if (info != null) System.arraycopy(info, 0, in, t.length, info.length);
            in[in.length - 1] = (byte) round;
            t = hmacSha256(prk, in);
            int n = Math.min(t.length, length - filled);
            System.arraycopy(t, 0, out, filled, n);
            filled += n;
        }
        return out;
    }

    /**
     * Derives the MIOT session keys for after the login from the bind token and the
     * two login randoms.
     *
     * @param token Bind token, {@link #TOKEN_LEN} bytes.
     * @param appRand Random that the app sent, {@link #RAND_LEN} bytes.
     * @param devRand Random that the charger sent, {@link #RAND_LEN} bytes.
     * @return The session keys.
     * @throws IllegalArgumentException If a parameter is null or has the wrong length.
     */
    public static SessionKeys deriveLogin(byte[] token, byte[] appRand, byte[] devRand) {
        if (token == null || token.length != TOKEN_LEN) {
            throw new IllegalArgumentException("token must be " + TOKEN_LEN + " bytes");
        }
        if (appRand == null || appRand.length != RAND_LEN
                || devRand == null || devRand.length != RAND_LEN) {
            throw new IllegalArgumentException("login randoms must be " + RAND_LEN + " bytes");
        }
        byte[] salt = new byte[32];
        System.arraycopy(appRand, 0, salt, 0, 16);
        System.arraycopy(devRand, 0, salt, 16, 16);
        byte[] out = hkdfSha256(token, salt, LOGIN_INFO, 64);
        SessionKeys k = new SessionKeys();
        System.arraycopy(out, 0, k.devKey, 0, 16);
        System.arraycopy(out, 16, k.appKey, 0, 16);
        System.arraycopy(out, 32, k.devIv, 0, 4);
        System.arraycopy(out, 36, k.appIv, 0, 4);
        return k;
    }

    /**
     * Compares two arrays in constant time. The login uses it for the device HMAC check.
     *
     * @param a First array, or null.
     * @param b Second array, or null.
     * @return True if both are null, or if both have the same length and contents.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return a == b;
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
