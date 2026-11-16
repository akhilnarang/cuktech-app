package dev.akhilnarang.cuktech.proto;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Credential storage for the bind token.
 *
 * <p>An AES-256/GCM key in the Android Keystore encrypts the 12-byte token. The key
 * cannot be exported, and it is hardware-backed if the phone supports it. The
 * ciphertext and IV are in the private SharedPreferences of the app
 * (allowBackup=false). The MAC address is stored next to it, because it is a
 * connection target and not a secret. The app never stores, logs, exports or copies
 * to the clipboard a plaintext token.
 *
 * <p>Keystore calls can be slow. Do not call this class in a tight loop on the main thread.
 */
public final class SecureStore {

    private static final String PREFS = "cuktech_controller";
    private static final String K_MAC = "mac";
    private static final String K_TOKEN = "token_ct"; // b64(iv) ":" b64(ct||tag)
    private static final String ALIAS = "cuktech-token-key";

    private final SharedPreferences prefs;

    /** @param context Context for the private SharedPreferences. */
    public SecureStore(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private boolean corrupt;

    /** @return True if a MAC and an encrypted token are stored. It does not decrypt the token. */
    public boolean hasCredentials() {
        return prefs.contains(K_MAC) && prefs.contains(K_TOKEN);
    }

    /** @return The stored charger MAC, or null. */
    public String getMac() {
        return prefs.getString(K_MAC, null);
    }

    /**
     * Decrypts the stored token.
     *
     * @return The 12-byte token, or null if it is missing or cannot be read. If the blob
     *         is DEFINITELY corrupt (bad tag, bad base64, wrong length, or an invalidated
     *         or unusable Keystore key), the method calls {@link #clear()} and sets
     *         {@link #wasCorrupt()}. The UI then goes to setup again. If the secure
     *         storage has a temporary error (Keystore not available for a short time),
     *         the method keeps the credentials so that the user can try again.
     */
    public byte[] loadToken() {
        corrupt = false;
        String blob = prefs.getString(K_TOKEN, null);
        if (blob == null) return null;
        try {
            String[] parts = blob.split(":", 2);
            if (parts.length != 2) throw new IllegalArgumentException("token blob has no separator");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ct = Base64.getDecoder().decode(parts[1]);
            SecretKey key = key();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] token = cipher.doFinal(ct);
            if (token.length != MiCrypto.TOKEN_LEN) {
                corrupt = true;
                clear();
                return null;
            }
            return token;
        } catch (javax.crypto.AEADBadTagException
                 | java.security.UnrecoverableKeyException
                 | java.security.InvalidKeyException e) {
            // wrong, invalidated (KeyPermanentlyInvalidatedException is an
            // InvalidKeyException) or unusable key, or tampered blob:
            // unrecoverable, wipe
            corrupt = true;
            clear();
            return null;
        } catch (IllegalArgumentException e) {
            // malformed blob (no separator or bad base64): unrecoverable, wipe
            corrupt = true;
            clear();
            return null;
        } catch (Exception e) {
            // transient keystore/cipher error: keep credentials, retry later
            return null;
        }
    }

    /** True when the last loadToken() failed because the blob was corrupt. */
    public boolean wasCorrupt() {
        return corrupt;
    }

    /**
     * Stores the MAC as plain text and the token encrypted with the Keystore key.
     * If the MAC changes, it also removes the stored firmware version. The write is
     * asynchronous (apply).
     *
     * @param mac Charger MAC.
     * @param token Bind token.
     * @throws IllegalStateException If the encryption fails.
     */
    public void save(String mac, byte[] token) {
        try {
            SecretKey key = key();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = cipher.doFinal(token);
            String iv = Base64.getEncoder().encodeToString(cipher.getIV());
            String ctB64 = Base64.getEncoder().encodeToString(ct);
            SharedPreferences.Editor editor = prefs.edit();
            if (!mac.equals(prefs.getString(K_MAC, null))) editor.remove("firmware_version");
            editor
                    .putString(K_MAC, mac)
                    .putString(K_TOKEN, iv + ":" + ctB64)
                    .apply();
        } catch (Exception e) {
            throw new IllegalStateException("failed to seal token", e);
        }
    }

    /** @return The last known firmware version of the stored charger, or null. */
    public String getFirmwareVersion() { return prefs.getString("firmware_version", null); }
    /** @param version Firmware version text. The write is asynchronous (apply). */
    public void saveFirmwareVersion(String version) {
        prefs.edit().putString("firmware_version", version).apply();
    }

    /**
     * Stores the optional Xiaomi cloud session, encrypted with the same Keystore key and
     * the AAD "xiaomi-cloud-session-v1". It has no password. The write is synchronous (commit).
     *
     * @param json Session JSON.
     * @throws IllegalStateException If the encryption or the write fails.
     */
    public void saveCloudSession(String json) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key());
            cipher.updateAAD("xiaomi-cloud-session-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String sealed = Base64.getEncoder().encodeToString(cipher.getIV()) + ":"
                    + Base64.getEncoder().encodeToString(cipher.doFinal(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            if (!prefs.edit().putString("cloud_session", sealed).commit())
                throw new IllegalStateException("cloud session could not be saved");
        } catch (Exception e) {
            throw new IllegalStateException("could not encrypt the cloud session");
        }
    }

    /**
     * Decrypts the stored Xiaomi cloud session.
     *
     * @return The session JSON, or null if none is stored.
     * @throws IllegalStateException If the stored session cannot be decrypted. The
     *         session is not removed.
     */
    public String loadCloudSession() {
        String blob = prefs.getString("cloud_session", null);
        if (blob == null) return null;
        try {
            String[] parts = blob.split(":", 2);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.getDecoder().decode(parts[0])));
            cipher.updateAAD("xiaomi-cloud-session-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return new String(cipher.doFinal(Base64.getDecoder().decode(parts[1])), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("saved cloud login is not available. Forget it and sign in again.");
        }
    }

    /** @return True if a cloud session is stored. It does not decrypt it. */
    public boolean hasCloudSession() { return prefs.contains("cloud_session"); }

    /** Removes only the cloud session. The write is asynchronous (apply). */
    public void clearCloudSession() { prefs.edit().remove("cloud_session").apply(); }

    /**
     * Removes all credentials permanently (Forget button). It clears all the preferences
     * of this store, which includes the cloud session and the firmware version, AND
     * deletes the Keystore key alias. The preferences go first: when the blob is gone,
     * nobody can recover the ciphertext, even if the key deletion is late. Then the
     * method tries to remove the alias and ignores errors.
     */
    public void clear() {
        prefs.edit().clear().apply();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.deleteEntry(ALIAS);
        } catch (Exception ignored) {
            // key orphaned but no ciphertext remains; a fresh save regenerates
        }
    }

    // Gets the Keystore key, or makes it on first use.
    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        SecretKey existing = (SecretKey) ks.getKey(ALIAS, null);
        if (existing != null) return existing;
        KeyGenerator kg = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return kg.generateKey();
    }
}
