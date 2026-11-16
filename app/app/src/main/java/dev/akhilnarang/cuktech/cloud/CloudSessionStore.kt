package dev.akhilnarang.cuktech.cloud

import dev.akhilnarang.cuktech.CloudSession
import dev.akhilnarang.cuktech.proto.SecureStore
import org.json.JSONObject

/**
 * Saves the Xiaomi API session in [SecureStore]. Passwords and verification codes are never saved.
 * The username is saved only as a SHA-256 tag. The data is encrypted with the Android Keystore.
 * [save] writes synchronously (SharedPreferences commit).
 */
class CloudSessionStore(private val store: SecureStore) {
/**
 * Saves [session] as JSON (schema 1). It replaces the old session.
 * @param username If not null, the SHA-256 tag of the trimmed, lowercase name is saved.
 *   If null, the old tag is kept if the user ID and region are the same.
 */
    fun save(session: CloudSession, username: String? = null) {
        val json = JSONObject().apply {
            put("schema", 1)
            put("userId", session.userId)
            put("ssecurity", session.ssecurity)
            put("serviceToken", session.serviceToken)
            put("deviceId", session.deviceId)
            put("skewSeconds", session.skewSeconds)
            put("region", session.region)
            if (username != null) put("usernameTag", tag(username))
            else {
                val old = store.loadCloudSession()?.let { JSONObject(it) }
                if (old?.optString("userId") == session.userId && old.optString("region") == session.region)
                    old.optString("usernameTag", "").takeIf { it.isNotEmpty() }?.let { put("usernameTag", it) }
            }
        }
        store.saveCloudSession(json.toString())
    }

/**
 * Loads the saved session.
 * @param expectedUsername If not null, the saved username tag must match it.
 * @param expectedRegion If not null, the saved region must match it.
 * @return The session, or null if no session is saved or it does not match.
 * @throws IllegalStateException If the saved data is not valid.
 */
    fun load(expectedUsername: String? = null, expectedRegion: String? = null): CloudSession? {
        val json = store.loadCloudSession() ?: return null
        try {
            val obj = JSONObject(json)
            require(obj.getInt("schema") == 1)
            if (expectedUsername != null && obj.optString("usernameTag") != tag(expectedUsername)) return null
            if (expectedRegion != null && obj.optString("region") != expectedRegion) return null
            val session = CloudSession(obj.getString("userId"), obj.getString("ssecurity"),
                obj.getString("serviceToken"), obj.getString("deviceId"),
                obj.getDouble("skewSeconds"), obj.getString("region"))
            require(session.userId.isNotBlank() && session.ssecurity.isNotBlank() && session.serviceToken.isNotBlank())
            require(session.region in setOf("cn", "in", "i2", "sg", "de", "us", "ru", "tw"))
            return session
        } catch (e: Exception) {
            throw IllegalStateException("Saved cloud login is invalid. Forget it and sign in again.")
        }
    }

/** Returns true if a session is saved. It does not check that the session is valid. */
    fun exists() = store.hasCloudSession()

/** Deletes the saved session. */
    fun clear() = store.clearCloudSession()

    private fun tag(username: String): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(username.trim().lowercase(java.util.Locale.US).toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
}
