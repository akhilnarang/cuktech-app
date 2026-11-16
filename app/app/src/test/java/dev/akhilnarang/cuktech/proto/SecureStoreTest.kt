package dev.akhilnarang.cuktech.proto

import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.*
import org.junit.Test

/**
 * Corrupt-blob classification in [SecureStore.loadToken]. The plain JVM has no
 * AndroidKeyStore provider, so a well-formed blob gets the transient Keystore error path.
 */
class SecureStoreTest {
    /** SharedPreferences in memory. Only the calls that SecureStore makes are supported. */
    private class Prefs(val values: MutableMap<String, String>) : SharedPreferences {
        override fun getString(key: String, defValue: String?) = values[key] ?: defValue
        override fun contains(key: String) = key in values
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            override fun clear() = apply { values.clear() }
            override fun remove(key: String) = apply { values.remove(key) }
            override fun putString(key: String, value: String?) = apply { if (value == null) values.remove(key) else values[key] = value }
            override fun putStringSet(key: String, value: MutableSet<String>?) = error("unused")
            override fun putInt(key: String, value: Int) = error("unused")
            override fun putLong(key: String, value: Long) = error("unused")
            override fun putFloat(key: String, value: Float) = error("unused")
            override fun putBoolean(key: String, value: Boolean) = error("unused")
            override fun commit() = true
            override fun apply() {}
        }
        override fun getAll() = error("unused")
        override fun getStringSet(key: String, defValues: MutableSet<String>?) = error("unused")
        override fun getInt(key: String, defValue: Int) = error("unused")
        override fun getLong(key: String, defValue: Long) = error("unused")
        override fun getFloat(key: String, defValue: Float) = error("unused")
        override fun getBoolean(key: String, defValue: Boolean) = error("unused")
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) = error("unused")
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) = error("unused")
    }

    private fun store(values: MutableMap<String, String>) = SecureStore(object : ContextWrapper(null) {
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences = Prefs(values)
    })

    @Test fun malformedBlobIsCorruptAndWipedButKeystoreErrorKeepsCredentials() {
        for (blob in listOf("AAAAAAAAAAAAAAAA", "AAAA:not*base64")) {
            val values = mutableMapOf("mac" to "00:11:22:33:44:55", "token_ct" to blob, "cloud_session" to "x")
            val store = store(values)
            assertNull(store.loadToken())
            assertTrue("blob '$blob' must count as corrupt", store.wasCorrupt())
            assertTrue("a corrupt blob must be wiped", values.isEmpty())
        }
        val values = mutableMapOf("mac" to "00:11:22:33:44:55", "token_ct" to "AAAAAAAAAAAAAAAA:AAAAAAAA")
        val store = store(values)
        assertNull(store.loadToken())
        assertFalse(store.wasCorrupt())
        assertTrue("a transient error keeps the credentials", store.hasCredentials())
    }
}
