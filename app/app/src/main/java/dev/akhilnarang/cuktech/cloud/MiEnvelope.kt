package dev.akhilnarang.cuktech.cloud

import dev.akhilnarang.cuktech.CloudException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.zip.GZIPInputStream

/**
 * Xiaomi cloud /app envelope functions. It has no Android or OkHttp dependencies.
 *
 * It contains the nonce, signed nonce, envelope signature, request form, RC4 response decode,
 * base64 field decode and the JSON body builders. The output matches cloud.py byte for byte.
 */
object MiEnvelope {
    private const val RC4_DROP = 1024
    private const val GUNZIP_MAX_BYTES = 65536
    private val random = SecureRandom()
    private val b64 = Base64.getEncoder()

    /**
     * RC4 that discards the first [drop] keystream bytes. One instance is one continuing keystream.
     * Not thread-safe.
     *
     * @param key RC4 key. It must not be empty.
     * @param drop Number of keystream bytes to discard. Default 1024.
     * @throws IllegalArgumentException If [key] is empty.
     */
    class Rc4(key: ByteArray, drop: Int = RC4_DROP) {
        private val s = IntArray(256) { it }
        private var i = 0
        private var j = 0

        init {
            require(key.isNotEmpty()) { "empty RC4 key" }
            var jj = 0
            for (ii in 0 until 256) {
                jj = (jj + s[ii] + (key[ii % key.size].toInt() and 0xFF)) and 0xFF
                val t = s[ii]; s[ii] = s[jj]; s[jj] = t
            }
            repeat(drop) { next() }
        }

/** Returns the next keystream byte, 0..255. */
        fun next(): Int {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
            return s[(s[i] + s[j]) and 0xFF]
        }

/** XORs [data] with the next keystream bytes. Encryption and decryption are the same operation. */
        fun crypt(data: ByteArray): ByteArray = ByteArray(data.size) { (data[it].toInt() xor next()).toByte() }
    }

/**
 * Makes a /app nonce: 8 random bytes, then the minute count since the epoch as a big-endian u32.
 *
 * @param nowMs Server-corrected time, in ms since the epoch.
 * @param rand The 8 random bytes. Tests can set them.
 * @return The nonce as standard base64.
 * @throws IllegalArgumentException If [rand] is not 8 bytes.
 */
    fun generateNonce(nowMs: Long, rand: ByteArray = ByteArray(8).also { random.nextBytes(it) }): String {
        require(rand.size == 8) { "nonce randomness must be 8 bytes" }
        val minute = (nowMs / 60000).toInt()
        val bucket = byteArrayOf((minute ushr 24).toByte(), (minute ushr 16).toByte(), (minute ushr 8).toByte(), minute.toByte())
        return b64.encodeToString(rand + bucket)
    }

/**
 * Returns base64(SHA-256(ssecurity || nonce)). Both inputs are standard base64.
 * @throws IllegalArgumentException If an input is not valid base64.
 */
    fun signedNonce(ssecurityB64: String, nonceB64: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(Base64.getDecoder().decode(ssecurityB64))
        md.update(Base64.getDecoder().decode(nonceB64))
        return b64.encodeToString(md.digest())
    }

/**
 * Returns base64(SHA-1("METHOD&path&k=v&...&signedNonce")). The params are sorted by key.
 * @param path The API path without the /app prefix.
 */
    fun envelopeSignature(method: String, path: String, params: Map<String, String>, signedNonceB64: String): String {
        val parts = mutableListOf(method.uppercase(), path)
        params.entries.sortedBy { it.key }.forEach { parts += "${it.key}=${it.value}" }
        parts += signedNonceB64
        val digest = MessageDigest.getInstance("SHA-1").digest(parts.joinToString("&").toByteArray())
        return b64.encodeToString(digest)
    }

    /**
     * Makes the encrypted /app form fields, in cloud.py order.
     *
     * The fields are `data` and `rc4_hash__` (RC4-encrypted), then `signature`, `ssecurity` and `_nonce`.
     * @param dataJson Plain JSON request body.
     * @param path The API path without the /app prefix.
     * @return The form fields in send order.
     */
    fun buildRequestForm(ssecurityB64: String, nonceB64: String, signedNonceB64: String, dataJson: String, path: String): LinkedHashMap<String, String> {
        val plain = linkedMapOf("data" to dataJson)
        plain["rc4_hash__"] = envelopeSignature("POST", path, plain, signedNonceB64)
        val rc4 = Rc4(Base64.getDecoder().decode(signedNonceB64))
        val encrypted = LinkedHashMap<String, String>()
        for (name in plain.keys.sorted()) encrypted[name] = b64.encodeToString(rc4.crypt(plain.getValue(name).toByteArray()))
        encrypted["signature"] = envelopeSignature("POST", path, encrypted, signedNonceB64)
        encrypted["ssecurity"] = ssecurityB64
        encrypted["_nonce"] = nonceB64
        return encrypted
    }

/**
 * Decompresses gzip data.
 * @param maxBytes Maximum output size, in bytes. Default 64 KiB.
 * @throws CloudException If the stream is not valid gzip or the output is larger than [maxBytes].
 */
    fun gunzipBounded(data: ByteArray, maxBytes: Int = GUNZIP_MAX_BYTES): ByteArray {
        val out = ByteArrayOutputStream()
        try {
            GZIPInputStream(data.inputStream()).use { gz ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = gz.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > maxBytes) throw CloudException("gunzipped response exceeds size cap")
                }
            }
        } catch (e: IOException) {
            throw CloudException("invalid gzip stream")
        }
        return out.toByteArray()
    }

    /**
     * Decodes an /app response: base64, then RC4 with the signed nonce, then gunzip if the server
     * says GZIP, then UTF-8 text. The caller parses the JSON.
     *
     * @param contentEncoding Value of the `MIOT-CONTENT-ENCODING` header, or null.
     * @throws CloudException If the body is not valid base64, or GZIP is announced and the data is not gzip.
     */
    fun decodeResponseText(ssecurityB64: String, nonceB64: String, bodyText: String, contentEncoding: String?): String {
        val key = Base64.getDecoder().decode(signedNonce(ssecurityB64, nonceB64))
        var decrypted = try {
            Rc4(key).crypt(Base64.getMimeDecoder().decode(bodyText.trim()))
        } catch (e: IllegalArgumentException) {
            throw CloudException("response body is not valid base64/RC4")
        }
        if ((contentEncoding ?: "").uppercase() == "GZIP") {
            if (!isGzip(decrypted)) throw CloudException("GZIP response missing gzip magic")
            decrypted = gunzipBounded(decrypted)
        }
        return String(decrypted, Charsets.UTF_8)
    }

    /**
     * Decodes a URL-safe base64 cloud field. Padding is optional and whitespace is ignored.
     * If the data starts with the gzip magic, it is decompressed.
     * @throws CloudException If [value] is empty or not valid base64, or the gzip data is not valid.
     */
    fun decodeB64Field(value: String): ByteArray {
        if (value.isEmpty()) throw CloudException("cloud field is empty")
        var text = value.filterNot { it.isWhitespace() }.replace('-', '+').replace('_', '/')
        text += "=".repeat((4 - text.length % 4) % 4)
        val raw = try {
            Base64.getDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            throw CloudException("cloud field is not valid base64")
        }
        return if (isGzip(raw)) gunzipBounded(raw) else raw
    }

    private fun isGzip(b: ByteArray) = b.size >= 2 && b[0] == 0x1F.toByte() && b[1] == 0x8B.toByte()

    /**
     * Returns [s] as a JSON string literal, with the same escapes as Python json.dumps.
     * @param asciiOnly True to escape all characters above 0x7E as \uXXXX (json.dumps default).
     */
    fun q(s: String, asciiOnly: Boolean = false): String = buildString {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c == '\n' -> append("\\n")
            c == '\r' -> append("\\r")
            c == '\t' -> append("\\t")
            c == '\b' -> append("\\b")
            c == '\u000C' -> append("\\f")
            c < ' ' || (asciiOnly && c.code > 0x7E) -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }

/** JSON body for `/device/bltapplydid`. If [did] is empty, the body has no `did` field. */
    fun buildApplydidBody(mac: String, model: String, tokenHex: String, did: String = ""): String =
        "{\"mac\":${q(mac)},\"model\":${q(model)},\"token\":${q(tokenHex)}" +
            (if (did.isNotEmpty()) ",\"did\":${q(did)}" else "") + "}"

/** JSON body for `/v2/device/ble_standard_bind`. [bindKeyHex] goes in `bind_key` and `beacon_key`. */
    fun buildStandardBindBody(did: String, tokenHex: String, bindKeyHex: String, smac: String): String =
        "{\"did\":${q(did)},\"token\":${q(tokenHex)},\"props\":[" +
            "{\"type\":\"prop\",\"key\":\"bind_key\",\"value\":${q(bindKeyHex)}}," +
            "{\"type\":\"prop\",\"key\":\"smac\",\"value\":${q(smac)}}]," +
            "\"beacon_key\":${q(bindKeyHex)}}"

    /** JSON body for `/user/del_owner_device_batch`, with json.dumps default separators, as cloud.py remove_device sends it. */
    fun buildRemoveBody(did: String, pid: Int): String =
        "{\"devList\": [{\"did\": ${q(did, asciiOnly = true)}, \"pid\": $pid}]}"
}
