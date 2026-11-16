package dev.akhilnarang.cuktech.firmware

import dev.akhilnarang.cuktech.CloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.net.Proxy
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.coroutines.coroutineContext

/**
 * Downloads official firmware packages. It uses a separate HTTP client, so Xiaomi account cookies
 * never go to the firmware CDN. It uses no proxy and follows redirects only after it checks them.
 */
object FirmwareDownloader {
    private const val MAX_BYTES = 8 * 1024 * 1024
    private val http = OkHttpClient.Builder().proxy(Proxy.NO_PROXY)
        .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .connectTimeout(10, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS)
        .callTimeout(90, TimeUnit.SECONDS).build()

/**
 * Parses and checks a firmware URL.
 * @return The URL, if it is https on port 443, has no userinfo, and its host is in or under
 *   mi.com, mi-img.com, xiaomi.com or mi-fds.com.
 * @throws CloudException If the URL is not valid or not official.
 */
    internal fun officialUrl(value: String): HttpUrl {
        val url = value.toHttpUrlOrNull() ?: throw CloudException("Invalid firmware download URL")
        val domains = listOf("mi.com", "mi-img.com", "xiaomi.com", "mi-fds.com")
        if (!url.isHttps || url.port != 443 || url.username.isNotEmpty() || url.password.isNotEmpty() ||
            domains.none { url.host == it || url.host.endsWith(".$it") })
            throw CloudException("Firmware must come from an official Xiaomi HTTPS server")
        return url
    }

/**
 * Downloads [info] to a new temporary file in [directory] and checks it.
 *
 * It follows a maximum of 3 redirects and checks each target with [officialUrl]. The file must be
 * 1 KiB to 8 MiB. Its MD5 must match [FirmwareInfo.md5]. It must have `R2SF` at offset 40 and
 * contain [FirmwareInfo.model]. The signature is not checked here: use [FirmwarePackage.validate].
 * If the download fails or is cancelled, the file is deleted.
 *
 * @param progress Called on the main thread with the received bytes and the total bytes.
 *   The total is -1 if the server does not send a length.
 * @return The checked file. The caller owns it and deletes it.
 * @throws CloudException If the network, the server or a check fails.
 */
    suspend fun download(info: FirmwareInfo, directory: File, progress: (Long, Long) -> Unit): File = withContext(Dispatchers.IO) {
        val output = File.createTempFile("firmware-", ".bin", directory)
        var completed = false
        try {
            var url = officialUrl(info.url)
            repeat(4) {
                coroutineContext.ensureActive()
                val response = try { http.newCall(Request.Builder().url(url).build()).execute() }
                catch (e: java.io.IOException) { throw CloudException("Cannot connect to the firmware server") }
                response.use { r ->
                    if (r.code in listOf(301, 302, 303, 307, 308)) {
                        val location = r.header("Location") ?: throw CloudException("Firmware redirect is missing a destination")
                        url = officialUrl(url.resolve(location)?.toString() ?: "")
                    } else {
                        if (!r.isSuccessful) throw CloudException("Firmware download failed: HTTP ${r.code}")
                        val body = r.body ?: throw CloudException("Firmware download was empty")
                        val length = body.contentLength()
                        if (length > MAX_BYTES) throw CloudException("Firmware package is too large")
                        var received = 0L
                        val md5 = MessageDigest.getInstance("MD5")
                        body.byteStream().use { input ->
                            output.outputStream().use { target ->
                                val buffer = ByteArray(32 * 1024)
                                while (true) {
                                    coroutineContext.ensureActive()
                                    val n = input.read(buffer)
                                    if (n < 0) break
                                    received += n
                                    if (received > MAX_BYTES) throw CloudException("Firmware package exceeds the size limit")
                                    md5.update(buffer, 0, n)
                                    target.write(buffer, 0, n)
                                    withContext(Dispatchers.Main) { progress(received, length) }
                                }
                            }
                        }
                        if (received < 1024 || (length >= 0 && received != length))
                            throw CloudException("Firmware download is incomplete")
                        val actual = md5.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
                        if (!actual.equals(info.md5, ignoreCase = true))
                            throw CloudException("Firmware checksum does not match Xiaomi's metadata")
                        val bytes = output.readBytes()
                        if (bytes.size < 44 || String(bytes, 40, 4, Charsets.US_ASCII) != "R2SF" ||
                            !String(bytes, Charsets.ISO_8859_1).contains(info.model))
                            throw CloudException("The downloaded image does not match this charger family")
                        completed = true
                        return@withContext output
                    }
                }
            }
            throw CloudException("Too many firmware download redirects")
        } catch (e: java.io.IOException) {
            throw CloudException("Cannot read or save the firmware package")
        } finally {
            if (!completed) output.delete()
        }
    }
}
