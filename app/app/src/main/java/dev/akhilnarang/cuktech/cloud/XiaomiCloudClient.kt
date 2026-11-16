package dev.akhilnarang.cuktech.cloud

import dev.akhilnarang.cuktech.BindMaterial
import dev.akhilnarang.cuktech.CloudDevice
import dev.akhilnarang.cuktech.CloudException
import dev.akhilnarang.cuktech.CloudSession
import dev.akhilnarang.cuktech.LoginPrompts
import dev.akhilnarang.cuktech.XiaomiCloud
import dev.akhilnarang.cuktech.firmware.FirmwareInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Cookie
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.Buffer
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.Proxy
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Xiaomi account sign-in and MiCloud device API.
 *
 * Every HTTP call goes through [call]. Each call uses an allowlisted https URL, no proxy and no
 * automatic redirects. Timeouts and the body size have limits. Exception messages never contain
 * URLs, cookies or credentials. All public functions are safe to call from any thread.
 */
class XiaomiCloudClient internal constructor(private val http: OkHttpClient) : XiaomiCloud {
/** Makes a client with its own OkHttp instance: 10 s connect, 30 s read and 45 s call timeouts. */
    constructor() : this(OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false) // never silently replay a POST (password hash, mutations)
        .proxy(Proxy.NO_PROXY) // cloud.py refuses proxies
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .callTimeout(45, TimeUnit.SECONDS)
        .build())

    // ------------------------------------------------------------------ HTTP

/** A complete HTTP response. The body is fully read and has a size limit. */
    internal class Resp(val code: Int, val headers: Headers, val body: ByteArray, val url: HttpUrl) {
        val text: String get() = String(body, Charsets.UTF_8)
        val setCookies: List<Cookie> by lazy { Cookie.parseAll(url, headers) }
        fun cookie(name: String): String = setCookies.lastOrNull { it.name == name }?.value ?: ""
        fun location(): String? = headers["Location"]?.takeIf { it.isNotEmpty() }?.let { url.resolve(it)?.toString() }
    }

/**
 * Sends one HTTP request. It does not follow redirects.
 *
 * It tries a second time once in two cases: a read-only request that gets HTTP 502, 503 or 504
 * or an I/O error, or any request that fails before it is sent (DNS, connect or no route).
 *
 * @param method `GET` or `POST`.
 * @param url Absolute URL. It must pass the host allowlist.
 * @param stage Short step name for error messages.
 * @param params Query parameters to add to [url].
 * @param form Form body for a POST. If null, a POST has an empty body.
 * @param cookies Returns the `Cookie` header value for the final URL, or null.
 * @param maxBytes Maximum body size, in bytes.
 * @return The response. The caller checks the status code.
 * @throws CloudException If the URL is refused, the network fails, the body is too large,
 *   or a POST gets a redirect. After a POST redirect, the server result is unknown.
 */
    internal fun call(
        method: String,
        url: String,
        stage: String,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
        form: Map<String, String>? = null,
        cookies: (HttpUrl) -> String? = { null },
        maxBytes: Int = MAX_RESPONSE_BYTES,
    ): Resp {
        val base = validateUrl(url)
        val u = base.newBuilder().apply { params.forEach { (k, v) -> addQueryParameter(k, v) } }.build()
        val body = when {
            method == "GET" -> null
            form != null -> FormBody.Builder().apply { form.forEach { (k, v) -> add(k, v) } }.build()
            else -> ByteArray(0).toRequestBody(null)
        }
        val request = try {
            Request.Builder().url(u).method(method, body).apply {
                headers.forEach { (k, v) -> header(k, v) }
                cookies(u)?.let { header("Cookie", it) }
            }.build()
        } catch (e: IllegalArgumentException) {
            throw CloudException("invalid request during $stage") // OkHttp messages may echo header values
        }
        val readOnly = method == "GET" || (method == "POST" && u.encodedPath in setOf(
            "/app/home/device_list", "/app/v2/device/latest_ver", "/app/home/latest_version"))
        var response: Resp? = null
        for (attempt in 0..1) {
            try {
                val r = http.newCall(request).execute().use { r -> Resp(r.code, r.headers, readCapped(r, maxBytes), u) }
                if (attempt == 0 && readOnly && r.code in setOf(502, 503, 504)) continue
                response = r
                break
            } catch (e: IOException) {
                // DNS/connect refusal proves the request was never submitted. A read-only
                // request may also be repeated after a dropped connection or read timeout.
                val beforeSend = e is java.net.UnknownHostException || e is java.net.ConnectException || e is java.net.NoRouteToHostException
                if (attempt == 0 && (readOnly || beforeSend) && e !is javax.net.ssl.SSLException) continue
                val message = when (e) {
                    is java.net.UnknownHostException -> "Cannot find the Xiaomi server during $stage. Check your connection and try again."
                    is java.net.SocketTimeoutException -> "Xiaomi timed out during $stage. Try again."
                    is javax.net.ssl.SSLException -> "Secure connection to Xiaomi failed during $stage. Check the phone's date, time, and connection."
                    else -> "Network connection failed during $stage. Try again when the connection is stable."
                }
                throw CloudException(message)
            }
        }
        val resp = response ?: throw CloudException("Cannot connect to Xiaomi during $stage")
        if (resp.code in REDIRECT_CODES && method != "GET") {
            throw CloudException(
                "unexpected redirect during $stage (POSTs are never replayed; the operation may or may " +
                    "not have been processed. The result is unknown.)"
            )
        }
        return resp
    }

    private fun readCapped(r: Response, maxBytes: Int): ByteArray {
        val src = r.body?.source() ?: return ByteArray(0)
        val buf = Buffer()
        while (src.read(buf, 8192) != -1L) {
            if (buf.size > maxBytes) throw CloudException("response body exceeds size cap")
        }
        return buf.readByteArray()
    }

    // ------------------------------------------------------------------ login

    override suspend fun login(username: String, password: String, region: String, prompts: LoginPrompts): CloudSession =
        withContext(Dispatchers.IO) {
            if (region !in SERVERS) throw CloudException("unknown region")
            LoginFlow(prompts).login(username, password, region)
        }

// State of one sign-in attempt. The cookie jar is in memory only.
    private inner class LoginFlow(private val prompts: LoginPrompts) {
        private val jar = mutableListOf<Cookie>()
        val deviceId = (1..16).map { LETTERS.random() }.joinToString("")
        private var skewSeconds = 0.0
        private var sign: String? = null
        private var ssecurity: String? = null
        private var location: String? = null
        private var serviceToken: String? = null
        private var userId: String? = null

        init {
            for (domain in listOf("mi.com", "xiaomi.com")) {
                setCookie("sdkVersion", "accountsdk-18.8.15", domain)
                setCookie("deviceId", deviceId, domain)
            }
        }

        // -- cookie jar (requests.Session semantics, in memory only)

        private fun setCookie(name: String, value: String, domain: String) {
            store(Cookie.Builder().name(name).value(value).domain(domain).path("/").build())
        }

        private fun store(c: Cookie) {
            jar.removeAll { it.name == c.name && it.domain == c.domain && it.path == c.path }
            if (c.expiresAt > System.currentTimeMillis()) jar += c
        }

        private fun cookieHeader(url: HttpUrl, extra: Map<String, String>): String? {
            val now = System.currentTimeMillis()
            val pairs = jar.filter { it.expiresAt > now && it.matches(url) }.map { it.name to it.value }.toMutableList()
            extra.forEach { (k, v) -> if ((k to v) !in pairs) pairs += k to v }
            return pairs.joinToString("; ") { "${it.first}=${it.second}" }.ifEmpty { null }
        }

        /** The same cookie can be on several domains (userId after 2FA). Use the numeric account ID first. */
        private fun sessionCookie(name: String): String {
            val values = jar.filter { it.name == name && it.value.isNotEmpty() }.map { it.value }
            return values.firstOrNull { v -> v.isNotEmpty() && v.all { it.isDigit() } } ?: values.firstOrNull() ?: ""
        }

        private fun sessionCookieDomain(name: String, domain: String): String =
            jar.lastOrNull { it.name == name && it.domain == domain }?.value ?: ""

        private fun req(
            method: String,
            url: String,
            stage: String,
            headers: Map<String, String> = emptyMap(),
            params: Map<String, String> = emptyMap(),
            form: Map<String, String>? = null,
            extraCookies: Map<String, String> = emptyMap(),
            maxBytes: Int = MAX_RESPONSE_BYTES,
        ): Resp {
            val r = call(method, url, stage, headers, params, form, { cookieHeader(it, extraCookies) }, maxBytes)
            r.setCookies.forEach(::store)
            return r
        }

        private fun hdrs() = mapOf("User-Agent" to USER_AGENT, "Content-Type" to "application/x-www-form-urlencoded")

        // -- flow

        suspend fun login(username: String, password: String, region: String): CloudSession {
            if (username.isEmpty() || password.isEmpty()) throw CloudException("username and password are required")
            if (username.length > MAX_USERNAME_LEN) throw CloudException("username is implausibly long")
            if (!step1(username)) throw CloudException("login step 1 failed (invalid username?)")
            step2(username, password)
            if (!ssecurity.isNullOrEmpty() && !location.isNullOrEmpty()) {
                if (!step3()) throw CloudException("unable to fetch serviceToken (step 3)")
            }
            // a 2FA continuation can finish without the account identity; step 1 then issues a
            // NEW ssecurity, which needs its matching serviceToken (mixed pair -> HTTP 401)
            if (userId.isNullOrBlank()) {
                if (!(sessionSatisfied(username) && step3())) {
                    throw CloudException(
                        "login completed but the account identity (userId) was not returned. " +
                            "The app does not continue with an incomplete session."
                    )
                }
            }
            val sec = ssecurity
            val tok = serviceToken
            if (sec.isNullOrEmpty() || sec.length <= 4 || tok.isNullOrEmpty()) throw CloudException("login incomplete (no serviceToken)")
            val uid = userId?.trim()
            if (uid.isNullOrEmpty()) throw CloudException("login completed but the account identity (userId) is missing. The app stops here.")
            return CloudSession(uid, sec, tok, deviceId, skewSeconds, region)
        }

        private fun learnSkew(r: Resp) {
            r.headers.getDate("Date")?.let { skewSeconds = (it.time - System.currentTimeMillis()) / 1000.0 }
        }

// GET serviceLogin. It gives _sign, or ssecurity if the session is already signed in.
        private fun step1(username: String): Boolean {
            val r = req(
                "GET", "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true", "login step 1",
                headers = hdrs(), extraCookies = mapOf("userId" to username),
            )
            learnSkew(r)
            if (r.code != 200) return false
            val j = parseJson(r.text, "login step 1")
            if (j.has("_sign")) {
                sign = j.str("_sign")
                return true
            }
            if (j.has("ssecurity")) {
                loadSuccess(j)
                return true
            }
            return false
        }

        private fun loadSuccess(j: JSONObject) {
            ssecurity = j.str("ssecurity")
            userId = j.str("userId")
            location = j.str("location")
        }

// GET the login location to get the serviceToken cookie.
        private fun step3(): Boolean {
            val r = req("GET", location ?: "", "service token exchange", headers = hdrs())
            if (r.code != 200) return false
            serviceToken = r.cookie("serviceToken")
            return !serviceToken.isNullOrEmpty()
        }

// POST serviceLoginAuth2 with the MD5 password hash. It handles captchas and starts 2FA if necessary.
        private suspend fun step2(username: String, password: String) {
            val hash = MessageDigest.getInstance("MD5").digest(password.toByteArray())
                .joinToString("") { "%02X".format(it) }
            val fields = linkedMapOf(
                "sid" to "xiaomiio",
                "hash" to hash,
                "callback" to "https://sts.api.io.mi.com/sts",
                "qs" to "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
                "user" to username,
                "_sign" to (sign ?: ""),
                "_json" to "true",
            )
            var captchaSeen = 0
            // each captcha costs a fetch POST + an answer POST; count captcha prompts, not POSTs
            repeat(MAX_CAPTCHA_ATTEMPTS * 2 + 1) {
                val r = req("POST", "https://account.xiaomi.com/pass/serviceLoginAuth2", "login step 2", headers = hdrs(), params = fields)
                if (r.code != 200) throw CloudException("serviceLoginAuth2 HTTP ${r.code}")
                val j = parseJson(r.text, "login step 2")
                val wrongCaptcha = (j.opt("code") as? Number)?.toDouble() == 87001.0
                if (wrongCaptcha) fields.remove("captCode") // wrong answer: never re-send it, fetch a fresh captcha
                val captchaUrl = j.str("captchaUrl")
                if (!captchaUrl.isNullOrEmpty()) {
                    captchaSeen++
                    if (captchaSeen > MAX_CAPTCHA_ATTEMPTS) throw captchaFailed()
                    fields["captCode"] = fetchCaptcha(captchaUrl)
                    return@repeat
                }
                if (wrongCaptcha) return@repeat
                if ((j.str("ssecurity")?.length ?: 0) > 4) {
                    loadSuccess(j)
                    return
                }
                val notificationUrl = j.str("notificationUrl")
                if (notificationUrl != null) {
                    do2fa(notificationUrl, username)
                    return
                }
                if (j.str("code") == "70016") throw CloudException("wrong account or password (Xiaomi code 70016)")
                throw CloudException("password login rejected: code=${j.str("code")} desc=${j.str("description") ?: j.str("desc")}")
            }
            throw captchaFailed()
        }

        private fun captchaFailed() = CloudException(
            "captcha still fails after $MAX_CAPTCHA_ATTEMPTS attempts. Do not use a VPN or proxy, and try again in a few minutes."
        )

        private suspend fun fetchCaptcha(url: String): String {
            var img = req("GET", absAccountUrl(url), "captcha image", headers = hdrs(), maxBytes = MAX_CAPTCHA_BYTES)
            // the client never follows redirects; the image (and its ick cookie) may sit behind one
            repeat(3) { img.location()?.takeIf { img.code in REDIRECT_CODES }?.let { img = req("GET", it, "captcha image", headers = hdrs(), maxBytes = MAX_CAPTCHA_BYTES) } }
            if (img.code != 200) throw CloudException("captcha image HTTP ${img.code}")
            return prompts.captcha(img.body)?.trim() ?: throw CloudException("sign-in cancelled")
        }

        // -- email 2FA

        private suspend fun do2fa(notificationUrl: String, username: String) {
            val headers = hdrs()
            val locale = notificationUrl.toHttpUrlOrNull()?.queryParameter("_locale")?.takeIf { it.isNotEmpty() } ?: "en_US"
            req("GET", notificationUrl, "2fa start")
            val context = notificationUrl.toHttpUrlOrNull()?.queryParameter("context")
                ?: throw CloudException("2FA challenge could not be parsed")
            val rList = req(
                "GET", "https://account.xiaomi.com/identity/list", "2fa identity list",
                headers = headers, params = mapOf("sid" to "xiaomiio", "context" to context, "_locale" to locale),
            )
            val identitySession = rList.cookie("identity_session").ifEmpty { sessionCookie("identity_session") }
            // the identity list is a hint only: if Xiaomi refuses one channel (e.g. 66108, no
            // email on a phone-only account), fall back to the other
            val first = verifyFlag(rList.text)
            val refused = mutableListOf<String>()
            var flag = first
            for (f in listOf(first, if (first == FLAG_SMS) FLAG_EMAIL else FLAG_SMS)) {
                val sent = req(
                    "POST", "https://account.xiaomi.com/identity/auth/send${if (f == FLAG_SMS) "Phone" else "Email"}Ticket", "2fa code dispatch",
                    headers = headers,
                    params = linkedMapOf(
                        "_dc" to System.currentTimeMillis().toString(), "sid" to "xiaomiio", "context" to context,
                        "mask" to "0", "_locale" to locale,
                    ),
                    form = linkedMapOf("retry" to "0", "icode" to "", "_json" to "true", "ick" to sessionCookie("ick")),
                )
                val sentCode = runCatching { parseJson(sent.text, "2fa code dispatch").opt("code") }.getOrNull()
                if (sentCode is Number && sentCode.toDouble() != 0.0) {
                    refused += "${if (f == FLAG_SMS) "SMS" else "email"} code=$sentCode"
                    continue
                }
                flag = f
                refused.clear()
                break
            }
            if (refused.isNotEmpty()) {
                throw CloudException("Xiaomi refused to send a verification code (${refused.joinToString(", ")}). Wait a few minutes and try again.")
            }
            val kind = if (flag == FLAG_SMS) "Phone" else "Email"
            val code = prompts.verificationCode(flag == FLAG_SMS)?.trim() ?: throw CloudException("sign-in cancelled")
            val verifyUrl = "https://account.xiaomi.com/identity/auth/verify$kind"
            val r = req(
                "POST", verifyUrl, "2fa code verification",
                headers = headers,
                params = linkedMapOf(
                    "_flag" to flag.toString(), "_json" to "true", "sid" to "xiaomiio", "context" to context,
                    "mask" to "0", "_locale" to locale,
                ),
                form = linkedMapOf("_flag" to flag.toString(), "ticket" to code, "trust" to "false", "_json" to "true", "ick" to sessionCookie("ick")),
                extraCookies = if (identitySession.isNotEmpty()) mapOf("identity_session" to identitySession) else emptyMap(),
            )
            if (r.code != 200) throw CloudException("2FA verification failed (HTTP error)")
            val jr = try {
                JSONObject(r.text.replaceFirst("&&&START&&&", ""))
            } catch (e: JSONException) {
                JSONObject()
            }
            val verifyCode = jr.opt("code")
            // no numeric code = ambiguous (continue with in-session checks); non-zero = rejected
            if (verifyCode is Number && verifyCode.toDouble() != 0.0) {
                throw CloudException("Xiaomi rejected the verification code (code=$verifyCode). Get a new code and sign in again.")
            }
            var finishLoc = jr.str("location")?.takeIf { it.isNotEmpty() }
            if (finishLoc == null) {
                finishLoc = r.location() ?: scrape(r.text, "https://account.xiaomi.com/identity/result/check")
            }
            continue2fa(finishLoc, context, locale, headers, notificationUrl, username)
        }

        private suspend fun continue2fa(
            finishLoc: String?,
            context: String,
            locale: String,
            headers: Map<String, String>,
            notificationUrl: String,
            username: String,
        ) {
            if (finishLoc != null) {
                val loc = absAccountUrl(finishLoc)
                // off-allowlist location: do not follow, fall through to the in-session continuation
                if (runCatching { validateUrl(loc) }.isSuccess) {
                    val rLoc = req("GET", loc, "2fa redirect", headers = headers)
                    if (finishChainFrom(rLoc, loc, headers)) return
                }
            }
            if (resultCheck(context, locale, headers)) return
            if (sessionSatisfied(username)) return
            repeat(2) {
                if (!prompts.browserConfirmation(notificationUrl)) return@repeat
                if (resultCheck(context, locale, headers)) return
                if (sessionSatisfied(username)) return
            }
            throw CloudException("2FA verification failed in this session. Sign in again.")
        }

        /** identity/list gives the 2FA methods of the account: 4 = SMS, 8 = email. If unknown, use email. */
        private fun verifyFlag(listText: String): Int {
            val j = runCatching { parseJson(listText, "2fa identity list") }.getOrNull() ?: return FLAG_EMAIL
            val options = j.optJSONArray("options")?.let { a -> (0 until a.length()).map { a.optInt(it) } }.orEmpty()
            val preferred = j.optInt("flag")
            return when {
                preferred in setOf(FLAG_SMS, FLAG_EMAIL) && (options.isEmpty() || preferred in options) -> preferred
                FLAG_EMAIL in options -> FLAG_EMAIL
                FLAG_SMS in options -> FLAG_SMS
                else -> FLAG_EMAIL
            }
        }

        private fun resultCheck(context: String, locale: String, headers: Map<String, String>): Boolean {
            val r0 = req(
                "GET", "https://account.xiaomi.com/identity/result/check", "2fa result check",
                headers = headers, params = mapOf("sid" to "xiaomiio", "context" to context, "_locale" to locale),
            )
            val loc = r0.location() ?: return false
            return finishChainQuiet(loc, headers)
        }

        /** Runs step 1 again in this session. Returns true if it now gives ssecurity and location. */
        private fun sessionSatisfied(username: String): Boolean {
            step1(username)
            return !ssecurity.isNullOrEmpty() && !location.isNullOrEmpty()
        }

        private fun finishChainFrom(response: Resp, fetchedUrl: String, headers: Map<String, String>): Boolean {
            val endUrl = if ("identity/result/check" in fetchedUrl) response.location() else fetchedUrl
            return endUrl != null && finishChainQuiet(endUrl, headers)
        }

        /** Follows result/check 302 -> Auth2/end (ssecurity in extension-pragma) -> STS serviceToken. Returns false at a dead end. */
        private fun finishChainQuiet(finishLoc0: String, headers: Map<String, String>): Boolean {
            val finishLoc = absAccountUrl(finishLoc0)
            val endUrl0 = if ("identity/result/check" in finishLoc) {
                req("GET", finishLoc, "2fa redirect", headers = headers).location()
            } else {
                finishLoc
            } ?: return false
            val endUrl = absAccountUrl(endUrl0)
            var r = req("GET", endUrl, "2fa finish", headers = headers)
            if (r.code == 200 && "Xiaomi Account - Tips" in r.text) r = req("GET", endUrl, "2fa finish", headers = headers)
            r.headers["extension-pragma"]?.takeIf { it.isNotEmpty() }?.let { ext ->
                try {
                    JSONObject(ext).str("ssecurity")?.takeIf { it.isNotEmpty() }?.let { ssecurity = it }
                } catch (e: JSONException) {
                    // ignore, as cloud.py does
                }
            }
            if (ssecurity.isNullOrEmpty()) return false
            val sts = r.location() ?: scrape(r.text, "https://sts.api.io.mi.com/sts") ?: return false
            val rs = req("GET", absAccountUrl(sts), "service token exchange", headers = headers)
            if (rs.code != 200) return false
            serviceToken = sessionCookieDomain("serviceToken", "sts.api.io.mi.com")
            if (serviceToken.isNullOrEmpty()) return false
            if (userId.isNullOrEmpty()) userId = sessionCookie("userId")
            return true
        }

        private fun scrape(text: String, prefix: String): String? {
            val idx = text.indexOf(prefix)
            if (idx == -1) return null
            val end = text.indexOf('"', idx)
            return text.substring(idx, if (end != -1) end else minOf(idx + 300, text.length))
        }
    }

    // ------------------------------------------------------------------ /app API

// Signed, RC4-encrypted POST to https://{region.}api.io.mi.com/app{path}. HTTP 401 sets authRejected.
    private suspend fun encryptedPost(s: CloudSession, path: String, dataJson: String): JSONObject = withContext(Dispatchers.IO) {
        if (s.region !in SERVERS) throw CloudException("unknown region")
        if (s.userId.isBlank()) throw CloudException("session has no account identity (userId). Sign in again.")
        val prefix = if (s.region == "cn") "" else "${s.region}."
        val url = "https://${prefix}api.io.mi.com/app$path"
        val nowMs = ((System.currentTimeMillis() / 1000.0 + s.skewSeconds) * 1000).toLong()
        val nonce = MiEnvelope.generateNonce(nowMs)
        val signed = MiEnvelope.signedNonce(s.ssecurity, nonce)
        val form = MiEnvelope.buildRequestForm(s.ssecurity, nonce, signed, dataJson, path)
        val cookie = linkedMapOf(
            "userId" to s.userId,
            "serviceToken" to s.serviceToken,
            "yetAnotherServiceToken" to s.serviceToken,
            "locale" to "en_GB",
            "timezone" to "GMT+00:00",
            "is_daylight" to "0",
            "dst_offset" to "0",
            "channel" to "MI_APP_STORE",
        ).entries.joinToString("; ") { "${it.key}=${it.value}" }
        val r = call(
            "POST", url, "api call $path",
            headers = mapOf(
                "Accept-Encoding" to "identity",
                "User-Agent" to USER_AGENT,
                "Content-Type" to "application/x-www-form-urlencoded",
                "x-xiaomi-protocal-flag-cli" to "PROTOCAL-HTTP2",
                "MIOT-ENCRYPT-ALGORITHM" to "ENCRYPT-RC4",
            ),
            form = form,
            cookies = { cookie },
        )
        if (r.code == 401) throw CloudException("api call failed: HTTP 401", authRejected = true)
        if (r.code != 200) throw CloudException("api call failed: HTTP ${r.code}")
        parseJson(MiEnvelope.decodeResponseText(s.ssecurity, nonce, r.text, r.headers["MIOT-CONTENT-ENCODING"]), "api call $path")
    }

    override suspend fun listDevices(session: CloudSession): List<CloudDevice> {
        val resp = encryptedPost(session, "/home/device_list", "{\"getVirtualModel\":true,\"getHuamiDevices\":1}")
        val code = resp.opt("code")
        if (code != null && code != JSONObject.NULL && !(code is Number && code.toDouble() == 0.0)) {
            throw CloudException("device list error envelope: code=$code")
        }
        val result = resp.opt("result") as? JSONObject ?: throw CloudException("device list response has no result object")
        val list = result.opt("list") as? JSONArray ?: throw CloudException("device list response has no list")
        return (0 until list.length()).mapNotNull { list.opt(it) as? JSONObject }.map { d ->
            CloudDevice(
                did = d.str("did") ?: "",
                pid = d.str("pid")?.toDoubleOrNull()?.toInt(),
                model = d.str("model"),
                name = d.str("name"),
                mac = d.str("mac"),
                token = d.str("token"),
            )
        }
    }

    /**
     * Gets the latest firmware metadata for a device of the account (`/v2/device/latest_ver`).
     * It only reads metadata. It never starts an OTA.
     *
     * @param did Cloud device ID.
     * @param model `njcuk.fitting.ad1204` or `njcuk.fitting.1204e`.
     * @return The offered version, URL (`safe_url` first), MD5 and changelog. The URL is not checked here.
     * @throws CloudException If the model is not supported, the request fails, or no valid package is offered.
     */
    suspend fun latestFirmware(session: CloudSession, did: String, model: String): FirmwareInfo {
        if (model !in setOf("njcuk.fitting.ad1204", "njcuk.fitting.1204e"))
            throw CloudException("This charger model is not supported for firmware downloads")
        val resp = encryptedPost(session, "/v2/device/latest_ver", JSONObject().put("did", did).toString())
        if (resp.optInt("code", -1) != 0) throw CloudException("Xiaomi did not return firmware metadata")
        val result = resp.optJSONObject("result") ?: throw CloudException("No firmware was offered")
        val version = result.optString("version", "")
        val md5 = result.optString("md5", "").lowercase(java.util.Locale.US)
        if (!version.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+_[0-9]+")) || !md5.matches(Regex("[0-9a-f]{32}")))
            throw CloudException("No downloadable firmware package was offered")
        val url = result.optString("safe_url", "").ifBlank { result.optString("url", "") }
        return FirmwareInfo(model, version, url, md5, result.optString("changeLog", ""))
    }

    override suspend fun applyDid(session: CloudSession, mac: String, model: String, tokenHex: String, factoryDid: String): String {
        val resp = encryptedPost(session, "/device/bltapplydid", MiEnvelope.buildApplydidBody(mac, model, tokenHex, factoryDid))
        val did = payload(resp).str("did")?.trim().orEmpty()
        if (did.isEmpty()) throw CloudException("bltapplydid response has no did")
        return did
    }

    override suspend fun standardBind(session: CloudSession, did: String, tokenHex: String, bindKeyHex: String, smac: String): BindMaterial {
        val resp = encryptedPost(
            session, "/v2/device/ble_standard_bind",
            MiEnvelope.buildStandardBindBody(did, tokenHex, bindKeyHex, smac),
        )
        val p = payload(resp)
        if (!truthy(p.opt("success"))) throw CloudException("ble_standard_bind reported success=false")
        val cloudSign = MiEnvelope.decodeB64Field(p.str("cloud_sign") ?: "")
        if (cloudSign.size != 64) throw CloudException("cloud_sign must decode to 64 bytes, got ${cloudSign.size}")
        val cloudCert = MiEnvelope.decodeB64Field(p.str("cloud_cert") ?: "")
        val utc = when (val u = p.opt("utc")) {
            is Boolean -> if (u) 1L else 0L // Python int(True) == 1
            is Number -> u.toLong()
            is String -> u.trim().toLongOrNull()
            else -> null
        } ?: throw CloudException("ble_standard_bind response has no valid utc")
        if (utc !in 1..0xFFFFFFFFL) throw CloudException("utc out of u32 range: $utc")
        return BindMaterial(cloudSign, cloudCert, utc)
    }

    override suspend fun removeDevice(session: CloudSession, did: String, pid: Int) {
        val resp = encryptedPost(session, "/user/del_owner_device_batch", MiEnvelope.buildRemoveBody(did, pid))
        val code = resp.opt("code")
        if (!(code is Number && code.toDouble() == 0.0)) {
            throw CloudException("remove device failed: code=${resp.str("code")} message=${resp.str("message")}")
        }
    }

    private companion object {
        val SERVERS = setOf("cn", "de", "us", "ru", "tw", "sg", "in", "i2")
        val ALLOWED_HOSTS = setOf("account.xiaomi.com", "sts.api.io.mi.com", "api.io.mi.com") +
            SERVERS.map { "$it.api.io.mi.com" }
        val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
        const val MAX_RESPONSE_BYTES = 1 shl 20
        const val MAX_CAPTCHA_BYTES = 512 shl 10
        const val MAX_USERNAME_LEN = 128
        const val MAX_CAPTCHA_ATTEMPTS = 5
        const val FLAG_SMS = 4
        const val FLAG_EMAIL = 8
        val LETTERS = ('a'..'z') + ('A'..'Z')
        val USER_AGENT = "Android-7.1.1-1.0.0-ONEPLUS A3010-136-" +
            // Mi Home style User-Agent that the cloud API expects, for interoperability (as in Xiaomi-cloud-tokens-extractor).
            (1..13).map { ('A'..'Z').random() }.joinToString("") + " APP/xiaomi.smarthome APPV/62830"

        /** Accepts only https, port 443, no userinfo and an official host. The error message never contains the URL. */
        fun validateUrl(url: String): HttpUrl {
            val u = url.toHttpUrlOrNull() ?: throw CloudException("server supplied a malformed URL")
            if (u.scheme != "https") throw CloudException("server supplied a non-https URL (refused)")
            if (u.username.isNotEmpty() || u.password.isNotEmpty()) throw CloudException("server supplied a URL with userinfo (refused)")
            if (u.port != 443) throw CloudException("server supplied a non-443 port (refused)")
            if (u.host.lowercase() !in ALLOWED_HOSTS) {
                throw CloudException("server supplied a URL on an unexpected host (refused; official hosts: account.xiaomi.com, sts.api.io.mi.com, {region.}api.io.mi.com)")
            }
            return u
        }

        /** Resolves a bare server path against the account origin before the allowlist check. */
        fun absAccountUrl(url: String): String {
            if (url.isEmpty() || url.startsWith("//") || Regex("^[A-Za-z][A-Za-z0-9+.-]*:").containsMatchIn(url)) return url
            return "https://account.xiaomi.com".toHttpUrl().resolve(url)?.toString() ?: url
        }

        fun parseJson(text: String, stage: String): JSONObject = try {
            JSONObject(text.replaceFirst("&&&START&&&", ""))
        } catch (e: JSONException) {
            throw CloudException("unexpected (non-JSON) response during $stage")
        }

        /** Unwraps {"result": {...}} if the server puts the payload there. */
        fun payload(obj: JSONObject): JSONObject {
            val result = obj.opt("result") as? JSONObject ?: return obj
            return if (result.has("did") || result.has("success") || result.has("list")) result else obj
        }

/** Python truth value, as cloud.py uses it. */
        fun truthy(v: Any?): Boolean = when (v) {
            null, JSONObject.NULL -> false
            is Boolean -> v
            is Number -> v.toDouble() != 0.0
            is String -> v.isNotEmpty()
            is JSONObject -> v.length() > 0
            is JSONArray -> v.length() > 0
            else -> true
        }

        fun JSONObject.str(k: String): String? = opt(k)?.takeIf { it != JSONObject.NULL }?.toString()
    }
}
