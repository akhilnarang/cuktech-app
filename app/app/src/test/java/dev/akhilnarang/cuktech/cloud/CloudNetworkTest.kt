package dev.akhilnarang.cuktech.cloud

import dev.akhilnarang.cuktech.CloudException
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException

class CloudNetworkTest {
    private fun response(chain: Interceptor.Chain, code: Int = 200, text: String = "ok"): Response =
        Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
            .code(code).message("test").body(text.toResponseBody()).build()

    private fun client(interceptor: Interceptor) = XiaomiCloudClient(OkHttpClient.Builder()
        .followRedirects(false).retryOnConnectionFailure(false).addInterceptor(interceptor).build())

    @Test fun firstConnectionFailureDuringLoginStartRecovers() {
        var requests = 0
        val api = client { chain ->
            if (++requests == 1) throw IOException("sensitive query must not be printed")
            response(chain)
        }
        assertEquals(200, api.call("GET", "https://account.xiaomi.com/pass/serviceLogin", "login step 1").code)
        assertEquals(2, requests)
    }

    @Test fun readOnlyPostRecoversAfterDroppedResponse() {
        var requests = 0
        val api = client { chain -> if (++requests == 1) throw SocketTimeoutException("secret") else response(chain) }
        assertEquals(200, api.call("POST", "https://api.io.mi.com/app/home/device_list", "device list").code)
        assertEquals(2, requests)
    }

    @Test fun passwordSubmissionIsNotReplayedAfterAmbiguousTimeout() {
        var requests = 0
        val api = client { ++requests; throw SocketTimeoutException("password-hash=private") }
        try {
            api.call("POST", "https://account.xiaomi.com/pass/serviceLoginAuth2", "login step 2")
            fail("expected a sanitized timeout")
        } catch (e: CloudException) {
            assertTrue(e.message!!.contains("login step 2"))
            assertFalse(e.message!!.contains("private"))
        }
        assertEquals(1, requests)
    }

    @Test fun dnsFailureBeforeSubmissionCanBeRetried() {
        var requests = 0
        val api = client { chain -> if (++requests == 1) throw UnknownHostException("secret") else response(chain) }
        assertEquals(200, api.call("POST", "https://account.xiaomi.com/pass/serviceLoginAuth2", "login step 2").code)
        assertEquals(2, requests)
    }

    @Test fun accountMutationIsNotReplayedAfterConnectionDrops() {
        var requests = 0
        val api = client { ++requests; throw IOException("secret") }
        try { api.call("POST", "https://api.io.mi.com/app/device/bltapplydid", "bind"); fail() }
        catch (e: CloudException) { assertFalse(e.message!!.contains("secret")) }
        assertEquals(1, requests)
    }

    @Test fun transientGetServerErrorIsRetriedOnce() {
        var requests = 0
        val api = client { chain -> response(chain, if (++requests == 1) 503 else 200) }
        assertEquals(200, api.call("GET", "https://account.xiaomi.com/pass/serviceLogin", "login step 1").code)
        assertEquals(2, requests)
    }

    @Test fun tlsFailureDoesNotRetryOrExposeExceptionText() {
        var requests = 0
        val api = client { ++requests; throw SSLHandshakeException("secret") }
        try { api.call("GET", "https://account.xiaomi.com/pass/serviceLogin", "login step 1"); fail() }
        catch (e: CloudException) { assertFalse(e.message!!.contains("secret")) }
        assertEquals(1, requests)
    }

    @Test fun retryHasABound() {
        var requests = 0
        val api = client { ++requests; throw IOException("secret") }
        try { api.call("GET", "https://account.xiaomi.com/pass/serviceLogin", "login step 1"); fail() }
        catch (e: CloudException) { assertFalse(e.message!!.contains("secret")) }
        assertEquals(2, requests)
    }
}
