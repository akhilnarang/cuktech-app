package dev.akhilnarang.cuktech.firmware

import dev.akhilnarang.cuktech.CloudException
import org.junit.Assert.*
import org.junit.Test

class FirmwareUrlTest {
    @Test fun officialCdnIsAccepted() {
        assertEquals("iot-ota-cdn.io.mi.com", FirmwareDownloader.officialUrl("https://iot-ota-cdn.io.mi.com/miio_fw/example.bin").host)
    }

    @Test fun credentialsAndLookalikeHostsCannotReceiveADownload() {
        for (url in listOf("http://iot-ota-cdn.io.mi.com/a.bin", "https://mi.com.attacker.example/a.bin",
            "https://attacker-mi.com/a.bin", "https://user:secret@iot-ota-cdn.io.mi.com/a.bin",
            "https://iot-ota-cdn.io.mi.com:8443/a.bin")) {
            try { FirmwareDownloader.officialUrl(url); fail("should reject unsafe download") }
            catch (e: CloudException) { assertFalse(e.message!!.contains("secret")) }
        }
    }
}
