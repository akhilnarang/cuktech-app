package dev.akhilnarang.cuktech.firmware

import android.content.Context
import dev.akhilnarang.cuktech.proto.AndroidGattPort
import dev.akhilnarang.cuktech.bind.BleChargerScanner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.first

/**
 * Installs a checked firmware package on a bound charger. Start it only after the user confirms.
 * After the transfer, it reconnects and reads the running version through a new authenticated link.
 */
internal class FirmwareInstaller(private val context: Context) {
/**
 * Sends [image] to the charger and confirms the new running version.
 *
 * The charger must advertise pid 0x660e as bound, and it must run [FirmwarePackage.RECEIVER_VERSION].
 * Downgrades are refused. After the transfer, it waits 5 s, then tries to verify a maximum of 6 times,
 * 3 s apart. It never sends the image a second time. The total time limit is 20 minutes.
 *
 * @param address Charger BLE MAC address.
 * @param token 12-byte BLE login token.
 * @param progress Called with the sent bytes and the total bytes.
 * @param phase Called with a short user-facing text when a new step starts.
 * @param observedVersion Called with each running version that the app reads.
 * @return True if the image version was already installed (reinstall). False for an update.
 * @throws IllegalStateException If a check or the transfer fails, or the new version cannot be confirmed.
 * @throws kotlinx.coroutines.TimeoutCancellationException If the scan or the complete install takes too long.
 */
    suspend fun install(address: String, token: ByteArray, image: FirmwarePackage,
                        progress: (Int, Int) -> Unit, phase: (String) -> Unit,
                        observedVersion: (String) -> Unit): Boolean = withTimeout(20 * 60_000L) {
        phase("Checking charger identity")
        val advertised = withTimeout(15_000) { BleChargerScanner(context).scan().first { it.address.equals(address, true) } }
        check(advertised.pid == 0x660e && advertised.registered) { "Direct installation requires a bound China-model AD1204" }
        phase("Connecting and authenticating")
        val link = FirmwareGattLink(AndroidGattPort(context))
        var reinstall = false
        try {
            link.open(address, token)
            val current = link.version()
            observedVersion(current)
            check(current == FirmwarePackage.RECEIVER_VERSION) {
                "Direct installation is known only for ${FirmwarePackage.RECEIVER_VERSION}. The charger reports $current."
            }
            check(compareVersions(image.info.version, current) >= 0) { "Firmware downgrades are not supported" }
            reinstall = current == image.info.version
            FirmwareTransfer(link).send(image.bytes, progress, phase)
        } finally { link.close() }
        // The receiver starts its activation delay only after disconnect.
        phase("Waiting for restart and checking running firmware")
        delay(5_000)
        repeat(6) { attempt ->
            val verify = FirmwareGattLink(AndroidGattPort(context))
            try {
                verify.open(address, token)
                val running = verify.version()
                observedVersion(running)
                if (running == image.info.version) return@withTimeout reinstall
            } catch (e: CancellationException) { throw e }
            catch (_: Exception) { /* Reboot discovery/auth may take several attempts. Never repeat the flash. */ }
            finally { verify.close() }
            if (attempt < 5) delay(3_000)
        }
        error("Transfer complete, but the app cannot confirm the new running version. Reconnect and check it before you try again.")
    }

// Compares `X.Y.Z_NNNN` versions part by part as numbers.
    private fun compareVersions(a: String, b: String): Int {
        val av = a.split('.', '_').map { it.toInt() }
        val bv = b.split('.', '_').map { it.toInt() }
        for (i in av.indices) if (av[i] != bv[i]) return av[i].compareTo(bv[i])
        return 0
    }
}
