package dev.akhilnarang.cuktech.bind

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import dev.akhilnarang.cuktech.ChargerAdvert
import dev.akhilnarang.cuktech.ChargerScanning
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow

/**
 * BLE scanner for AD1204U chargers. It matches FE95 service data with a known product id.
 * Each flow starts its own low-latency scan and stops it when the collector cancels.
 */
class BleChargerScanner(context: Context) : ChargerScanning {
    private val context = context.applicationContext

    /**
     * Scans for chargers.
     *
     * @return A cold flow of adverts. It sends an address again only when a field changes.
     *   The flow fails with [SecurityException] if the scan permission is missing, and with
     *   [IllegalStateException] if Bluetooth is off or the scan fails.
     */
    override fun scan(): Flow<ChargerAdvert> = flow {
        val last = HashMap<String, ChargerAdvert>()
        frames().collect { (r, f) ->
            val a = ChargerAdvert(r.device.address, r.scanRecord?.deviceName, f.productId!!, f.registered, r.rssi)
            if (last.put(a.address, a) != a) emit(a) // re-emit an address only when something changed
        }
    }

    /**
     * Sends each matching advert (AD1204U product ids only), with no duplicate filter.
     * The flow fails in the same way as [scan].
     *
     * @return A cold flow of scan results and their parsed FE95 frames.
     */
    internal fun frames(): Flow<Pair<ScanResult, Fe95Frame>> = callbackFlow {
        val perm = if (Build.VERSION.SDK_INT >= 31) Manifest.permission.BLUETOOTH_SCAN
        else Manifest.permission.ACCESS_FINE_LOCATION
        if (context.checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED) {
            close(SecurityException("Bluetooth scan permission not granted ($perm)"))
            return@callbackFlow
        }
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        val scanner = adapter?.takeIf { it.isEnabled }?.bluetoothLeScanner
        if (scanner == null) {
            close(IllegalStateException("Bluetooth is off"))
            return@callbackFlow
        }
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, r: ScanResult) {
                val data = r.scanRecord?.getServiceData(FE95_UUID) ?: return
                val f = Fe95.parse(data) ?: return
                if (f.productId in Fe95.MODELS) trySend(r to f)
            }

            override fun onScanFailed(errorCode: Int) {
                close(IllegalStateException("Bluetooth scan failed (code $errorCode)"))
            }
        }
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        try {
            scanner.startScan(null, settings, cb)
        } catch (e: SecurityException) {
            close(e)
            return@callbackFlow
        }
        awaitClose {
            try {
                scanner.stopScan(cb)
            } catch (_: Exception) {
                // Bluetooth turned off or permission revoked mid-scan: nothing to stop
            }
        }
    }

    private companion object {
        val FE95_UUID: ParcelUuid = ParcelUuid.fromString("0000fe95-0000-1000-8000-00805f9b34fb")
    }
}
