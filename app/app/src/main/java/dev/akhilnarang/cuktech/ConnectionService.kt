package dev.akhilnarang.cuktech

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Foreground service that keeps the process alive while the app is in the background.
 *
 * The app starts it while the charger is connected or while a firmware update runs.
 * The BLE session stays in ControllerViewModel or FirmwareViewModel. This service only holds
 * the foreground slot and shows an ongoing notification. Tapping the notification opens the
 * existing task.
 */
class ConnectionService : Service() {
  override fun onBind(intent: Intent?): IBinder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val nm = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= 26) {
      nm.createNotificationChannel(NotificationChannel(CHANNEL, "Charger connection", NotificationManager.IMPORTANCE_LOW))
    }
    val open = PendingIntent.getActivity(
      // launcher intent brings the existing task forward instead of a second activity (and session)
      this, 0, packageManager.getLaunchIntentForPackage(packageName) ?: Intent(this, MainActivity::class.java),
      PendingIntent.FLAG_IMMUTABLE,
    )
    val notification = NotificationCompat.Builder(this, CHANNEL)
      .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
      .setContentTitle(if (intent?.getBooleanExtra("firmware", false) == true) "Updating charger firmware" else "Connected to charger")
      .setContentText(if (intent?.getBooleanExtra("firmware", false) == true) "Keep the charger on power. Open CUKTECH Local to see the progress."
          else "Live data continues in the background. To stop, disconnect in the app.")
      .setContentIntent(open)
      .setOngoing(true)
      .build()
    ServiceCompat.startForeground(
      this, 1, notification,
      if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE else 0,
    )
    return START_NOT_STICKY
  }

  companion object {
    private const val CHANNEL = "connection"

/**
 * Starts the service in the foreground.
 *
 * @param context Any context. The service uses the application process.
 * @param firmware True to show the firmware-update notification text. If true, a start failure
 *   (for example, a background-start restriction) is thrown. If false, the failure is ignored.
 * @throws IllegalStateException If [firmware] is true and Android does not allow the start.
 */
    fun start(context: Context, firmware: Boolean = false) {
      val intent = Intent(context, ConnectionService::class.java).putExtra("firmware", firmware)
      if (firmware) context.startForegroundService(intent)
      else runCatching { context.startForegroundService(intent) }
    }

/** Stops the service and removes its notification. Safe to call if the service is not running. */
    fun stop(context: Context) {
      context.stopService(Intent(context, ConnectionService::class.java))
    }
  }
}
