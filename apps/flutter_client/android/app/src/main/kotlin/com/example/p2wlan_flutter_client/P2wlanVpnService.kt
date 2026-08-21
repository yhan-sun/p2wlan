package com.example.p2wlan_flutter_client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import java.io.File

/**
 * Android-owned lifecycle for the P2WLAN overlay VPN.
 *
 * The Builder installs only the P2WLAN overlay CIDR. It intentionally does
 * not install a default route, so control-plane HTTPS and direct/relay UDP
 * continue over the physical network and cannot hairpin through this VPN.
 */
class P2wlanVpnService : VpnService() {
    companion object {
        private const val TAG = "P2wlanVpnService"
        private const val CHANNEL_ID = "p2wlan_vpn"
        private const val NOTIFICATION_ID = 39277
        const val ACTION_START = "com.example.p2wlan_flutter_client.action.START"
        const val ACTION_STOP = "com.example.p2wlan_flutter_client.action.STOP"
        const val EXTRA_REQUEST_JSON = "request_json"

        @Volatile
        private var serviceRunning = false

        fun isRunning(): Boolean = serviceRunning && P2wlanNative.isRunning()

        fun diagnosticsAuthPath(context: Context): File {
            return File(File(context.filesDir, "p2wlan"), "p2wlan-daemon.diag-auth")
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        val requestJson = intent?.getStringExtra(EXTRA_REQUEST_JSON)
        if (requestJson.isNullOrBlank()) {
            Log.e(TAG, "VPN start request is empty")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (!isRunning()) {
            startVpn(requestJson)
        }
        return START_NOT_STICKY
    }

    private fun startVpn(requestJson: String) {
        var detachedFd = -1
        try {
            createNotificationChannel()
            val notification = buildNotification()
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }

            val request = JSONObject(requestJson)
            val overlay = parseCidr(request.optString("overlay_cidr", "10.20.0.0/16"))
            val address = validIpv4(request.optString("virtual_ip"))
                ?: "10.20.0.1"
            val mtu = request.optInt("mtu", 1420).coerceIn(576, 65535)

            val builder = Builder()
                .setSession("P2WLAN")
                .setMtu(mtu)
                .setBlocking(false)
                // Only the overlay is captured. Public control/relay endpoints
                // never match this route and therefore stay on Wi-Fi/mobile.
                .addAddress(address, overlay.second)
                .addRoute(overlay.first, overlay.second)

            val established = builder.establish()
                ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
            detachedFd = established.detachFd()
            vpnInterface = null

            val enrichedRequest = enrichRequest(request)
            val nativeError = P2wlanNative.start(detachedFd, enrichedRequest.toString())
            if (!nativeError.isNullOrBlank()) {
                closeDetachedFd(detachedFd)
                detachedFd = -1
                throw IllegalStateException(nativeError)
            }
            detachedFd = -1
            serviceRunning = true
            Log.i(TAG, "P2WLAN Android VPN started")
        } catch (error: Throwable) {
            Log.e(TAG, "Failed to start P2WLAN Android VPN", error)
            if (detachedFd >= 0) closeDetachedFd(detachedFd)
            vpnInterface?.close()
            vpnInterface = null
            serviceRunning = false
            stopForeground(true)
            stopSelf()
        }
    }

    private fun stopVpn() {
        try {
            if (P2wlanNative.isRunning()) {
                P2wlanNative.stop()
            }
        } catch (error: Throwable) {
            Log.w(TAG, "Failed to request Rust daemon shutdown", error)
        }
        serviceRunning = false
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(true)
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (P2wlanNative.isRunning()) {
            P2wlanNative.stop()
        }
        serviceRunning = false
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun enrichRequest(request: JSONObject): JSONObject {
        val directory = File(filesDir, "p2wlan")
        if (!directory.exists()) directory.mkdirs()
        if (!request.has("config_path")) {
            request.put("config_path", File(directory, "p2wlan-config.json").absolutePath)
        }
        if (!request.has("log_path")) {
            request.put("log_path", File(directory, "p2wlan-daemon.log").absolutePath)
        }
        if (!request.has("diagnostics_auth_path")) {
            request.put(
                "diagnostics_auth_path",
                File(directory, "p2wlan-daemon.diag-auth").absolutePath,
            )
        }
        return request
    }

    private fun parseCidr(cidr: String): Pair<String, Int> {
        val parts = cidr.trim().split("/")
        val network = validIpv4(parts.firstOrNull()) ?: "10.20.0.0"
        val prefix = parts.getOrNull(1)?.toIntOrNull()?.coerceIn(0, 32) ?: 16
        return Pair(network, prefix)
    }

    private fun validIpv4(value: String?): String? {
        val parts = value?.trim()?.split(".") ?: return null
        if (parts.size != 4) return null
        if (parts.any { it.isEmpty() || it.toIntOrNull() !in 0..255 }) return null
        return parts.joinToString(".")
    }

    private fun closeDetachedFd(fd: Int) {
        try {
            ParcelFileDescriptor.adoptFd(fd).close()
        } catch (error: Throwable) {
            Log.w(TAG, "Failed to close detached VPN fd", error)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "P2WLAN VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "P2WLAN overlay network is active"
            },
        )
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("P2WLAN")
                .setContentText("Overlay VPN is active")
                .setSmallIcon(applicationInfo.icon)
                .setOngoing(true)
                .build()
        } else {
            Notification.Builder(this)
                .setContentTitle("P2WLAN")
                .setContentText("Overlay VPN is active")
                .setSmallIcon(applicationInfo.icon)
                .setOngoing(true)
                .build()
        }
    }
}
