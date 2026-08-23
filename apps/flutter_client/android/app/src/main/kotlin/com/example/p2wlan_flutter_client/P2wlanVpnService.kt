package com.example.p2wlan_flutter_client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
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
        private const val STATE_PREFERENCES = "p2wlan_vpn_state"
        private const val STATE_START_REQUEST = "start_request_json"
        private const val RESTART_INITIAL_DELAY_MS = 1_000L
        private const val RESTART_MAX_DELAY_MS = 60_000L
        private const val MAX_AUTOMATIC_RESTARTS = 8
        const val ACTION_START = "com.example.p2wlan_flutter_client.action.START"
        const val ACTION_STOP = "com.example.p2wlan_flutter_client.action.STOP"
        const val EXTRA_REQUEST_JSON = "request_json"

        @Volatile
        private var serviceRunning = false

        @Volatile
        private var serviceError: String? = null

        fun isRunning(): Boolean = serviceRunning && P2wlanNative.isRunning()

        fun lastError(): String? = serviceError ?: P2wlanNative.lastError()

        fun diagnosticsAuthPath(context: Context): File {
            return File(File(context.filesDir, "p2wlan"), "p2wlan-daemon.diag-auth")
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile
    private var monitorGeneration = 0L
    private var monitorThread: Thread? = null
    private var lastRequestJson: String? = null
    private var restartRunnable: Runnable? = null
    private var restartAttempts = 0
    @Volatile
    private var explicitStop = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            explicitStop = true
            stopVpn()
            return START_NOT_STICKY
        }

        explicitStop = false
        val requestJson = intent?.getStringExtra(EXTRA_REQUEST_JSON)
            ?.takeIf { it.isNotBlank() }
            ?: loadPersistedStartRequest()
        if (requestJson.isNullOrBlank()) {
            Log.e(TAG, "VPN start request is empty")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        lastRequestJson = requestJson
        persistStartRequest(requestJson)
        if (!isRunning()) {
            startVpn(requestJson)
        }
        // Android may recreate a foreground service after the process is
        // reclaimed. Returning START_STICKY lets the service come back and
        // the private persisted request above supplies the missing Intent.
        return START_STICKY
    }

    private fun startVpn(requestJson: String) {
        var detachedFd = -1
        try {
            stopMonitor()
            cancelAutomaticRestart()
            serviceError = null
            lastRequestJson = requestJson
            persistStartRequest(requestJson)
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
            val nativeError = P2wlanNative.start(this, detachedFd, enrichedRequest.toString())
            // Ownership of the detached fd is transferred to P2wlanNative as
            // soon as nativeStart is invoked. Native startup/error paths (and
            // the Kotlin library-load fallback) close it; Kotlin must not
            // close the integer a second time after this call returns.
            detachedFd = -1
            if (!nativeError.isNullOrBlank()) {
                throw IllegalStateException(nativeError)
            }
            serviceRunning = true
            restartAttempts = 0
            startNativeMonitor()
            Log.i(TAG, "P2WLAN Android VPN started")
        } catch (error: Throwable) {
            val message = "Android VPN 服务启动失败：${error.message ?: error::class.java.simpleName}"
            serviceError = message
            Log.e(TAG, message, error)
            if (detachedFd >= 0) closeDetachedFd(detachedFd)
            vpnInterface?.close()
            vpnInterface = null
            serviceRunning = false
            if (!explicitStop && scheduleAutomaticRestart(requestJson)) {
                return
            }
            stopForeground(true)
            stopSelf()
        }
    }

    private fun stopVpn() {
        explicitStop = true
        lastRequestJson = null
        restartAttempts = 0
        cancelAutomaticRestart()
        clearPersistedStartRequest()
        serviceRunning = false
        stopMonitor()
        try {
            if (P2wlanNative.isRunning()) {
                P2wlanNative.stop()
            }
        } catch (error: Throwable) {
            Log.w(TAG, "Failed to request Rust daemon shutdown", error)
        }
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
        serviceRunning = false
        cancelAutomaticRestart()
        stopMonitor()
        if (P2wlanNative.isRunning()) {
            P2wlanNative.stop()
        }
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    /**
     * A Rust daemon can fail after JNI has successfully accepted the TUN fd
     * (for example, when a stored control token is rejected). Keep the
     * foreground service and VPN interface from looking alive in that case,
     * and retain a useful error for Flutter's status call.
     */
    private fun startNativeMonitor() {
        val generation = ++monitorGeneration
        val thread = Thread({
            try {
                while (serviceRunning && P2wlanNative.isRunning()) {
                    Thread.sleep(250)
                }
            } catch (_: InterruptedException) {
                return@Thread
            }
            if (!serviceRunning || generation != monitorGeneration) return@Thread

            val error = P2wlanNative.lastError()
                ?: "Android VPN 本地 daemon 已退出，请查看诊断日志。"
            mainHandler.post {
                if (!serviceRunning || generation != monitorGeneration) return@post
                serviceError = error
                serviceRunning = false
                Log.e(TAG, error)
                val requestJson = lastRequestJson
                if (!explicitStop && requestJson != null && scheduleAutomaticRestart(requestJson)) {
                    return@post
                }
                stopForeground(true)
                stopSelf()
            }
        }, "p2wlan-native-monitor")
        monitorThread = thread
        thread.start()
    }

    private fun stopMonitor() {
        monitorGeneration += 1
        monitorThread?.interrupt()
        monitorThread = null
    }

    /**
     * Keep an unexpected Rust/VPN exit recoverable.  This is deliberately
     * bounded and backoff-based: a transient control/relay failure gets a new
     * TUN and registration, while a persistent bad token does not create a
     * tight foreground-service restart loop.
     */
    private fun scheduleAutomaticRestart(requestJson: String): Boolean {
        if (explicitStop || restartRunnable != null) return true
        if (restartAttempts >= MAX_AUTOMATIC_RESTARTS) {
            serviceError = "Android VPN 自动重启次数已达上限，请重新点击启动。"
            Log.e(TAG, serviceError ?: "Android VPN automatic restart limit reached")
            return false
        }

        restartAttempts += 1
        val exponent = (restartAttempts - 1).coerceIn(0, 6)
        val delayMs = (RESTART_INITIAL_DELAY_MS * (1L shl exponent))
            .coerceAtMost(RESTART_MAX_DELAY_MS)
        val restart = Runnable {
            restartRunnable = null
            if (explicitStop || isRunning()) return@Runnable
            startVpn(requestJson)
        }
        restartRunnable = restart
        Log.w(
            TAG,
            "Android VPN/native daemon exited; retrying in ${delayMs}ms " +
                "(attempt $restartAttempts/$MAX_AUTOMATIC_RESTARTS)",
        )
        mainHandler.postDelayed(restart, delayMs)
        return true
    }

    private fun cancelAutomaticRestart() {
        restartRunnable?.let(mainHandler::removeCallbacks)
        restartRunnable = null
    }

    private fun statePreferences() = getSharedPreferences(STATE_PREFERENCES, Context.MODE_PRIVATE)

    private fun persistStartRequest(requestJson: String) {
        statePreferences().edit().putString(STATE_START_REQUEST, requestJson).apply()
    }

    private fun loadPersistedStartRequest(): String? {
        return statePreferences().getString(STATE_START_REQUEST, null)
    }

    private fun clearPersistedStartRequest() {
        statePreferences().edit().remove(STATE_START_REQUEST).apply()
    }

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
