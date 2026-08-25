package com.example.p2wlan_flutter_client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
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
        private const val HEALTHY_RUNTIME_RESET_DELAY_MS = 30_000L
        private const val NATIVE_MONITOR_INTERVAL_MS = 250L
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
    private var wifiLatencyLock: WifiManager.WifiLock? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile
    private var monitorGeneration = 0L
    private var monitorThread: Thread? = null
    @Volatile
    private var nativeReadyObserved = false
    private var nativeStartedAtElapsedMs = 0L
    private var healthyBudgetResetRunnable: Runnable? = null
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

        // A user-initiated START is an explicit request to try again after a
        // previous bounded crash budget. Android service recreation has a
        // null action and must retain the existing budget.
        if (intent?.action == ACTION_START) {
            restartAttempts = 0
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
            val experiment = AndroidExperimentConfig.from(request)
            val overlay = parseCidr(request.optString("overlay_cidr", "10.20.0.0/16"))
            val address = validIpv4(request.optString("virtual_ip"))
                ?: "10.20.0.1"
            val mtu = request.optInt("mtu", 1420).coerceIn(576, 65535)

            val builder = Builder()
                .setSession("P2WLAN")
                .setMtu(mtu)
                .setBlocking(experiment.tunMode == AndroidTunMode.DEDICATED_BLOCKING)
                // Only the overlay is captured. Public control/relay endpoints
                // never match this route and therefore stay on Wi-Fi/mobile.
                .addAddress(address, overlay.second)
                .addRoute(overlay.first, overlay.second)

            val established = builder.establish()
                ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
            detachedFd = established.detachFd()
            vpnInterface = null
            configureWifiLatencyMode(experiment.wifiLowLatencyRequested)

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
            nativeStartedAtElapsedMs = SystemClock.elapsedRealtime()
            nativeReadyObserved = false
            serviceRunning = true
            Log.i(
                TAG,
                "event=android_daemon_started " +
                    "restart_attempt=$restartAttempts " +
                    "android_tun_mode=${experiment.tunMode.wireValue} " +
                    "android_wifi_low_latency=${experiment.wifiLowLatencyRequested}",
            )
            startNativeMonitor()
            Log.i(TAG, "P2WLAN Android VPN started")
        } catch (error: Throwable) {
            val message = "Android VPN 服务启动失败：${error.message ?: error::class.java.simpleName}"
            serviceError = message
            Log.e(TAG, message, error)
            if (detachedFd >= 0) closeDetachedFd(detachedFd)
            releaseWifiLatencyMode()
            vpnInterface?.close()
            vpnInterface = null
            serviceRunning = false
            if (!explicitStop && scheduleAutomaticRestart(requestJson, message)) {
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
        nativeReadyObserved = false
        nativeStartedAtElapsedMs = 0L
        stopMonitor()
        try {
            if (P2wlanNative.isRunning()) {
                P2wlanNative.stop()
            }
        } catch (error: Throwable) {
            Log.w(TAG, "Failed to request Rust daemon shutdown", error)
        }
        releaseWifiLatencyMode()
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
        nativeReadyObserved = false
        nativeStartedAtElapsedMs = 0L
        cancelAutomaticRestart()
        stopMonitor()
        if (P2wlanNative.isRunning()) {
            P2wlanNative.stop()
        }
        releaseWifiLatencyMode()
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
                    if (!nativeReadyObserved && P2wlanNative.isReady()) {
                        nativeReadyObserved = true
                        val readyAtElapsedMs = SystemClock.elapsedRealtime()
                        mainHandler.post {
                            if (
                                !serviceRunning ||
                                generation != monitorGeneration ||
                                !P2wlanNative.isRunning() ||
                                !P2wlanNative.isReady()
                            ) {
                                return@post
                            }
                            val startupRuntimeMs =
                                readyAtElapsedMs - nativeStartedAtElapsedMs
                            Log.i(
                                TAG,
                                "event=android_daemon_ready " +
                                    "restart_attempt=$restartAttempts " +
                                    "startup_runtime_ms=$startupRuntimeMs " +
                                    "healthy_reset_delay_ms=$HEALTHY_RUNTIME_RESET_DELAY_MS",
                            )
                            scheduleHealthyBudgetReset(generation)
                        }
                    }
                    Thread.sleep(NATIVE_MONITOR_INTERVAL_MS)
                }
            } catch (_: InterruptedException) {
                return@Thread
            }
            if (!serviceRunning || generation != monitorGeneration) return@Thread

            val error = P2wlanNative.lastError()
                ?: "Android VPN 本地 daemon 已退出，请查看诊断日志。"
            val runtimeMs = (SystemClock.elapsedRealtime() - nativeStartedAtElapsedMs)
                .coerceAtLeast(0L)
            mainHandler.post {
                if (!serviceRunning || generation != monitorGeneration) return@post
                cancelHealthyBudgetReset()
                serviceError = error
                serviceRunning = false
                releaseWifiLatencyMode()
                Log.e(
                    TAG,
                    "event=android_daemon_exited " +
                        "restart_attempt=$restartAttempts " +
                        "runtime_ms=$runtimeMs " +
                        "exit_reason=${compactLogReason(error)}",
                )
                val requestJson = lastRequestJson
                if (
                    !explicitStop &&
                    requestJson != null &&
                    scheduleAutomaticRestart(requestJson, error)
                ) {
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
        cancelHealthyBudgetReset()
    }

    /**
     * Reset the crash budget only after the native daemon has reported ready
     * and remained alive for the full health window. A successful nativeStart
     * means only that the runtime handle was installed; it is not a healthy
     * daemon boot.
     */
    private fun scheduleHealthyBudgetReset(generation: Long) {
        cancelHealthyBudgetReset()
        val reset = Runnable {
            healthyBudgetResetRunnable = null
            if (
                !serviceRunning ||
                generation != monitorGeneration ||
                !nativeReadyObserved ||
                !P2wlanNative.isRunning() ||
                !P2wlanNative.isReady()
            ) {
                return@Runnable
            }
            val stableRuntimeMs =
                (SystemClock.elapsedRealtime() - nativeStartedAtElapsedMs).coerceAtLeast(0L)
            val previousAttempt = restartAttempts
            restartAttempts = 0
            Log.i(
                TAG,
                "event=android_daemon_healthy " +
                    "previous_restart_attempt=$previousAttempt " +
                    "stable_runtime_ms=$stableRuntimeMs",
            )
        }
        healthyBudgetResetRunnable = reset
        mainHandler.postDelayed(reset, HEALTHY_RUNTIME_RESET_DELAY_MS)
    }

    private fun cancelHealthyBudgetReset() {
        healthyBudgetResetRunnable?.let(mainHandler::removeCallbacks)
        healthyBudgetResetRunnable = null
    }

    /**
     * Keep an unexpected Rust/VPN exit recoverable.  This is deliberately
     * bounded and backoff-based: a transient control/relay failure gets a new
     * TUN and registration, while a persistent bad token does not create a
     * tight foreground-service restart loop.
     */
    private fun scheduleAutomaticRestart(requestJson: String, exitReason: String): Boolean {
        if (explicitStop || restartRunnable != null) return true
        val schedule = nextAutomaticRestartSchedule(
            currentAttempt = restartAttempts,
            maxAttempts = MAX_AUTOMATIC_RESTARTS,
            initialDelayMs = RESTART_INITIAL_DELAY_MS,
            maxDelayMs = RESTART_MAX_DELAY_MS,
        ) ?: run {
            serviceError = "Android VPN 自动重启次数已达上限，请重新点击启动。"
            Log.e(TAG, serviceError ?: "Android VPN automatic restart limit reached")
            return false
        }

        restartAttempts = schedule.attempt
        val delayMs = schedule.delayMs
        val restart = Runnable {
            restartRunnable = null
            if (explicitStop || isRunning()) return@Runnable
            startVpn(requestJson)
        }
        restartRunnable = restart
        Log.w(
            TAG,
            "event=android_restart_scheduled " +
                "retry_delay_ms=$delayMs " +
                "restart_attempt=$restartAttempts/$MAX_AUTOMATIC_RESTARTS " +
                "exit_reason=${compactLogReason(exitReason)}",
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

    private fun configureWifiLatencyMode(requested: Boolean) {
        // A prior failed/restarted start must not retain a lock across TUN
        // generations. The new request below is the only owner of the lock.
        releaseWifiLatencyMode()
        val network = physicalNetworkKind()
        var held = false
        if (AndroidWifiLatencyPolicy.shouldAcquire(Build.VERSION.SDK_INT, network, requested)) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val manager = getSystemService(WifiManager::class.java)
                    val lock = manager?.createWifiLock(
                        WifiManager.WIFI_MODE_FULL_LOW_LATENCY,
                        "P2WLAN:android-low-latency",
                    )
                    if (lock != null) {
                        lock.setReferenceCounted(false)
                        lock.acquire()
                        if (lock.isHeld) {
                            wifiLatencyLock = lock
                            held = true
                        }
                    }
                }
            } catch (error: Throwable) {
                Log.w(TAG, "Failed to acquire Android Wi-Fi low-latency lock", error)
            }
        }
        Log.i(
            TAG,
            "event=android_wifi_latency_mode requested=$requested held=$held network=$network",
        )
    }

    private fun releaseWifiLatencyMode() {
        val lock = wifiLatencyLock ?: return
        val wasHeld = try {
            lock.isHeld
        } catch (_: Throwable) {
            false
        }
        try {
            if (wasHeld) lock.release()
        } catch (error: Throwable) {
            Log.w(TAG, "Failed to release Android Wi-Fi low-latency lock", error)
        } finally {
            wifiLatencyLock = null
        }
        Log.i(
            TAG,
            "event=android_wifi_latency_mode requested=true held=false network=${physicalNetworkKind()}",
        )
    }

    private fun physicalNetworkKind(): String {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return "unknown"
        var hasCellular = false
        for (network in manager.allNetworks) {
            val capabilities = manager.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi"
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                hasCellular = true
            }
        }
        return if (hasCellular) "cellular" else "unknown"
    }

    private fun compactLogReason(value: String): String {
        return value.replace('\n', ' ').replace('\r', ' ').take(240)
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
