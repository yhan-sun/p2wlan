package com.example.p2wlan_flutter_client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
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
import java.util.concurrent.atomic.AtomicLong

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

        private val serviceIncarnationCounter = AtomicLong()

        @Volatile
        private var currentServiceIncarnation = 0L

        @Volatile
        private var currentBridgeIncarnation = 0L

        @Volatile
        private var currentLifecycleGeneration = 0L

        @Volatile
        private var currentPermissionState = MobilePermissionState.UNKNOWN.wireValue

        @Volatile
        private var currentAutomaticRestartGeneration = 0L

        @Volatile
        private var currentLastTransition: String? = null

        @Volatile
        private var currentLastResult: String? = null

        fun isRunning(): Boolean = serviceRunning && P2wlanNative.isRunning()

        fun lastError(): String? = serviceError ?: P2wlanNative.lastError()

        fun allocateServiceIncarnation(): Long = serviceIncarnationCounter.incrementAndGet()

        internal fun recordPermissionState(state: MobilePermissionState) {
            currentPermissionState = state.wireValue
            currentLastTransition = when (state) {
                MobilePermissionState.PENDING -> MobileLifecycleEvent.VPN_PERMISSION_REQUEST_STARTED.wireName
                MobilePermissionState.GRANTED -> MobileLifecycleEvent.VPN_PERMISSION_GRANTED.wireName
                MobilePermissionState.REVOKED -> MobileLifecycleEvent.VPN_PERMISSION_REVOKED.wireName
                MobilePermissionState.UNKNOWN -> null
            }
            currentLastResult = MobileLifecycleOutcome.APPLIED.wireValue
        }

        fun lifecycleStatus(): Map<String, Any?> = mapOf(
            "serviceIncarnation" to currentServiceIncarnation.takeIf { it > 0L },
            "bridgeIncarnation" to currentBridgeIncarnation.takeIf { it > 0L },
            "lifecycleGeneration" to currentLifecycleGeneration.takeIf { it > 0L },
            "automaticRestartGeneration" to currentAutomaticRestartGeneration.takeIf { it > 0L },
            "permissionState" to currentPermissionState,
            "lastTransition" to currentLastTransition,
            "lastResult" to currentLastResult,
        )

        fun diagnosticsAuthPath(context: Context): File {
            return File(File(context.filesDir, "p2wlan"), "p2wlan-daemon.diag-auth")
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val lifecycleCoordinator = MobileLifecycleCoordinator()
    private var serviceIncarnation = 0L
    private var ownedBridgeIncarnation = 0L
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
    private val physicalNetworkReducer = PhysicalNetworkIdentityReducer()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        serviceIncarnation = allocateServiceIncarnation()
        currentServiceIncarnation = serviceIncarnation
        lastRequestJson = loadPersistedStartRequest()
        publishLifecycle(
            lifecycleCoordinator.serviceRecreated(serviceIncarnation),
        )
        adoptExistingNativeRuntime()
        registerPhysicalNetworkCallback()
    }

    private fun isCurrentServiceOwner(): Boolean =
        serviceIncarnation > 0L && currentServiceIncarnation == serviceIncarnation

    /**
     * START_STICKY can recreate the Service object without killing the app
     * process. In that case the Rust runtime and detached TUN fd outlive this
     * Kotlin instance. Adopt the live bridge before handling the next Intent;
     * the old instance's owner checks then become stale automatically.
     */
    private fun adoptExistingNativeRuntime() {
        if (!isCurrentServiceOwner()) return
        try {
            if (!P2wlanNative.isRunning()) return
            val bridgeIncarnation = P2wlanNative.incarnation()
                ?: throw IllegalStateException("live Rust runtime has no bridge incarnation")
            val adoptionResult = P2wlanNative.adoptService(
                this,
                serviceIncarnation,
                bridgeIncarnation,
            )
            if (adoptionResult != MobileLifecycleOutcome.APPLIED.wireValue &&
                adoptionResult != MobileLifecycleOutcome.DUPLICATE.wireValue
            ) {
                throw IllegalStateException("Android native service owner was rejected: $adoptionResult")
            }
            val transition = lifecycleCoordinator.attachBridge(bridgeIncarnation)
            if (transition.outcome != MobileLifecycleOutcome.APPLIED &&
                transition.outcome != MobileLifecycleOutcome.DUPLICATE
            ) {
                throw IllegalStateException("live bridge incarnation was rejected")
            }
            ownedBridgeIncarnation = bridgeIncarnation
            serviceRunning = true
            nativeReadyObserved = P2wlanNative.isReady()
            nativeStartedAtElapsedMs = SystemClock.elapsedRealtime()
            publishLifecycle(transition)
            startNativeMonitor()
            Log.i(TAG, "event=android_daemon_adopted bridge_incarnation=$bridgeIncarnation")
        } catch (error: Throwable) {
            serviceError = "Android VPN 运行时重新附着失败：${error.message ?: error::class.java.simpleName}"
            Log.e(TAG, serviceError, error)
        }
    }

    private fun publishLifecycle(transition: MobileLifecycleTransition) {
        if (!isCurrentServiceOwner()) return
        currentLifecycleGeneration = transition.newIdentity.lifecycleGeneration
        currentAutomaticRestartGeneration = transition.newIdentity.automaticRestartGeneration
        currentLastTransition = transition.event.wireName
        currentLastResult = transition.outcome.wireValue
        currentBridgeIncarnation = transition.newIdentity.bridgeIncarnation
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isCurrentServiceOwner()) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
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
        publishLifecycle(lifecycleCoordinator.startRequested())
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
        if (!isCurrentServiceOwner()) return
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
            val nativeError = P2wlanNative.start(
                this,
                serviceIncarnation,
                detachedFd,
                enrichedRequest.toString(),
            )
            // Ownership of the detached fd is transferred to P2wlanNative as
            // soon as nativeStart is invoked. Native startup/error paths (and
            // the Kotlin library-load fallback) close it; Kotlin must not
            // close the integer a second time after this call returns.
            detachedFd = -1
            if (!nativeError.isNullOrBlank()) {
                throw IllegalStateException(nativeError)
            }
            val bridgeIncarnation = P2wlanNative.incarnation()
                ?: throw IllegalStateException("Android 原生 daemon 未返回 bridge incarnation")
            val bridgeTransition = lifecycleCoordinator.attachBridge(bridgeIncarnation)
            if (bridgeTransition.outcome != MobileLifecycleOutcome.APPLIED &&
                bridgeTransition.outcome != MobileLifecycleOutcome.DUPLICATE
            ) {
                throw IllegalStateException("Android bridge incarnation was rejected")
            }
            ownedBridgeIncarnation = bridgeIncarnation
            publishLifecycle(bridgeTransition)
            nativeStartedAtElapsedMs = SystemClock.elapsedRealtime()
            nativeReadyObserved = false
            serviceRunning = true
            // Capture this callback's bridge owner. A late callback from a
            // previous bridge remains stale even if the service object itself
            // is still alive.
            registerPhysicalNetworkCallback()
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
            if (isCurrentServiceOwner()) serviceRunning = false
            if (!explicitStop && scheduleAutomaticRestart(requestJson, message)) {
                return
            }
            stopForeground(true)
            stopSelf()
        }
    }

    private fun stopVpn() {
        if (!isCurrentServiceOwner()) {
            stopMonitor()
            releaseWifiLatencyMode()
            vpnInterface?.close()
            vpnInterface = null
            return
        }
        explicitStop = true
        publishLifecycle(lifecycleCoordinator.explicitStopRequested())
        lastRequestJson = null
        restartAttempts = 0
        cancelAutomaticRestart()
        clearPersistedStartRequest()
        serviceRunning = false
        nativeReadyObserved = false
        nativeStartedAtElapsedMs = 0L
        stopMonitor()
        try {
            if (ownedBridgeIncarnation > 0L &&
                P2wlanNative.incarnation() == ownedBridgeIncarnation &&
                P2wlanNative.isRunning()
            ) {
                P2wlanNative.stop(ownedBridgeIncarnation)
            }
        } catch (error: Throwable) {
            Log.w(TAG, "Failed to request Rust daemon shutdown", error)
        }
        releaseWifiLatencyMode()
        vpnInterface?.close()
        vpnInterface = null
        if (ownedBridgeIncarnation > 0L) {
            publishLifecycle(lifecycleCoordinator.detachBridge(ownedBridgeIncarnation))
            ownedBridgeIncarnation = 0L
        }
        stopForeground(true)
        stopSelf()
    }

    override fun onRevoke() {
        if (!isCurrentServiceOwner()) {
            super.onRevoke()
            return
        }
        stopVpn()
        publishLifecycle(lifecycleCoordinator.revokePermission())
        recordPermissionState(MobilePermissionState.REVOKED)
        super.onRevoke()
    }

    override fun onDestroy() {
        explicitStop = true
        val ownsService = isCurrentServiceOwner()
        publishLifecycle(lifecycleCoordinator.explicitStopRequested())
        if (ownsService) serviceRunning = false
        nativeReadyObserved = false
        nativeStartedAtElapsedMs = 0L
        cancelAutomaticRestart()
        stopMonitor()
        unregisterPhysicalNetworkCallback()
        if (ownsService && ownedBridgeIncarnation > 0L &&
            P2wlanNative.incarnation() == ownedBridgeIncarnation &&
            P2wlanNative.isRunning()
        ) {
            P2wlanNative.stop(ownedBridgeIncarnation)
        }
        if (ownsService && ownedBridgeIncarnation > 0L) {
            publishLifecycle(lifecycleCoordinator.detachBridge(ownedBridgeIncarnation))
            ownedBridgeIncarnation = 0L
        }
        releaseWifiLatencyMode()
        vpnInterface?.close()
        vpnInterface = null
        if (ownsService) currentServiceIncarnation = 0L
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
        val ownerServiceIncarnation = serviceIncarnation
        val thread = Thread({
            try {
                while (
                    serviceRunning &&
                    isCurrentServiceOwner() &&
                    lifecycleCoordinator.acceptsServiceCallback(ownerServiceIncarnation) &&
                    P2wlanNative.isRunning()
                ) {
                    if (!nativeReadyObserved && P2wlanNative.isReady()) {
                        nativeReadyObserved = true
                        val readyAtElapsedMs = SystemClock.elapsedRealtime()
                        mainHandler.post {
                            if (
                                !serviceRunning ||
                                !isCurrentServiceOwner() ||
                                !lifecycleCoordinator.acceptsServiceCallback(ownerServiceIncarnation) ||
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
                            scheduleHealthyBudgetReset(generation, ownerServiceIncarnation)
                        }
                    }
                    Thread.sleep(NATIVE_MONITOR_INTERVAL_MS)
                }
            } catch (_: InterruptedException) {
                return@Thread
            }
            if (!serviceRunning ||
                !isCurrentServiceOwner() ||
                !lifecycleCoordinator.acceptsServiceCallback(ownerServiceIncarnation) ||
                generation != monitorGeneration
            ) return@Thread

            val error = P2wlanNative.lastError()
                ?: "Android VPN 本地 daemon 已退出，请查看诊断日志。"
            val runtimeMs = (SystemClock.elapsedRealtime() - nativeStartedAtElapsedMs)
                .coerceAtLeast(0L)
            mainHandler.post {
                if (!serviceRunning ||
                    !isCurrentServiceOwner() ||
                    !lifecycleCoordinator.acceptsServiceCallback(ownerServiceIncarnation) ||
                    generation != monitorGeneration
                ) return@post
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
                publishLifecycle(lifecycleCoordinator.nativeMonitorStopped(ownerServiceIncarnation))
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
    private fun scheduleHealthyBudgetReset(generation: Long, ownerServiceIncarnation: Long) {
        cancelHealthyBudgetReset()
        val reset = Runnable {
            healthyBudgetResetRunnable = null
            if (
                !serviceRunning ||
                !isCurrentServiceOwner() ||
                !lifecycleCoordinator.acceptsServiceCallback(ownerServiceIncarnation) ||
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
        if (!isCurrentServiceOwner() || explicitStop || restartRunnable != null) return true
        val lifecycle = lifecycleCoordinator.automaticRestartScheduled(serviceIncarnation)
        if (lifecycle.outcome != MobileLifecycleOutcome.APPLIED) {
            Log.w(TAG, "event=android_restart_rejected result=${lifecycle.result}")
            return false
        }
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
        val ownerServiceIncarnation = serviceIncarnation
        val restartGeneration = lifecycle.newIdentity.automaticRestartGeneration
        val restart = Runnable {
            restartRunnable = null
            val callback = lifecycleCoordinator.automaticRestartCallback(
                ownerServiceIncarnation,
                restartGeneration,
            )
            publishLifecycle(callback)
            if (
                callback.outcome != MobileLifecycleOutcome.APPLIED ||
                explicitStop ||
                !isCurrentServiceOwner() ||
                !lifecycleCoordinator.acceptsServiceCallback(ownerServiceIncarnation) ||
                isRunning()
            ) return@Runnable
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
        return try {
            val manager = getSystemService(ConnectivityManager::class.java) ?: return "unknown"
            var hasCellular = false
            for (network in manager.allNetworks) {
                val capabilities = manager.getNetworkCapabilities(network) ?: continue
                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi"
                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    hasCellular = true
                }
            }
            if (hasCellular) "cellular" else "unknown"
        } catch (error: SecurityException) {
            Log.w(TAG, "Unable to inspect the physical network for Wi-Fi latency mode", error)
            "unknown"
        }
    }

    /**
     * Connectivity callbacks are an input boundary only. The Rust daemon's
     * PeerManager/network_epoch_gate remains the sole network/path authority;
     * this reducer merely turns callback bursts into one deterministic hint.
     */
    private fun registerPhysicalNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        unregisterPhysicalNetworkCallback()
        val callbackServiceOwner = serviceIncarnation
        val callbackBridgeOwner = ownedBridgeIncarnation
        val forwarder = PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = callbackServiceOwner,
            callbackBridgeIncarnation = callbackBridgeOwner,
            currentServiceIncarnation = { currentServiceIncarnation },
            currentBridgeIncarnation = { ownedBridgeIncarnation },
            notifier = PhysicalNetworkChangeNotifier { serviceOwner, bridgeOwner, generation, hash ->
                val result = P2wlanNative.notifyPhysicalNetworkChanged(
                    serviceOwner,
                    bridgeOwner,
                    generation,
                    hash,
                )
                MobileLifecycleOutcome.entries.firstOrNull { it.wireValue == result }
                    ?: MobileLifecycleOutcome.FAILED
            },
            reducer = physicalNetworkReducer,
        )
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                observePhysicalNetwork(network, forwarder)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                observePhysicalNetwork(network, forwarder)
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties: android.net.LinkProperties,
            ) {
                observePhysicalNetwork(network, forwarder)
            }

            override fun onLost(network: Network) {
                val transition = forwarder.onLost(network.networkHandle)
                if (transition.outcome == MobileLifecycleOutcome.APPLIED) {
                    Log.i(TAG, "event=physical_network_lost generation=${transition.generation}")
                }
            }
        }
        try {
            manager.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (error: Throwable) {
            Log.w(TAG, "Unable to register physical network callback", error)
        }
    }

    private fun unregisterPhysicalNetworkCallback() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)
                ?.unregisterNetworkCallback(callback)
        } catch (error: Throwable) {
            Log.w(TAG, "Unable to unregister physical network callback", error)
        }
    }

    private fun observePhysicalNetwork(
        network: Network,
        forwarder: PhysicalNetworkCallbackForwarder,
    ) {
        if (!isCurrentServiceOwner()) return
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        val capabilities = manager.getNetworkCapabilities(network) ?: return
        val transports = buildSet {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("wifi")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("cellular")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ethernet")
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("vpn")
            if (isEmpty()) add("other")
        }
        val identity = PhysicalNetworkIdentity(
            networkHandle = network.networkHandle,
            transports = transports,
            validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            captive = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            interfaceIdentity = manager.getLinkProperties(network)?.interfaceName,
        )
        val transition = forwarder.onAvailable(identity)
        if (transition.outcome != MobileLifecycleOutcome.APPLIED) {
            Log.i(
                TAG,
                "event=physical_network_callback_ignored outcome=${transition.outcome.wireValue} " +
                    "generation=${transition.generation}",
            )
            return
        }
        val lifecycle = lifecycleCoordinator.physicalNetworkChanged(transition.generation)
        publishLifecycle(lifecycle)
        Log.i(
            TAG,
            "event=physical_network_changed generation=${transition.generation} " +
                "transport=${transports.sorted().joinToString(",")} " +
                "validated=${identity.validated} captive=${identity.captive} " +
                "network_identity_hash=${identity.identityHash()}",
        )
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
