package com.example.p2wlan_flutter_client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.util.concurrent.atomic.AtomicLong

class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "p2wlan/android_vpn"
        private const val PLATFORM_CHANNEL = "p2wlan/platform"
        private const val VPN_PERMISSION_REQUEST = 39278

        private val nextActivityIncarnation = AtomicLong()
        private val nextEngineIncarnation = AtomicLong()
    }

    private data class PendingPermission(
        val requestId: Long,
        val activityIncarnation: Long,
        val engineIncarnation: Long,
        val result: MethodChannel.Result,
    )

    private val lifecycleCoordinator = MobileLifecycleCoordinator()
    private var activityIncarnation = 0L
    private var engineIncarnation = 0L
    private var pendingPermission: PendingPermission? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        activityIncarnation = nextActivityIncarnation.incrementAndGet()
        super.onCreate(savedInstanceState)
        lifecycleCoordinator.activityRecreated(activityIncarnation, 0L)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        engineIncarnation = nextEngineIncarnation.incrementAndGet()
        lifecycleCoordinator.activityRecreated(activityIncarnation, engineIncarnation)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result -> handleMethod(call, result) }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, PLATFORM_CHANNEL)
            .setMethodCallHandler { call, result -> handlePlatformMethod(call, result) }
    }

    private fun handlePlatformMethod(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "applicationSupportDirectory" -> {
                val directory = File(filesDir, "p2wlan")
                if (!directory.exists() && !directory.mkdirs()) {
                    result.error(
                        "storage_unavailable",
                        "无法创建 P2WLAN 持久化配置目录",
                        null,
                    )
                    return
                }
                result.success(directory.absolutePath)
            }
            "deviceName" -> result.success(androidDeviceName())
            else -> result.notImplemented()
        }
    }

    private fun androidDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.trim()
        val model = Build.MODEL.trim()
        return listOf(manufacturer, model)
            .filter { it.isNotEmpty() }
            .distinct()
            .joinToString(" ")
            .ifEmpty { "Android device" }
    }

    private fun handleMethod(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "prepareVpn" -> prepareVpn(result)
            "start" -> startVpn(call, result)
            "stop" -> stopVpn(result)
            "status" -> result.success(
                mapOf<String, Any?>(
                    "serviceRunning" to P2wlanVpnService.isRunning(),
                    "nativeRunning" to P2wlanNative.isRunning(),
                    "nativeReady" to P2wlanNative.isReady(),
                    "nativeError" to P2wlanVpnService.lastError(),
                ) + P2wlanVpnService.lifecycleStatus(),
            )
            "diagnosticsAuthToken" -> result.success(readDiagnosticsAuthToken())
            else -> result.notImplemented()
        }
    }

    private fun prepareVpn(result: MethodChannel.Result) {
        val transition = lifecycleCoordinator.beginPermissionRequest(
            activityIncarnation,
            engineIncarnation,
        )
        if (transition.outcome != MobileLifecycleOutcome.APPLIED) {
            result.error("vpn_permission_pending", "Another VPN permission request is already open", null)
            return
        }
        val requestId = transition.newIdentity.permissionRequestId
        val intent = try {
            VpnService.prepare(this)
        } catch (error: Throwable) {
            lifecycleCoordinator.revokePermission()
            P2wlanVpnService.recordPermissionState(MobilePermissionState.REVOKED)
            result.error(
                "vpn_permission_prepare_failed",
                "无法准备 Android VPN 权限：${error.message ?: error::class.java.simpleName}",
                null,
            )
            return
        }
        if (intent == null) {
            lifecycleCoordinator.completePermissionRequest(
                requestId,
                activityIncarnation,
                engineIncarnation,
                granted = true,
            )
            P2wlanVpnService.recordPermissionState(MobilePermissionState.GRANTED)
            result.success(true)
            return
        }
        pendingPermission = PendingPermission(
            requestId,
            activityIncarnation,
            engineIncarnation,
            result,
        )
        P2wlanVpnService.recordPermissionState(MobilePermissionState.PENDING)
        try {
            startActivityForResult(intent, VPN_PERMISSION_REQUEST)
        } catch (error: Throwable) {
            pendingPermission = null
            lifecycleCoordinator.revokePermission()
            P2wlanVpnService.recordPermissionState(MobilePermissionState.REVOKED)
            result.error(
                "vpn_permission_request_failed",
                "无法打开 Android VPN 权限确认：${error.message ?: error::class.java.simpleName}",
                null,
            )
        }
    }

    private fun startVpn(call: MethodCall, result: MethodChannel.Result) {
        val permissionRequired = try {
            VpnService.prepare(this) != null
        } catch (error: Throwable) {
            lifecycleCoordinator.revokePermission()
            P2wlanVpnService.recordPermissionState(MobilePermissionState.REVOKED)
            result.error(
                "vpn_permission_prepare_failed",
                "无法检查 Android VPN 权限：${error.message ?: error::class.java.simpleName}",
                null,
            )
            return
        }
        if (permissionRequired) {
            lifecycleCoordinator.revokePermission()
            P2wlanVpnService.recordPermissionState(MobilePermissionState.REVOKED)
            result.error("vpn_permission_required", "Android VPN permission has not been granted", null)
            return
        }
        val requestJson = call.argument<String>("requestJson")
        if (requestJson.isNullOrBlank()) {
            result.error("invalid_request", "Android VPN start request is empty", null)
            return
        }
        val intent = Intent(this, P2wlanVpnService::class.java).apply {
            action = P2wlanVpnService.ACTION_START
            putExtra(P2wlanVpnService.EXTRA_REQUEST_JSON, requestJson)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            result.success(true)
        } catch (error: Throwable) {
            result.error(
                "vpn_start_failed",
                "Android VPN 服务启动失败：${error.message ?: error::class.java.simpleName}",
                null,
            )
        }
    }

    private fun stopVpn(result: MethodChannel.Result) {
        try {
            val intent = Intent(this, P2wlanVpnService::class.java).apply {
                action = P2wlanVpnService.ACTION_STOP
            }
            startService(intent)
            result.success(true)
        } catch (error: Throwable) {
            result.error("vpn_stop_failed", error.message, null)
        }
    }

    private fun readDiagnosticsAuthToken(): String? {
        val path = P2wlanVpnService.diagnosticsAuthPath(
            this,
        )
        return try {
            if (!path.exists()) null else path.readText().trim().ifEmpty { null }
        } catch (_: Throwable) {
            null
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != VPN_PERMISSION_REQUEST) return
        val pending = pendingPermission ?: return
        pendingPermission = null
        val granted = if (resultCode == Activity.RESULT_OK) {
            try {
                VpnService.prepare(this) == null
            } catch (_: Throwable) {
                false
            }
        } else {
            false
        }
        val transition = lifecycleCoordinator.completePermissionRequest(
            pending.requestId,
            pending.activityIncarnation,
            pending.engineIncarnation,
            granted,
        )
        if (transition.outcome != MobileLifecycleOutcome.APPLIED) {
            runCatching {
                pending.result.error("vpn_permission_stale", "VPN permission result belongs to an old Activity/FlutterEngine", null)
            }
            return
        }
        P2wlanVpnService.recordPermissionState(
            if (granted) MobilePermissionState.GRANTED else MobilePermissionState.REVOKED,
        )
        pending.result.success(granted)
    }

    override fun onDestroy() {
        pendingPermission?.let { pending ->
            pendingPermission = null
            lifecycleCoordinator.activityRecreated(
                activityIncarnation,
                nextEngineIncarnation.incrementAndGet(),
            )
            runCatching {
                pending.result.error(
                    "vpn_permission_cancelled",
                    "VPN permission request was cancelled with the Activity/FlutterEngine",
                    null,
                )
            }
            P2wlanVpnService.recordPermissionState(MobilePermissionState.REVOKED)
        }
        super.onDestroy()
    }
}
