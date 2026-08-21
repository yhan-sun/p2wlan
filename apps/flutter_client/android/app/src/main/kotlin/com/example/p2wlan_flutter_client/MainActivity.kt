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

class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "p2wlan/android_vpn"
        private const val VPN_PERMISSION_REQUEST = 39278
    }

    private var pendingPermissionResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result -> handleMethod(call, result) }
    }

    private fun handleMethod(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "prepareVpn" -> prepareVpn(result)
            "start" -> startVpn(call, result)
            "stop" -> stopVpn(result)
            "status" -> result.success(
                mapOf(
                    "serviceRunning" to P2wlanVpnService.isRunning(),
                    "nativeRunning" to P2wlanNative.isRunning(),
                    "nativeReady" to P2wlanNative.isReady(),
                    "nativeError" to P2wlanVpnService.lastError(),
                ),
            )
            "diagnosticsAuthToken" -> result.success(readDiagnosticsAuthToken())
            else -> result.notImplemented()
        }
    }

    private fun prepareVpn(result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            result.success(true)
            return
        }
        if (pendingPermissionResult != null) {
            result.error("vpn_permission_pending", "Another VPN permission request is already open", null)
            return
        }
        pendingPermissionResult = result
        startActivityForResult(intent, VPN_PERMISSION_REQUEST)
    }

    private fun startVpn(call: MethodCall, result: MethodChannel.Result) {
        if (VpnService.prepare(this) != null) {
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
        val result = pendingPermissionResult ?: return
        pendingPermissionResult = null
        val granted = resultCode == Activity.RESULT_OK && VpnService.prepare(this) == null
        result.success(granted)
    }
}
