package com.example.p2wlan_flutter_client

import android.os.ParcelFileDescriptor
import android.util.Log

/** JNI entry points implemented by client/android-native. */
internal object P2wlanNative {
    private const val TAG = "P2wlanNative"

    @Volatile
    private var loaded = false

    @Volatile
    private var loadError: String? = null

    @Synchronized
    private fun ensureLoaded(): Boolean {
        if (loaded) return true
        if (loadError != null) return false
        return try {
            System.loadLibrary("p2wlan_android")
            loaded = true
            true
        } catch (error: Throwable) {
            val message = formatError(
                "无法加载 Android 原生库 libp2wlan_android.so；请确认安装包包含当前设备 ABI",
                error,
            )
            loadError = message
            Log.e(TAG, message, error)
            false
        }
    }

    fun start(service: P2wlanVpnService, tunFd: Int, requestJson: String): String? {
        if (!ensureLoaded()) {
            closeOwnedFd(tunFd)
            return loadError
        }
        return try {
            val error = nativeStart(service, tunFd, requestJson)
            loadError = error
            if (error != null) Log.e(TAG, error)
            error
        } catch (error: Throwable) {
            closeOwnedFd(tunFd)
            val message = formatError("Android 原生 daemon 启动失败", error)
            loadError = message
            Log.e(TAG, message, error)
            message
        }
    }

    /**
     * Stop only the runtime incarnation the caller owns. A zero expected
     * incarnation retains the legacy unscoped call for diagnostics/tests; the
     * VpnService always supplies its bridge incarnation.
     */
    fun stop(expectedIncarnation: Long? = null): Boolean {
        if (!ensureLoaded()) return false
        return try {
            nativeStop(expectedIncarnation ?: 0L)
        } catch (error: Throwable) {
            val message = formatError("Android 原生 daemon 停止失败", error)
            loadError = message
            Log.w(TAG, message, error)
            false
        }
    }

    fun isRunning(): Boolean {
        if (!ensureLoaded()) return false
        return try {
            nativeIsRunning()
        } catch (error: Throwable) {
            val message = formatError("无法读取 Android 原生 daemon 状态", error)
            loadError = message
            Log.w(TAG, message, error)
            false
        }
    }

    fun isReady(): Boolean {
        if (!ensureLoaded()) return false
        return try {
            nativeIsReady()
        } catch (error: Throwable) {
            val message = formatError("无法读取 Android 原生 daemon 就绪状态", error)
            loadError = message
            Log.w(TAG, message, error)
            false
        }
    }

    fun lastError(): String? {
        if (!ensureLoaded()) return loadError
        return try {
            nativeLastError()?.trim()?.ifEmpty { null } ?: loadError
        } catch (error: Throwable) {
            loadError ?: formatError("无法读取 Android 原生 daemon 错误", error)
        }
    }

    /** Current Rust runtime incarnation, or null when no native runtime owns a slot. */
    fun incarnation(): Long? {
        if (!ensureLoaded()) return null
        return try {
            nativeIncarnation().takeIf { it > 0L }
        } catch (error: Throwable) {
            val message = formatError("无法读取 Android 原生 daemon incarnation", error)
            loadError = message
            Log.w(TAG, message, error)
            null
        }
    }

    private fun formatError(prefix: String, error: Throwable): String {
        val detail = error.message?.trim().orEmpty()
        return if (detail.isEmpty()) {
            "$prefix（${error::class.java.simpleName}）"
        } else {
            "$prefix：$detail"
        }
    }

    private fun closeOwnedFd(fd: Int) {
        if (fd < 0) return
        try {
            ParcelFileDescriptor.adoptFd(fd).close()
        } catch (error: Throwable) {
            Log.w(TAG, "关闭 Android VPN fd 失败", error)
        }
    }

    private external fun nativeStart(
        service: P2wlanVpnService,
        tunFd: Int,
        requestJson: String,
    ): String?

    private external fun nativeStop(expectedIncarnation: Long): Boolean

    private external fun nativeIsRunning(): Boolean

    private external fun nativeIsReady(): Boolean

    private external fun nativeLastError(): String?

    private external fun nativeIncarnation(): Long
}
