package com.example.p2wlan_flutter_client

import org.json.JSONObject

internal enum class AndroidTunMode(val wireValue: String) {
    ASYNC_FD("async_fd"),
    DEDICATED_BLOCKING("dedicated_blocking");

    companion object {
        fun parse(value: String?): AndroidTunMode {
            return when (value?.trim()?.lowercase()) {
                DEDICATED_BLOCKING.wireValue -> DEDICATED_BLOCKING
                else -> ASYNC_FD
            }
        }
    }
}

internal data class AndroidExperimentConfig(
    val tunMode: AndroidTunMode,
    val wifiLowLatencyRequested: Boolean,
) {
    companion object {
        fun from(request: JSONObject): AndroidExperimentConfig {
            return AndroidExperimentConfig(
                tunMode = AndroidTunMode.parse(request.optString("android_tun_mode", "")),
                wifiLowLatencyRequested = request.optBoolean("android_wifi_low_latency", false),
            )
        }
    }
}

internal object AndroidWifiLatencyPolicy {
    private const val MIN_API = 29

    fun shouldAcquire(
        sdkInt: Int,
        physicalNetwork: String,
        requested: Boolean,
    ): Boolean {
        return requested && sdkInt >= MIN_API && physicalNetwork == "wifi"
    }
}
