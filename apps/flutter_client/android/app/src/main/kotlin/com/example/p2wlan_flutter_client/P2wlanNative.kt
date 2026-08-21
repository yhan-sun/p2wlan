package com.example.p2wlan_flutter_client

/** JNI entry points implemented by client/android-native. */
internal object P2wlanNative {
    init {
        System.loadLibrary("p2wlan_android")
    }

    external fun start(tunFd: Int, requestJson: String): String?

    external fun stop(): Boolean

    external fun isRunning(): Boolean
}
