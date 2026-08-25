package com.example.p2wlan_flutter_client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidExperimentConfigTest {
    @Test
    fun invalidOrMissingTunModeFallsBackToAsyncFd() {
        assertEquals(AndroidTunMode.ASYNC_FD, AndroidTunMode.parse(null))
        assertEquals(AndroidTunMode.ASYNC_FD, AndroidTunMode.parse("unknown"))
        assertEquals(AndroidTunMode.DEDICATED_BLOCKING, AndroidTunMode.parse("DEDICATED_BLOCKING"))
    }

    @Test
    fun wifiLatencyRequiresOptInApiAndWifi() {
        assertFalse(AndroidWifiLatencyPolicy.shouldAcquire(28, "wifi", true))
        assertFalse(AndroidWifiLatencyPolicy.shouldAcquire(29, "cellular", true))
        assertFalse(AndroidWifiLatencyPolicy.shouldAcquire(29, "wifi", false))
        assertTrue(AndroidWifiLatencyPolicy.shouldAcquire(29, "wifi", true))
    }
}
