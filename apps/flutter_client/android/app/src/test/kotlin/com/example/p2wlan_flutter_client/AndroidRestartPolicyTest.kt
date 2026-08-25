package com.example.p2wlan_flutter_client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AndroidRestartPolicyTest {
    @Test
    fun crashLoopKeepsExponentialBackoffWhenNativeStartWasOnlyEarlySuccess() {
        var attempts = 0
        val observed = mutableListOf<AutomaticRestartSchedule>()

        repeat(8) {
            // Models: nativeStart() returned successfully, the daemon was not
            // ready yet, then it exited. There is deliberately no reset here.
            val schedule = nextAutomaticRestartSchedule(
                currentAttempt = attempts,
                maxAttempts = 8,
                initialDelayMs = 1_000,
                maxDelayMs = 60_000,
            ) ?: error("restart budget exhausted too early")
            attempts = schedule.attempt
            observed += schedule
        }

        assertEquals((1..8).toList(), observed.map { it.attempt })
        assertEquals(
            listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 32_000L, 60_000L, 60_000L),
            observed.map { it.delayMs },
        )
        assertNull(
            nextAutomaticRestartSchedule(
                currentAttempt = attempts,
                maxAttempts = 8,
                initialDelayMs = 1_000,
                maxDelayMs = 60_000,
            ),
        )
    }

    @Test
    fun healthyResetStartsAFreshBudgetOnlyAfterTheCallerConfirmsStability() {
        var attempts = 4
        // The service performs this reset only after nativeIsReady() and the
        // healthy-runtime window; nativeStart() itself never calls it.
        attempts = 0

        val schedule = nextAutomaticRestartSchedule(
            currentAttempt = attempts,
            maxAttempts = 8,
            initialDelayMs = 1_000,
            maxDelayMs = 60_000,
        )

        assertEquals(AutomaticRestartSchedule(attempt = 1, delayMs = 1_000), schedule)
    }
}
