package com.example.p2wlan_flutter_client

/**
 * Calculate one bounded automatic-restart step without depending on Android
 * lifecycle objects. Keeping this policy pure makes the crash-loop contract
 * testable on the JVM: a successful nativeStart() must not reset the attempt
 * number before the daemon becomes ready and stays healthy.
 */
internal data class AutomaticRestartSchedule(
    val attempt: Int,
    val delayMs: Long,
)

internal fun nextAutomaticRestartSchedule(
    currentAttempt: Int,
    maxAttempts: Int,
    initialDelayMs: Long,
    maxDelayMs: Long,
): AutomaticRestartSchedule? {
    require(maxAttempts > 0) { "maxAttempts must be positive" }
    require(initialDelayMs > 0) { "initialDelayMs must be positive" }
    require(maxDelayMs >= initialDelayMs) {
        "maxDelayMs must be at least initialDelayMs"
    }

    if (currentAttempt >= maxAttempts) return null

    val attempt = (currentAttempt + 1).coerceAtMost(maxAttempts)
    val exponent = (attempt - 1).coerceIn(0, 6)
    val delayMs = (initialDelayMs * (1L shl exponent)).coerceAtMost(maxDelayMs)
    return AutomaticRestartSchedule(attempt, delayMs)
}
