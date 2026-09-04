package com.example.p2wlan_flutter_client

import java.security.MessageDigest
import java.util.Locale

/**
 * Platform-neutral lifecycle reducer used by both the Android host and JVM
 * tests. It owns Android attachment/permission identities only; Rust remains
 * the authority for dataplane network generations and path state.
 */
internal enum class MobileLifecycleEvent(val wireName: String) {
    APP_BACKGROUNDED("app_backgrounded"),
    APP_RESUMED("app_resumed"),
    PHYSICAL_NETWORK_CHANGED("physical_network_changed"),
    VPN_PERMISSION_REQUEST_STARTED("vpn_permission_request_started"),
    VPN_PERMISSION_REVOKED("vpn_permission_revoked"),
    VPN_PERMISSION_GRANTED("vpn_permission_granted"),
    VPN_START_REQUESTED("vpn_start_requested"),
    EXPLICIT_STOP_REQUESTED("explicit_stop_requested"),
    ACTIVITY_RECREATED("activity_recreated"),
    SERVICE_RECREATED("service_recreated"),
    BRIDGE_ATTACHED("bridge_attached"),
    BRIDGE_DETACHED("bridge_detached"),
    NATIVE_RUNTIME_STARTED("native_runtime_started"),
    NATIVE_RUNTIME_STOPPED("native_runtime_stopped"),
    NATIVE_MONITOR_CALLBACK("native_monitor_callback"),
    AUTOMATIC_RESTART_SCHEDULED("automatic_restart_scheduled"),
    AUTOMATIC_RESTART_REJECTED("automatic_restart_rejected"),
    CONTROL_DISCONNECTED("control_disconnected"),
    CONTROL_RECONNECTED("control_reconnected"),
    CANDIDATE_REFRESH_STARTED("candidate_refresh_started"),
    RELAY_RETAINED("relay_retained"),
    DIRECT_RECONFIRMED("direct_reconfirmed"),
}

internal enum class MobileLifecycleOutcome(val wireValue: String) {
    APPLIED("applied"),
    DUPLICATE("duplicate"),
    STALE_REJECTED("stale_rejected"),
    SUPERSEDED("superseded"),
    FAILED("failed"),
}

internal enum class MobilePermissionState(val wireValue: String) {
    UNKNOWN("unknown"),
    PENDING("pending"),
    GRANTED("granted"),
    REVOKED("revoked"),
}

internal data class MobileLifecycleIdentity(
    val lifecycleGeneration: Long = 0,
    val permissionRequestId: Long = 0,
    val activityIncarnation: Long = 0,
    val engineIncarnation: Long = 0,
    val serviceIncarnation: Long = 0,
    val automaticRestartGeneration: Long = 0,
    val bridgeIncarnation: Long = 0,
    val networkGeneration: Long = 0,
    val controlConnectionGeneration: Long = 0,
)

internal data class MobileLifecycleState(
    val identity: MobileLifecycleIdentity = MobileLifecycleIdentity(),
    val permissionState: MobilePermissionState = MobilePermissionState.UNKNOWN,
    val desiredRunning: Boolean = false,
    val lastEvent: MobileLifecycleEvent? = null,
    val lastOutcome: MobileLifecycleOutcome? = null,
    val lastResult: String? = null,
)

internal data class MobileLifecycleTransition(
    val event: MobileLifecycleEvent,
    val outcome: MobileLifecycleOutcome,
    val oldIdentity: MobileLifecycleIdentity,
    val newIdentity: MobileLifecycleIdentity,
    val result: String? = null,
)

/**
 * A deterministic owner reducer. Every accepted transition gets a new
 * lifecycleGeneration. Duplicate/stale callbacks preserve state and expose
 * their decision to diagnostics.
 */
internal class MobileLifecycleCoordinator {
    var state: MobileLifecycleState = MobileLifecycleState()
        private set

    private var pendingPermission: Pair<Long, Long>? = null
    private var nextPermissionRequestId = 0L
    private var completedAutomaticRestartGeneration = 0L

    fun beginPermissionRequest(
        activityIncarnation: Long,
        engineIncarnation: Long,
    ): MobileLifecycleTransition {
        if (pendingPermission != null) {
            return record(
                transition(
                    MobileLifecycleEvent.VPN_PERMISSION_REQUEST_STARTED,
                    MobileLifecycleOutcome.FAILED,
                    "permission_request_pending",
                ),
            )
        }
        nextPermissionRequestId += 1
        val requestId = nextPermissionRequestId
        pendingPermission = requestId to engineIncarnation
        return advance(
            MobileLifecycleEvent.VPN_PERMISSION_REQUEST_STARTED,
            state.identity.copy(
                permissionRequestId = requestId,
                activityIncarnation = activityIncarnation,
                engineIncarnation = engineIncarnation,
            ),
            permissionState = MobilePermissionState.PENDING,
        )
    }

    fun completePermissionRequest(
        requestId: Long,
        activityIncarnation: Long,
        engineIncarnation: Long,
        granted: Boolean,
    ): MobileLifecycleTransition {
        val event = if (granted) {
            MobileLifecycleEvent.VPN_PERMISSION_GRANTED
        } else {
            MobileLifecycleEvent.VPN_PERMISSION_REVOKED
        }
        val pending = pendingPermission
        if (
            pending == null ||
            pending.first != requestId ||
            pending.second != engineIncarnation ||
            state.identity.activityIncarnation != activityIncarnation ||
            state.identity.engineIncarnation != engineIncarnation
        ) {
            return record(transition(event, MobileLifecycleOutcome.STALE_REJECTED, "old_permission_result"))
        }
        pendingPermission = null
        return advance(
            event,
            state.identity,
            permissionState = if (granted) {
                MobilePermissionState.GRANTED
            } else {
                MobilePermissionState.REVOKED
            },
        )
    }

    fun revokePermission(): MobileLifecycleTransition {
        if (
            state.permissionState == MobilePermissionState.REVOKED &&
            pendingPermission == null
        ) {
            return record(transition(MobileLifecycleEvent.VPN_PERMISSION_REVOKED, MobileLifecycleOutcome.DUPLICATE))
        }
        pendingPermission = null
        return advance(
            MobileLifecycleEvent.VPN_PERMISSION_REVOKED,
            state.identity,
            permissionState = MobilePermissionState.REVOKED,
            result = "permission_revoked",
            desiredRunning = false,
        )
    }

    fun startRequested(): MobileLifecycleTransition {
        if (state.desiredRunning) {
            return record(
                transition(
                    MobileLifecycleEvent.VPN_START_REQUESTED,
                    MobileLifecycleOutcome.DUPLICATE,
                    "start_already_desired",
                ),
            )
        }
        return advance(
            MobileLifecycleEvent.VPN_START_REQUESTED,
            state.identity,
            desiredRunning = true,
            result = "start_requested",
        )
    }

    fun explicitStopRequested(): MobileLifecycleTransition {
        if (!state.desiredRunning && pendingPermission == null) {
            return record(
                transition(
                    MobileLifecycleEvent.EXPLICIT_STOP_REQUESTED,
                    MobileLifecycleOutcome.DUPLICATE,
                    "stop_already_requested",
                ),
            )
        }
        pendingPermission = null
        return advance(
            MobileLifecycleEvent.EXPLICIT_STOP_REQUESTED,
            state.identity,
            desiredRunning = false,
            result = "explicit_stop",
        )
    }

    fun nativeMonitorStopped(serviceIncarnation: Long): MobileLifecycleTransition {
        if (!acceptsServiceCallback(serviceIncarnation)) {
            return record(
                transition(
                    MobileLifecycleEvent.NATIVE_MONITOR_CALLBACK,
                    MobileLifecycleOutcome.STALE_REJECTED,
                    "old_service_monitor",
                ),
            )
        }
        return advance(
            MobileLifecycleEvent.NATIVE_RUNTIME_STOPPED,
            state.identity,
            result = "native_monitor_observed_stop",
        )
    }

    fun automaticRestartScheduled(serviceIncarnation: Long): MobileLifecycleTransition {
        if (!state.desiredRunning || !acceptsServiceCallback(serviceIncarnation)) {
            return record(
                transition(
                    MobileLifecycleEvent.AUTOMATIC_RESTART_REJECTED,
                    MobileLifecycleOutcome.STALE_REJECTED,
                    "restart_owner_not_current",
                ),
            )
        }
        val nextGeneration = state.identity.automaticRestartGeneration + 1
        return advance(
            MobileLifecycleEvent.AUTOMATIC_RESTART_SCHEDULED,
            state.identity.copy(automaticRestartGeneration = nextGeneration),
            result = "restart_scheduled",
        )
    }

    fun automaticRestartCallback(
        serviceIncarnation: Long,
        restartGeneration: Long,
    ): MobileLifecycleTransition {
        if (
            !state.desiredRunning ||
            !acceptsServiceCallback(serviceIncarnation) ||
            restartGeneration != state.identity.automaticRestartGeneration
        ) {
            return record(
                transition(
                    MobileLifecycleEvent.AUTOMATIC_RESTART_REJECTED,
                    MobileLifecycleOutcome.STALE_REJECTED,
                    "old_restart_callback",
                ),
            )
        }
        if (restartGeneration == completedAutomaticRestartGeneration) {
            return record(
                transition(
                    MobileLifecycleEvent.AUTOMATIC_RESTART_SCHEDULED,
                    MobileLifecycleOutcome.DUPLICATE,
                    "restart_callback_already_consumed",
                ),
            )
        }
        completedAutomaticRestartGeneration = restartGeneration
        return advance(
            MobileLifecycleEvent.NATIVE_RUNTIME_STARTED,
            state.identity,
            result = "restart_callback_accepted",
        )
    }

    fun activityRecreated(
        activityIncarnation: Long,
        engineIncarnation: Long,
    ): MobileLifecycleTransition {
        if (
            state.identity.activityIncarnation == activityIncarnation &&
            state.identity.engineIncarnation == engineIncarnation
        ) {
            return record(transition(MobileLifecycleEvent.ACTIVITY_RECREATED, MobileLifecycleOutcome.DUPLICATE))
        }
        if (
            activityIncarnation < state.identity.activityIncarnation ||
            (activityIncarnation == state.identity.activityIncarnation &&
                engineIncarnation < state.identity.engineIncarnation)
        ) {
            return record(
                transition(
                    MobileLifecycleEvent.ACTIVITY_RECREATED,
                    MobileLifecycleOutcome.STALE_REJECTED,
                    "old_activity_engine",
                ),
            )
        }
        pendingPermission = null
        return advance(
            MobileLifecycleEvent.ACTIVITY_RECREATED,
            state.identity.copy(
                activityIncarnation = activityIncarnation,
                engineIncarnation = engineIncarnation,
            ),
            result = "activity_engine_reattached",
        )
    }

    fun serviceRecreated(serviceIncarnation: Long): MobileLifecycleTransition {
        if (serviceIncarnation <= state.identity.serviceIncarnation) {
            return record(transition(MobileLifecycleEvent.SERVICE_RECREATED, MobileLifecycleOutcome.STALE_REJECTED, "old_service"))
        }
        return advance(
            MobileLifecycleEvent.SERVICE_RECREATED,
            state.identity.copy(serviceIncarnation = serviceIncarnation),
            result = "service_reattached",
        )
    }

    fun attachBridge(bridgeIncarnation: Long): MobileLifecycleTransition {
        if (bridgeIncarnation <= 0) {
            return record(transition(MobileLifecycleEvent.BRIDGE_ATTACHED, MobileLifecycleOutcome.FAILED, "invalid_bridge"))
        }
        if (bridgeIncarnation == state.identity.bridgeIncarnation) {
            return record(transition(MobileLifecycleEvent.BRIDGE_ATTACHED, MobileLifecycleOutcome.DUPLICATE))
        }
        if (bridgeIncarnation < state.identity.bridgeIncarnation) {
            return record(transition(MobileLifecycleEvent.BRIDGE_ATTACHED, MobileLifecycleOutcome.STALE_REJECTED, "old_bridge"))
        }
        return advance(
            MobileLifecycleEvent.BRIDGE_ATTACHED,
            state.identity.copy(bridgeIncarnation = bridgeIncarnation),
            result = "bridge_attached",
        )
    }

    fun detachBridge(bridgeIncarnation: Long): MobileLifecycleTransition {
        if (bridgeIncarnation != state.identity.bridgeIncarnation) {
            return record(transition(MobileLifecycleEvent.BRIDGE_DETACHED, MobileLifecycleOutcome.STALE_REJECTED, "old_bridge_cleanup"))
        }
        return advance(
            MobileLifecycleEvent.BRIDGE_DETACHED,
            state.identity.copy(bridgeIncarnation = 0),
            result = "bridge_detached",
        )
    }

    fun physicalNetworkChanged(networkGeneration: Long): MobileLifecycleTransition {
        if (networkGeneration < state.identity.networkGeneration) {
            return record(
                transition(
                    MobileLifecycleEvent.PHYSICAL_NETWORK_CHANGED,
                    MobileLifecycleOutcome.STALE_REJECTED,
                    "old_network_generation",
                ),
            )
        }
        if (networkGeneration == state.identity.networkGeneration) {
            return record(transition(MobileLifecycleEvent.PHYSICAL_NETWORK_CHANGED, MobileLifecycleOutcome.DUPLICATE))
        }
        return advance(
            MobileLifecycleEvent.PHYSICAL_NETWORK_CHANGED,
            state.identity.copy(networkGeneration = networkGeneration),
            result = "network_generation_advanced",
        )
    }

    fun acceptsServiceCallback(serviceIncarnation: Long): Boolean =
        serviceIncarnation > 0 && serviceIncarnation == state.identity.serviceIncarnation

    fun acceptsBridgeCallback(bridgeIncarnation: Long): Boolean =
        bridgeIncarnation > 0 && bridgeIncarnation == state.identity.bridgeIncarnation

    private fun advance(
        event: MobileLifecycleEvent,
        identity: MobileLifecycleIdentity,
        permissionState: MobilePermissionState = state.permissionState,
        desiredRunning: Boolean = state.desiredRunning,
        result: String? = null,
    ): MobileLifecycleTransition {
        val old = state.identity
        val next = identity.copy(lifecycleGeneration = old.lifecycleGeneration + 1)
        state = MobileLifecycleState(
            identity = next,
            permissionState = permissionState,
            desiredRunning = desiredRunning,
            lastEvent = event,
            lastOutcome = MobileLifecycleOutcome.APPLIED,
            lastResult = result,
        )
        return MobileLifecycleTransition(event, MobileLifecycleOutcome.APPLIED, old, next, result)
    }

    private fun transition(
        event: MobileLifecycleEvent,
        outcome: MobileLifecycleOutcome,
        result: String? = null,
    ): MobileLifecycleTransition =
        MobileLifecycleTransition(event, outcome, state.identity, state.identity, result)

    private fun record(transition: MobileLifecycleTransition): MobileLifecycleTransition {
        state = state.copy(
            lastEvent = transition.event,
            lastOutcome = transition.outcome,
            lastResult = transition.result,
        )
        return transition
    }
}

internal data class PhysicalNetworkIdentity(
    val networkHandle: Long,
    val transports: Set<String>,
    val validated: Boolean,
    val captive: Boolean,
    val interfaceIdentity: String?,
) {
    /** Stable, non-sensitive identity passed to the Rust lifecycle boundary. */
    fun identityHash(): String {
        val canonical = buildString {
            append(networkHandle)
            append('|')
            transports.toList().sorted().joinTo(this, separator = ",")
            append('|')
            append(validated)
            append('|')
            append(captive)
            append('|')
            append(interfaceIdentity.orEmpty())
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(Charsets.UTF_8))
        return buildString(digest.size * 2) {
            digest.forEach { byte ->
                append("%02x".format(Locale.ROOT, byte.toInt() and 0xff))
            }
        }
    }
}

internal data class PhysicalNetworkTransition(
    val outcome: MobileLifecycleOutcome,
    val generation: Long,
    val oldIdentity: PhysicalNetworkIdentity?,
    val newIdentity: PhysicalNetworkIdentity?,
)

/** Debounces Android callback bursts and fences callbacks for old Networks. */
internal class PhysicalNetworkIdentityReducer {
    private var current: PhysicalNetworkIdentity? = null
    private val retiredHandles = mutableSetOf<Long>()
    private var replacementPending = false
    private var generation = 0L

    fun onAvailable(identity: PhysicalNetworkIdentity): PhysicalNetworkTransition {
        if (current == identity) {
            return PhysicalNetworkTransition(MobileLifecycleOutcome.DUPLICATE, generation, current, current)
        }
        if (retiredHandles.contains(identity.networkHandle)) {
            return PhysicalNetworkTransition(MobileLifecycleOutcome.STALE_REJECTED, generation, null, null)
        }
        val old = current
        if (old != null && old.networkHandle == identity.networkHandle) {
            generation += 1
            current = identity
            replacementPending = false
            return PhysicalNetworkTransition(MobileLifecycleOutcome.APPLIED, generation, old, identity)
        }
        if (!replacementPending) generation += 1
        old?.let { retiredHandles += it.networkHandle }
        current = identity
        replacementPending = false
        return PhysicalNetworkTransition(MobileLifecycleOutcome.APPLIED, generation, old, identity)
    }

    fun onLost(networkHandle: Long): PhysicalNetworkTransition {
        val old = current
        if (old == null || old.networkHandle != networkHandle) {
            return PhysicalNetworkTransition(MobileLifecycleOutcome.STALE_REJECTED, generation, old, old)
        }
        generation += 1
        current = null
        retiredHandles += networkHandle
        replacementPending = true
        return PhysicalNetworkTransition(MobileLifecycleOutcome.APPLIED, generation, old, null)
    }

    fun current(): PhysicalNetworkIdentity? = current
    fun generation(): Long = generation
}

/** JNI-shaped boundary used by the Android callback and JVM production-path tests. */
internal fun interface PhysicalNetworkChangeNotifier {
    fun notify(
        serviceIncarnation: Long,
        bridgeIncarnation: Long,
        kotlinNetworkGeneration: Long,
        networkIdentityHash: String,
    ): MobileLifecycleOutcome
}

internal data class PhysicalNetworkCallbackResult(
    val outcome: MobileLifecycleOutcome,
    val generation: Long,
    val oldIdentity: PhysicalNetworkIdentity?,
    val newIdentity: PhysicalNetworkIdentity?,
    val forwardedToRust: Boolean,
)

/**
 * Captures the service/bridge owner at callback registration and forwards only
 * reducer-authorized `onAvailable` edges to Rust. The Kotlin reducer remains a
 * debounce/fencing boundary; Rust owns the dataplane generation and rebind.
 */
internal class PhysicalNetworkCallbackForwarder(
    private val callbackServiceIncarnation: Long,
    private val callbackBridgeIncarnation: Long,
    private val currentServiceIncarnation: () -> Long,
    private val currentBridgeIncarnation: () -> Long,
    private val notifier: PhysicalNetworkChangeNotifier,
    private val reducer: PhysicalNetworkIdentityReducer = PhysicalNetworkIdentityReducer(),
) {
    fun onAvailable(identity: PhysicalNetworkIdentity): PhysicalNetworkCallbackResult {
        val ownerAccepted = callbackServiceIncarnation > 0L &&
            callbackBridgeIncarnation > 0L &&
            currentServiceIncarnation() == callbackServiceIncarnation &&
            currentBridgeIncarnation() == callbackBridgeIncarnation
        if (!ownerAccepted) {
            return result(
                MobileLifecycleOutcome.STALE_REJECTED,
                reducer.generation(),
                forwardedToRust = false,
            )
        }
        val transition = reducer.onAvailable(identity)
        if (transition.outcome != MobileLifecycleOutcome.APPLIED) {
            return PhysicalNetworkCallbackResult(
                transition.outcome,
                transition.generation,
                transition.oldIdentity,
                transition.newIdentity,
                forwardedToRust = false,
            )
        }
        val rustOutcome = notifier.notify(
            callbackServiceIncarnation,
            callbackBridgeIncarnation,
            transition.generation,
            identity.identityHash(),
        )
        return PhysicalNetworkCallbackResult(
            rustOutcome,
            transition.generation,
            transition.oldIdentity,
            transition.newIdentity,
            forwardedToRust = true,
        )
    }

    /** Loss is retained as reducer state; the replacement `onAvailable` edge
     * carries the single Rust generation advance for the handoff. */
    fun onLost(networkHandle: Long): PhysicalNetworkCallbackResult {
        val ownerAccepted = callbackServiceIncarnation > 0L &&
            callbackBridgeIncarnation > 0L &&
            currentServiceIncarnation() == callbackServiceIncarnation &&
            currentBridgeIncarnation() == callbackBridgeIncarnation
        if (!ownerAccepted) {
            return result(
                MobileLifecycleOutcome.STALE_REJECTED,
                reducer.generation(),
                forwardedToRust = false,
            )
        }
        val transition = reducer.onLost(networkHandle)
        return PhysicalNetworkCallbackResult(
            transition.outcome,
            transition.generation,
            transition.oldIdentity,
            transition.newIdentity,
            forwardedToRust = false,
        )
    }

    private fun result(
        outcome: MobileLifecycleOutcome,
        generation: Long,
        forwardedToRust: Boolean,
    ) = PhysicalNetworkCallbackResult(
        outcome,
        generation,
        reducer.current(),
        reducer.current(),
        forwardedToRust,
    )
}
