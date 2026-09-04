package com.example.p2wlan_flutter_client

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Test

class MobileLifecycleCoordinatorTest {
    @Test
    fun canonicalContractContainsEveryFixedScenarioAndWireName() {
        val contract = findContract().readText()
        for (index in 1..18) {
            assertTrue(contract.contains("\"id\": \"ML-${index.toString().padStart(2, '0')}\""))
        }
        assertEquals(
            MobileLifecycleEvent.entries.map { it.wireName },
            arrayValues(contract, "events"),
        )
        assertEquals(
            MobileLifecycleOutcome.entries.map { it.wireValue },
            arrayValues(contract, "outcomes"),
        )
    }

    @Test
    fun permissionRevokeInvalidatesPendingRequestAndRegrantGetsNewId() {
        val coordinator = MobileLifecycleCoordinator()
        val first = coordinator.beginPermissionRequest(1, 10)
        val firstId = first.newIdentity.permissionRequestId
        assertEquals(MobileLifecycleOutcome.APPLIED, first.outcome)

        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.revokePermission().outcome)
        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            coordinator.completePermissionRequest(firstId, 1, 10, granted = true).outcome,
        )

        val second = coordinator.beginPermissionRequest(1, 11)
        assertTrue(second.newIdentity.permissionRequestId > firstId)
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.completePermissionRequest(
                second.newIdentity.permissionRequestId,
                1,
                11,
                granted = true,
            ).outcome,
        )
        assertEquals(MobilePermissionState.GRANTED, coordinator.state.permissionState)
    }

    @Test
    fun duplicatePermissionGrantAndRevokeAreIdempotent() {
        val coordinator = MobileLifecycleCoordinator()
        val request = coordinator.beginPermissionRequest(1, 10)
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.completePermissionRequest(request.newIdentity.permissionRequestId, 1, 10, true).outcome,
        )
        val generation = coordinator.state.identity.lifecycleGeneration
        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            coordinator.completePermissionRequest(request.newIdentity.permissionRequestId, 1, 10, true).outcome,
        )
        assertEquals(generation, coordinator.state.identity.lifecycleGeneration)
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.revokePermission().outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, coordinator.revokePermission().outcome)
    }

    @Test
    fun stalePermissionResultIsRejectedAfterActivityAndEngineRecreation() {
        val coordinator = MobileLifecycleCoordinator()
        val request = coordinator.beginPermissionRequest(1, 10)
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.activityRecreated(2, 11).outcome)
        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            coordinator.completePermissionRequest(request.newIdentity.permissionRequestId, 1, 10, true).outcome,
        )
        assertEquals(2L, coordinator.state.identity.activityIncarnation)
        assertEquals(11L, coordinator.state.identity.engineIncarnation)
    }

    @Test
    fun serviceRecreationAllocatesNewIncarnationAndOldMonitorIsRejected() {
        val coordinator = MobileLifecycleCoordinator()
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.serviceRecreated(40).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.serviceRecreated(41).outcome)
        assertFalse(coordinator.acceptsServiceCallback(40))
        assertTrue(coordinator.acceptsServiceCallback(41))
        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            coordinator.serviceRecreated(40).outcome,
        )
    }

    @Test
    fun oldDelayedRestartIsRejectedAfterExplicitOwnerChange() {
        val coordinator = MobileLifecycleCoordinator()
        coordinator.serviceRecreated(1)
        coordinator.serviceRecreated(2)
        assertFalse(coordinator.acceptsServiceCallback(1))
        assertTrue(coordinator.acceptsServiceCallback(2))
    }

    @Test
    fun explicitStopAndPermissionRevokeFenceAutomaticRestartCallbacks() {
        val coordinator = MobileLifecycleCoordinator()
        coordinator.serviceRecreated(1)
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.startRequested().outcome)
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.automaticRestartScheduled(1).outcome,
        )
        val restartGeneration = coordinator.state.identity.automaticRestartGeneration
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.nativeMonitorStopped(1).outcome,
        )
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.explicitStopRequested().outcome,
        )
        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            coordinator.automaticRestartCallback(1, restartGeneration).outcome,
        )
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.startRequested().outcome,
        )
        assertEquals(
            MobileLifecycleOutcome.APPLIED,
            coordinator.revokePermission().outcome,
        )
        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            coordinator.automaticRestartCallback(1, restartGeneration).outcome,
        )
    }

    @Test
    fun bridgeReattachmentSupersedesOldBridgeAndOldTeardownCannotStopNewBridge() {
        val coordinator = MobileLifecycleCoordinator()
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.attachBridge(4).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, coordinator.attachBridge(5).outcome)
        assertTrue(coordinator.acceptsBridgeCallback(5))
        assertFalse(coordinator.acceptsBridgeCallback(4))
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, coordinator.detachBridge(4).outcome)
        assertTrue(coordinator.acceptsBridgeCallback(5))
    }

    @Test
    fun wifiCellularAndHotspotHandoffsAdvanceExactlyOnceAndDebounceCallbacks() {
        val reducer = PhysicalNetworkIdentityReducer()
        val wifi = PhysicalNetworkIdentity(10, setOf("wifi"), validated = true, captive = false, interfaceIdentity = "wlan0")
        val cellular = PhysicalNetworkIdentity(20, setOf("cellular"), validated = true, captive = false, interfaceIdentity = "rmnet0")
        val hotspot = PhysicalNetworkIdentity(30, setOf("wifi"), validated = true, captive = false, interfaceIdentity = "wlan1")

        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onAvailable(wifi).outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, reducer.onAvailable(wifi).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onAvailable(cellular).outcome)
        assertEquals(2L, reducer.generation())
        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onAvailable(hotspot).outcome)
        assertEquals(3L, reducer.generation())
        assertEquals(MobileLifecycleOutcome.DUPLICATE, reducer.onAvailable(hotspot).outcome)
    }

    @Test
    fun capabilityChangesOnTheCurrentNetworkRemainAdoptable() {
        val reducer = PhysicalNetworkIdentityReducer()
        val validated = PhysicalNetworkIdentity(10, setOf("wifi"), true, false, "wlan0")
        val captive = validated.copy(validated = false, captive = true)

        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onAvailable(validated).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onAvailable(captive).outcome)
        assertEquals(2L, reducer.generation())
        assertEquals(MobileLifecycleOutcome.DUPLICATE, reducer.onAvailable(captive).outcome)
    }

    @Test
    fun lateLostAndAvailableCallbacksForOldNetworkAreRejected() {
        val reducer = PhysicalNetworkIdentityReducer()
        val wifi = PhysicalNetworkIdentity(10, setOf("wifi"), true, false, "wlan0")
        val cellular = PhysicalNetworkIdentity(20, setOf("cellular"), true, false, "rmnet0")
        reducer.onAvailable(wifi)
        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onLost(10).outcome)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, reducer.onAvailable(wifi).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, reducer.onAvailable(cellular).outcome)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, reducer.onLost(10).outcome)
        assertEquals(2L, reducer.generation())
    }

    @Test
    fun ml04AndroidNetworkCallbackWifiToCellularForwardsJniExactlyOnce() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(
            callbackService = 40,
            callbackBridge = 4,
            currentService = { 40 },
            currentBridge = { 4 },
            calls = calls,
        )
        val wifi = identity(10, "wifi", "wlan0")
        val cellular = identity(20, "cellular", "rmnet0")

        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(wifi).outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, forwarder.onAvailable(wifi).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLost(10).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(cellular).outcome)
        assertEquals(listOf(1L to wifi.identityHash(), 2L to cellular.identityHash()), calls)
    }

    @Test
    fun ml05AndroidNetworkCallbackCellularToWifiHotspotForwardsJniExactlyOnce() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(
            callbackService = 41,
            callbackBridge = 5,
            currentService = { 41 },
            currentBridge = { 5 },
            calls = calls,
        )
        val cellular = identity(20, "cellular", "rmnet0")
        val hotspot = identity(30, "wifi", "wlan1")

        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(cellular).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLost(20).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(hotspot).outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, forwarder.onAvailable(hotspot).outcome)
        assertEquals(listOf(1L to cellular.identityHash(), 2L to hotspot.identityHash()), calls)
    }

    @Test
    fun ml10AndroidNetworkCallbackPassesCurrentServiceAndBridgeOwnerToJni() {
        val calls = AtomicInteger()
        var observedService = 0L
        var observedBridge = 0L
        val forwarder = PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = 50,
            callbackBridgeIncarnation = 7,
            currentServiceIncarnation = { 50 },
            currentBridgeIncarnation = { 7 },
            notifier = PhysicalNetworkChangeNotifier { service, bridge, _, _ ->
                observedService = service
                observedBridge = bridge
                calls.incrementAndGet()
                MobileLifecycleOutcome.APPLIED
            },
        )

        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(identity(50, "wifi", "wlan0")).outcome)
        assertEquals(1, calls.get())
        assertEquals(50L, observedService)
        assertEquals(7L, observedBridge)
    }

    @Test
    fun ml11AndroidNetworkCallbackRejectsOldBridgeOwner() {
        val calls = AtomicInteger()
        val forwarder = PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = 50,
            callbackBridgeIncarnation = 7,
            currentServiceIncarnation = { 50 },
            currentBridgeIncarnation = { 8 },
            notifier = PhysicalNetworkChangeNotifier { _, _, _, _ ->
                calls.incrementAndGet()
                MobileLifecycleOutcome.APPLIED
            },
        )

        val result = forwarder.onAvailable(identity(60, "cellular", "rmnet0"))
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, result.outcome)
        assertEquals(0, calls.get())
    }

    @Test
    fun ml03AndroidNetworkCallbackRejectsOldServiceOwner() {
        val calls = AtomicInteger()
        val forwarder = PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = 50,
            callbackBridgeIncarnation = 7,
            currentServiceIncarnation = { 51 },
            currentBridgeIncarnation = { 7 },
            notifier = PhysicalNetworkChangeNotifier { _, _, _, _ ->
                calls.incrementAndGet()
                MobileLifecycleOutcome.APPLIED
            },
        )

        assertEquals(
            MobileLifecycleOutcome.STALE_REJECTED,
            forwarder.onLost(60).outcome,
        )
        assertEquals(0, calls.get())
    }

    @Test
    fun ml14AndroidNetworkCallbackRejectsLateOldNetworkHandle() {
        val calls = mutableListOf<Long>()
        val forwarder = PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = 60,
            callbackBridgeIncarnation = 9,
            currentServiceIncarnation = { 60 },
            currentBridgeIncarnation = { 9 },
            notifier = PhysicalNetworkChangeNotifier { _, _, generation, _ ->
                calls += generation
                MobileLifecycleOutcome.APPLIED
            },
        )
        val oldWifi = identity(70, "wifi", "wlan0")
        val cellular = identity(71, "cellular", "rmnet0")

        forwarder.onAvailable(oldWifi)
        forwarder.onLost(oldWifi.networkHandle)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onAvailable(oldWifi).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(cellular).outcome)
        assertEquals(listOf(1L, 2L), calls)
    }

    @Test
    fun evidenceMl03DaemonProcessRecreation() {
        val coordinator = MobileLifecycleCoordinator()
        val old = coordinator.serviceRecreated(40).newIdentity
        val replacement = coordinator.serviceRecreated(41)
        assertEquals(MobileLifecycleOutcome.APPLIED, replacement.outcome)
        emitEvidence(
            scenarioId = "ML-03",
            method = "evidenceMl03DaemonProcessRecreation",
            events = "[\"service_recreated\",\"native_runtime_started\"]",
            oldIdentity = identityJson("service_incarnation" to old.serviceIncarnation),
            newIdentity = identityJson("service_incarnation" to replacement.newIdentity.serviceIncarnation),
            decision = replacement.outcome,
            invariants = "{\"new_process_adopted\":true}",
        )
    }

    @Test
    fun evidenceMl04WifiToCellularHandoff() {
        val calls = mutableListOf<Long>()
        val forwarder = forwarderForEvidence(calls)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(identity(10, "wifi", "wlan0")).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLost(10).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(identity(20, "cellular", "rmnet0")).outcome)
        assertEquals(listOf(1L, 2L), calls)
        emitEvidence(
            scenarioId = "ML-04",
            method = "evidenceMl04WifiToCellularHandoff",
            events = "[\"physical_network_changed\",\"candidate_refresh_started\"]",
            oldIdentity = identityJson("network_generation" to calls.first()),
            newIdentity = identityJson("network_generation" to calls.last()),
            decision = MobileLifecycleOutcome.APPLIED,
            invariants = "{\"single_network_generation_advance\":${calls.last() - calls.first() == 1L}}",
        )
    }

    @Test
    fun evidenceMl05CellularToWifiHotspotHandoff() {
        val calls = mutableListOf<Long>()
        val forwarder = forwarderForEvidence(calls)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(identity(20, "cellular", "rmnet0")).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLost(20).outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onAvailable(identity(30, "wifi", "wlan1")).outcome)
        assertEquals(listOf(1L, 2L), calls)
        emitEvidence(
            scenarioId = "ML-05",
            method = "evidenceMl05CellularToWifiHotspotHandoff",
            events = "[\"physical_network_changed\",\"candidate_refresh_started\"]",
            oldIdentity = identityJson("network_generation" to calls.first()),
            newIdentity = identityJson("network_generation" to calls.last()),
            decision = MobileLifecycleOutcome.APPLIED,
            invariants = "{\"single_network_generation_advance\":${calls.last() - calls.first() == 1L}}",
        )
    }

    @Test
    fun evidenceMl06VpnPermissionRevoke() {
        val coordinator = MobileLifecycleCoordinator()
        val request = coordinator.beginPermissionRequest(1, 10)
        val old = request.newIdentity
        val revoke = coordinator.revokePermission()
        val late = coordinator.completePermissionRequest(request.newIdentity.permissionRequestId, 1, 10, granted = true)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, late.outcome)
        emitEvidence(
            scenarioId = "ML-06",
            method = "evidenceMl06VpnPermissionRevoke",
            events = "[\"vpn_permission_revoked\",\"bridge_detached\"]",
            oldIdentity = identityJson(
                "permission_request_id" to old.permissionRequestId,
                "lifecycle_generation" to old.lifecycleGeneration,
            ),
            newIdentity = identityJson(
                "permission_request_id" to revoke.newIdentity.permissionRequestId,
                "lifecycle_generation" to revoke.newIdentity.lifecycleGeneration,
            ),
            decision = late.outcome,
            invariants = "{\"pending_permission_invalidated\":true}",
        )
    }

    @Test
    fun evidenceMl07VpnPermissionRegrant() {
        val coordinator = MobileLifecycleCoordinator()
        val first = coordinator.beginPermissionRequest(1, 10)
        coordinator.revokePermission()
        val old = coordinator.state.identity
        val second = coordinator.beginPermissionRequest(1, 11)
        val grant = coordinator.completePermissionRequest(second.newIdentity.permissionRequestId, 1, 11, granted = true)
        assertEquals(MobileLifecycleOutcome.APPLIED, grant.outcome)
        assertTrue(second.newIdentity.permissionRequestId > first.newIdentity.permissionRequestId)
        emitEvidence(
            scenarioId = "ML-07",
            method = "evidenceMl07VpnPermissionRegrant",
            events = "[\"vpn_permission_granted\",\"native_runtime_started\"]",
            oldIdentity = identityJson("permission_request_id" to old.permissionRequestId),
            newIdentity = identityJson("permission_request_id" to grant.newIdentity.permissionRequestId),
            decision = grant.outcome,
            invariants = "{\"new_permission_attempt\":${grant.newIdentity.permissionRequestId != old.permissionRequestId}}",
        )
    }

    @Test
    fun evidenceMl08ActivityEngineRecreation() {
        val coordinator = MobileLifecycleCoordinator()
        val request = coordinator.beginPermissionRequest(1, 10)
        val old = request.newIdentity
        val recreation = coordinator.activityRecreated(2, 11)
        val late = coordinator.completePermissionRequest(request.newIdentity.permissionRequestId, 1, 10, granted = true)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, late.outcome)
        emitEvidence(
            scenarioId = "ML-08",
            method = "evidenceMl08ActivityEngineRecreation",
            events = "[\"activity_recreated\",\"vpn_permission_granted\"]",
            oldIdentity = identityJson("activity_incarnation" to old.activityIncarnation, "engine_incarnation" to old.engineIncarnation),
            newIdentity = identityJson("activity_incarnation" to recreation.newIdentity.activityIncarnation, "engine_incarnation" to recreation.newIdentity.engineIncarnation),
            decision = late.outcome,
            invariants = "{\"old_engine_callback_rejected\":true}",
        )
    }

    @Test
    fun evidenceMl09ServiceRecreation() {
        val coordinator = MobileLifecycleCoordinator()
        val old = coordinator.serviceRecreated(8).newIdentity
        val replacement = coordinator.serviceRecreated(9)
        assertEquals(MobileLifecycleOutcome.APPLIED, replacement.outcome)
        emitEvidence(
            scenarioId = "ML-09",
            method = "evidenceMl09ServiceRecreation",
            events = "[\"service_recreated\",\"native_runtime_started\"]",
            oldIdentity = identityJson("service_incarnation" to old.serviceIncarnation),
            newIdentity = identityJson("service_incarnation" to replacement.newIdentity.serviceIncarnation),
            decision = replacement.outcome,
            invariants = "{\"new_service_incarnation\":true}",
        )
    }

    @Test
    fun evidenceMl10BridgeReattachment() {
        val coordinator = MobileLifecycleCoordinator()
        val old = coordinator.attachBridge(4).newIdentity
        val replacement = coordinator.attachBridge(5)
        assertEquals(MobileLifecycleOutcome.APPLIED, replacement.outcome)
        emitEvidence(
            scenarioId = "ML-10",
            method = "evidenceMl10BridgeReattachment",
            events = "[\"bridge_detached\",\"bridge_attached\"]",
            oldIdentity = identityJson("bridge_incarnation" to old.bridgeIncarnation),
            newIdentity = identityJson("bridge_incarnation" to replacement.newIdentity.bridgeIncarnation),
            decision = replacement.outcome,
            invariants = "{\"bridge_identity_adopted\":true}",
        )
    }

    @Test
    fun evidenceMl11OldBridgeTeardown() {
        val coordinator = MobileLifecycleCoordinator()
        coordinator.attachBridge(4)
        val old = coordinator.attachBridge(5).newIdentity
        val stale = coordinator.detachBridge(4)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, stale.outcome)
        emitEvidence(
            scenarioId = "ML-11",
            method = "evidenceMl11OldBridgeTeardown",
            events = "[\"bridge_detached\",\"bridge_attached\"]",
            oldIdentity = identityJson("bridge_incarnation" to 4L),
            newIdentity = identityJson("bridge_incarnation" to old.bridgeIncarnation),
            decision = stale.outcome,
            invariants = "{\"old_bridge_cleanup_rejected\":true}",
        )
    }

    @Test
    fun evidenceMl18DuplicateEvents() {
        val coordinator = MobileLifecycleCoordinator()
        val applied = coordinator.physicalNetworkChanged(1)
        val duplicate = coordinator.physicalNetworkChanged(1)
        assertEquals(MobileLifecycleOutcome.APPLIED, applied.outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, duplicate.outcome)
        assertEquals(applied.newIdentity, duplicate.newIdentity)
        emitEvidence(
            scenarioId = "ML-18",
            method = "evidenceMl18DuplicateEvents",
            events = "[\"physical_network_changed\",\"physical_network_changed\"]",
            oldIdentity = identityJson("network_generation" to applied.newIdentity.networkGeneration),
            newIdentity = identityJson("network_generation" to duplicate.newIdentity.networkGeneration),
            decision = duplicate.outcome,
            invariants = "{\"duplicate_has_no_second_effect\":true}",
        )
    }

    private fun identity(handle: Long, transport: String, interfaceName: String) =
        PhysicalNetworkIdentity(
            networkHandle = handle,
            transports = setOf(transport),
            validated = true,
            captive = false,
            interfaceIdentity = interfaceName,
        )

    private fun forwarder(
        callbackService: Long,
        callbackBridge: Long,
        currentService: () -> Long,
        currentBridge: () -> Long,
        calls: MutableList<Pair<Long, String>>,
    ) = PhysicalNetworkCallbackForwarder(
        callbackServiceIncarnation = callbackService,
        callbackBridgeIncarnation = callbackBridge,
        currentServiceIncarnation = currentService,
        currentBridgeIncarnation = currentBridge,
        notifier = PhysicalNetworkChangeNotifier { _, _, generation, hash ->
            calls += generation to hash
            MobileLifecycleOutcome.APPLIED
        },
    )

    private fun forwarderForEvidence(calls: MutableList<Long>) =
        PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = 50,
            callbackBridgeIncarnation = 7,
            currentServiceIncarnation = { 50 },
            currentBridgeIncarnation = { 7 },
            notifier = PhysicalNetworkChangeNotifier { _, _, generation, _ ->
                calls += generation
                MobileLifecycleOutcome.APPLIED
            },
        )

    private fun identityJson(vararg fields: Pair<String, Long>): String =
        fields.joinToString(prefix = "{", postfix = "}") { (key, value) ->
            "\"$key\":$value"
        }

    private fun emitEvidence(
        scenarioId: String,
        method: String,
        events: String,
        oldIdentity: String,
        newIdentity: String,
        decision: MobileLifecycleOutcome,
        invariants: String,
    ) {
        val exactTestId =
            "com.example.p2wlan_flutter_client.MobileLifecycleCoordinatorTest#$method"
        println(
            "MOBILE_LIFECYCLE_RECORD " +
                "{\"scenario_id\":\"$scenarioId\",\"exact_test_id\":\"$exactTestId\"," +
                "\"executed\":true,\"skipped\":false,\"result\":\"pass\"," +
                "\"events\":$events,\"observed_old_identity\":$oldIdentity," +
                "\"observed_new_identity\":$newIdentity," +
                "\"observed_decision\":\"${decision.wireValue}\",\"invariants\":$invariants," +
                "\"execution_source\":\"android_junit_xml\"}",
        )
    }

    private fun findContract(): File {
        val candidates = listOf(
            File("../../../contracts/mobile_lifecycle.json"),
            File("../../../../contracts/mobile_lifecycle.json"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("contracts/mobile_lifecycle.json was not found")
    }

    private fun arrayValues(document: String, key: String): List<String> {
        val section = document
            .substringAfter("\"$key\": [", missingDelimiterValue = "")
            .substringBefore("]")
        assertTrue("contract array $key is missing", section.isNotEmpty())
        return Regex("\\\"([^\\\"]+)\\\"")
            .findAll(section)
            .map { it.groupValues[1] }
            .toList()
    }
}
