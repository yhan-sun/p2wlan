package com.example.p2wlan_flutter_client

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
