package com.example.p2wlan_flutter_client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhysicalNetworkSnapshotTest {
    private val wifi = PhysicalNetworkCapabilities(setOf("wifi"), validated = true, captive = false)
    private val cellular = PhysicalNetworkCapabilities(setOf("cellular"), validated = true, captive = false)

    @Test
    fun handoffWaitsForBothCallbackSnapshotsAndForwardsExactlyOnce() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(calls)
        assertTrue(forwarder.announceAvailable(10))
        assertNull(forwarder.onCapabilitiesChanged(10, cellular))
        val initial = forwarder.onLinkPropertiesChanged(10, link("rmnet0"))!!
        assertEquals(MobileLifecycleOutcome.APPLIED, initial.outcome)

        assertTrue(forwarder.announceAvailable(20))
        assertNull(forwarder.onCapabilitiesChanged(20, wifi))
        assertEquals(1, calls.size)
        val replacement = forwarder.onLinkPropertiesChanged(20, link())!!
        assertEquals(MobileLifecycleOutcome.APPLIED, replacement.outcome)
        assertEquals("wlan0", replacement.newIdentity!!.interfaceIdentity)
        assertEquals(setOf("wifi"), replacement.newIdentity.transports)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, forwarder.onCapabilitiesChanged(20, wifi)!!.outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, forwarder.onLinkPropertiesChanged(20, link())!!.outcome)
        assertEquals(listOf(1L, 2L), calls.map { it.first })
    }

    @Test
    fun lateOldPropertiesCannotCompleteOrOverwritePendingNewSnapshot() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(calls)
        forwarder.announceAvailable(10)
        forwarder.onCapabilitiesChanged(10, cellular)
        forwarder.onLinkPropertiesChanged(10, link("rmnet0"))
        forwarder.announceAvailable(20)
        assertNull(forwarder.onLinkPropertiesChanged(20, link()))
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onCapabilitiesChanged(10, cellular)!!.outcome)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onLinkPropertiesChanged(10, link("old"))!!.outcome)
        forwarder.onLost(10)
        val next = forwarder.onCapabilitiesChanged(20, wifi)!!
        assertEquals(MobileLifecycleOutcome.APPLIED, next.outcome)
        assertEquals("wlan0", next.newIdentity!!.interfaceIdentity)
        assertEquals(listOf(1L, 2L), calls.map { it.first })
    }

    @Test
    fun sameHandleAddressAndRouteChangesEachReachRustOnce() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(calls)
        forwarder.announceAvailable(20)
        forwarder.onCapabilitiesChanged(20, wifi)
        forwarder.onLinkPropertiesChanged(20, link())
        val changedAddress = link(addresses = listOf("192.0.2.11/24", "2001:db8::11/64"))
        val changedRoute = link(addresses = listOf("192.0.2.11/24", "2001:db8::11/64"), routes = listOf("default via 192.0.2.2"))
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLinkPropertiesChanged(20, changedAddress)!!.outcome)
        assertEquals(MobileLifecycleOutcome.DUPLICATE, forwarder.onLinkPropertiesChanged(20, changedAddress)!!.outcome)
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLinkPropertiesChanged(20, changedRoute)!!.outcome)
        assertEquals(listOf(1L, 2L, 3L), calls.map { it.first })
        assertEquals(3, calls.map { it.second }.toSet().size)
    }

    @Test
    fun bestMatchingWifiCanReplaceAnotherWifiWithTheSameInterfaceAndAddresses() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(calls)
        for (handle in listOf(20L, 30L)) {
            assertTrue(forwarder.announceAvailable(handle))
            assertNull(forwarder.onCapabilitiesChanged(handle, wifi))
            assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onLinkPropertiesChanged(handle, link())!!.outcome)
        }
        assertEquals(listOf(1L, 2L), calls.map { it.first })
        assertNotEquals(calls.first().second, calls.last().second)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onLinkPropertiesChanged(20, link())!!.outcome)
    }

    @Test
    fun linkDigestIgnoresOrderingButIncludesDnsMtuAndIpv6Removal() {
        val addresses = listOf("192.0.2.10/24", "2001:db8::10/64")
        val routes = listOf("default via 192.0.2.1", "2001:db8::/64 dev wlan0")
        val original = link(addresses = addresses, routes = routes)
        assertEquals(original, link(addresses = addresses.reversed(), routes = routes.reversed()))
        assertNotEquals(original, link(addresses = addresses.take(1), routes = routes))
        assertNotEquals(original, link(addresses = addresses, routes = routes, dns = listOf("192.0.2.53")))
        assertNotEquals(original, link(addresses = addresses, routes = routes, mtu = 1280))
        assertEquals(64, original.configurationHash.length)
    }

    @Test
    fun lostPendingNetworkCannotReuseItsSnapshotsOnReturn() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(calls)
        forwarder.announceAvailable(20)
        forwarder.onCapabilitiesChanged(20, wifi)
        forwarder.onLost(20)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onLinkPropertiesChanged(20, link())!!.outcome)
        forwarder.announceAvailable(20)
        assertNull(forwarder.onLinkPropertiesChanged(20, link()))
        assertTrue(calls.isEmpty())
        assertEquals(MobileLifecycleOutcome.APPLIED, forwarder.onCapabilitiesChanged(20, wifi)!!.outcome)
        assertEquals(1, calls.size)
    }

    @Test
    fun replacedBridgeCannotCompletePendingSnapshots() {
        val calls = mutableListOf<Pair<Long, String>>()
        var bridgeOwner = 4L
        val forwarder = forwarder(calls) { bridgeOwner }
        forwarder.announceAvailable(20)
        forwarder.onCapabilitiesChanged(20, wifi)
        bridgeOwner = 5L
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onLinkPropertiesChanged(20, link())!!.outcome)
        assertTrue(calls.isEmpty())
    }

    @Test
    fun losingPendingReplacementDoesNotRestorePreviousNetworkFromAttributes() {
        val calls = mutableListOf<Pair<Long, String>>()
        val forwarder = forwarder(calls)
        forwarder.announceAvailable(10)
        forwarder.onCapabilitiesChanged(10, cellular)
        forwarder.onLinkPropertiesChanged(10, link("rmnet0"))
        forwarder.announceAvailable(20)
        forwarder.onCapabilitiesChanged(20, wifi)
        forwarder.onLost(20)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onCapabilitiesChanged(10, cellular)!!.outcome)
        assertEquals(MobileLifecycleOutcome.STALE_REJECTED, forwarder.onLinkPropertiesChanged(10, link("old"))!!.outcome)
        assertEquals(1, calls.size)
    }

    private fun link(
        interfaceName: String = "wlan0",
        addresses: List<String> = listOf("192.0.2.10/24"),
        routes: List<String> = listOf("default via 192.0.2.1"),
        dns: List<String> = listOf("192.0.2.1"),
        mtu: Int = 1500,
    ) = PhysicalNetworkLinkIdentity.fromProperties(interfaceName, addresses, routes, dns, mtu)

    private fun forwarder(calls: MutableList<Pair<Long, String>>, bridgeOwner: () -> Long = { 4 }) =
        PhysicalNetworkCallbackForwarder(
            callbackServiceIncarnation = 40,
            callbackBridgeIncarnation = 4,
            currentServiceIncarnation = { 40 },
            currentBridgeIncarnation = bridgeOwner,
            notifier = PhysicalNetworkChangeNotifier { _, _, generation, hash ->
                calls += generation to hash
                MobileLifecycleOutcome.APPLIED
            },
        )
}
