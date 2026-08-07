#!/usr/bin/env python3
"""Regression tests for the deterministic dual-NAT simulator."""

import asyncio
import importlib.util
import socket
import struct
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("nat_sim.py")
SPEC = importlib.util.spec_from_file_location("p2wlan_nat_sim", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
NAT_SIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NAT_SIM)


class CaptureProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.received = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.received.put_nowait((data, addr))


def unused_udp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


class StunEncodingTests(unittest.TestCase):
    def test_binding_response_is_rfc5389_shaped_and_echoes_transaction_id(self):
        transaction_id = bytes(range(12))
        response = NAT_SIM.binding_response(transaction_id, "127.0.0.1", 36000)

        msg_type, message_length, cookie = struct.unpack("!HHI", response[:8])
        self.assertEqual(msg_type, NAT_SIM.BINDING_RESPONSE)
        self.assertEqual(message_length, 12)
        self.assertEqual(cookie, NAT_SIM.MAGIC_COOKIE)
        self.assertEqual(response[8:20], transaction_id)
        attr_type, attr_length, reserved, family, xor_port = struct.unpack("!HHBBH", response[20:28])
        self.assertEqual((attr_type, attr_length, reserved, family), (NAT_SIM.XOR_MAPPED_ADDRESS, 8, 0, 1))
        self.assertEqual(xor_port ^ (NAT_SIM.MAGIC_COOKIE >> 16), 36000)
        cookie_bytes = struct.pack("!I", NAT_SIM.MAGIC_COOKIE)
        decoded_ip = bytes(a ^ b for a, b in zip(response[28:32], cookie_bytes))
        self.assertEqual(decoded_ip, b"\x7f\x00\x00\x01")

    def test_stun_parser_rejects_wrong_cookie_length_and_type(self):
        transaction_id = bytes(range(12))
        valid = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, NAT_SIM.MAGIC_COOKIE) + transaction_id
        self.assertEqual(NAT_SIM.parse_binding_request(valid), transaction_id)
        self.assertIsNone(NAT_SIM.parse_binding_request(valid[:-1]))
        wrong_cookie = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, 0) + transaction_id
        self.assertIsNone(NAT_SIM.parse_binding_request(wrong_cookie))
        wrong_type = struct.pack("!HHI", NAT_SIM.BINDING_RESPONSE, 0, NAT_SIM.MAGIC_COOKIE) + transaction_id
        self.assertIsNone(NAT_SIM.parse_binding_request(wrong_type))


class NatIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transports = []
        self.nats = []

    async def asyncTearDown(self):
        for nat in self.nats:
            await nat.close()
        for transport in self.transports:
            transport.close()

    async def capture_endpoint(self):
        protocol = CaptureProtocol()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=("127.0.0.1", 0)
        )
        self.transports.append(transport)
        return transport, protocol, transport.get_extra_info("sockname")

    async def new_nat(self, name, fabric=None):
        nat = NAT_SIM.Nat(
            name,
            "127.0.0.1",
            1,
            seed=7 if name == "A" else 8,
            base_port=unused_udp_port(),
        )
        await nat.start(fabric)
        self.nats.append(nat)
        return nat

    async def test_stun_response_waits_for_a_bound_mapping_and_reuses_it(self):
        nat = await self.new_nat("A")
        observer = await nat.add_observer()
        client, received, client_addr = await self.capture_endpoint()
        transaction = bytes(range(12))
        request = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, NAT_SIM.MAGIC_COOKIE) + transaction

        client.sendto(request, observer)
        response, source = await asyncio.wait_for(received.received.get(), timeout=1)
        mapping = nat.mappings[(client_addr, observer)]
        self.assertEqual(source, observer)
        self.assertEqual(response[8:20], transaction)
        self.assertIn(mapping.port, nat.forwarders)
        self.assertEqual(nat.observed_sequence, [mapping.port])

        client.sendto(request, observer)
        await asyncio.wait_for(received.received.get(), timeout=1)
        self.assertEqual(nat.observed_sequence, [mapping.port])

    async def test_public_forwarder_callback_delivers_exact_mapping_destination(self):
        nat = await self.new_nat("A")
        client, received, client_addr = await self.capture_endpoint()
        peer, _, peer_addr = await self.capture_endpoint()
        mapping = nat.mapping_for(client_addr, peer_addr)
        await nat.ensure_bound(mapping)

        payload = b"forwarder-callback-only"
        peer.sendto(payload, (nat.public_ip, mapping.port))
        delivered, source = await asyncio.wait_for(received.received.get(), timeout=1)
        self.assertEqual(delivered, payload)
        self.assertEqual(source, (nat.public_ip, mapping.port))

    async def test_private_sender_is_reemitted_from_the_sender_nat_public_mapping(self):
        fabric = NAT_SIM.NatFabric()
        nat_a = await self.new_nat("A", fabric)
        nat_b = await self.new_nat("B", fabric)
        client_a, received_a, client_a_addr = await self.capture_endpoint()
        client_b, received_b, client_b_addr = await self.capture_endpoint()
        nat_a.record_client(client_a_addr)
        nat_b.record_client(client_b_addr)

        # B's public endpoint is open before A starts punching.  The packet
        # from A reaches B once with A's private source, then NatFabric
        # re-emits it from the public mapping and B delivers only that copy.
        mapping_b = nat_b.mapping_for(client_b_addr, ("127.0.0.1", 9))
        await nat_b.ensure_bound(mapping_b)
        payload = b"source-nat-visible-to-peer"
        client_a.sendto(payload, (nat_b.public_ip, mapping_b.port))

        delivered, source = await asyncio.wait_for(received_b.received.get(), timeout=1)
        mapping_a = nat_a.mappings[(client_a_addr, (nat_b.public_ip, mapping_b.port))]
        self.assertEqual(delivered, payload)
        self.assertEqual(source, (nat_a.public_ip, mapping_a.port))
        self.assertNotEqual(source, client_a_addr)
        self.assertNotEqual(source, (nat_b.public_ip, mapping_b.port))

        reverse_payload = b"reverse-source-nat-visible-to-peer"
        client_b.sendto(reverse_payload, (nat_a.public_ip, mapping_a.port))
        reverse_delivered, reverse_source = await asyncio.wait_for(received_a.received.get(), timeout=1)
        reverse_mapping = nat_b.mappings[(client_b_addr, (nat_a.public_ip, mapping_a.port))]
        self.assertEqual(reverse_delivered, reverse_payload)
        self.assertEqual(reverse_source, (nat_b.public_ip, reverse_mapping.port))
        self.assertNotEqual(reverse_source, client_b_addr)

    async def test_unknown_private_sender_cannot_bypass_the_nat_filter(self):
        fabric = NAT_SIM.NatFabric()
        nat = await self.new_nat("A", fabric)
        _, received, client_addr = await self.capture_endpoint()
        attacker, _, _ = await self.capture_endpoint()
        mapping = nat.mapping_for(client_addr, ("127.0.0.1", 9))
        await nat.ensure_bound(mapping)

        attacker.sendto(b"must-drop", (nat.public_ip, mapping.port))
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(received.received.get(), timeout=0.15)


if __name__ == "__main__":
    unittest.main()
