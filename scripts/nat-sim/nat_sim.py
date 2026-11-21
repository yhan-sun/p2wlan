#!/usr/bin/env python3
"""Deterministic dual-NAT simulator for the p2wlan dual-end harness.

The simulator uses two address/port-dependent NATs on loopback.  Each mapping
owns one public UDP socket, so packets delivered to a daemon are sourced from
the mapping port that a remote peer would actually observe.

Hard<->Hard uses a test-only libc sendto/sendmsg shim: every loopback UDP
send, from the original daemon socket, carries its destination to a per-NAT
gateway. The gateway allocates the source mapping even when the destination
has no mapping/listener. It then routes only through existing public mappings,
so a guessed host port cannot bypass the simulated NAT. Per-process successful
send counters are reconciled with gateway receipts; a lost gateway datagram
invalidates the experiment instead of silently skipping a NAT allocation.

The legacy listener route is retained for existing Direct/Relay gates. It can
only observe registered private sends to bound public/preview ports and is not
a complete outbound-capture oracle. Optional preview sockets never admit public
inbound traffic before a real mapping exists.

STUN observers are the NAT's measurement face.  They return RFC 5389 Binding
responses with the allocated mapping encoded as XOR-MAPPED-ADDRESS.  They are
kept separate from public forwarders so observer packets cannot accidentally
become peer traffic.

The control plane and TCP relay intentionally bypass this UDP topology.
"""

import argparse
import asyncio
import collections
import dataclasses
import errno
import json
import os
from pathlib import Path
import random
import signal
import socket
import struct
import time
from background_traffic import run_background, validate_background_limits
from network_conditions import Impairments, NetworkProfile, load_profiles
from monotonic_clock import monotonic_ns
from typing import Deque, Dict, List, Optional, Set, Tuple


MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
XOR_MAPPED_ADDRESS = 0x0020
Address = Tuple[str, int]


def format_address(addr: Address) -> str:
    return f"{addr[0]}:{addr[1]}"


def wireguard_transport_trace_fields(data: bytes) -> Dict[str, object]:
    """Return bounded identity fields only for syntactically typed WG data.

    This classifies the UDP envelope, not its authenticity. A daemon's
    decrypt-success/replay result is still required before calling a packet a
    valid current-session ciphertext.
    """
    if len(data) < 16 or data[:4] != b"\x04\x00\x00\x00":
        return {}
    fingerprint = 0xCBF29CE484222325
    for byte in data:
        fingerprint ^= byte
        fingerprint = (fingerprint * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return {
        "payload_class": "wireguard_transport_v1",
        "receiver_index": int.from_bytes(data[4:8], "little"),
        "wireguard_counter": int.from_bytes(data[8:16], "little"),
        "wire_fp": f"{fingerprint:016x}",
    }


class NatTrace:
    """Optional sanitized event trace for deterministic traversal analysis."""

    def __init__(self, path: str) -> None:
        self._stream = open(path, "w", encoding="utf-8")
        self._sequence = 0

    def record(self, event: str, **fields: object) -> None:
        self._sequence += 1
        row = {
            "sequence": self._sequence,
            "monotonic_ns": monotonic_ns(),
            "event": event,
            **fields,
        }
        self._stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


def ip_bytes(ip: str) -> bytes:
    octets = ip.split(".")
    if len(octets) != 4:
        raise ValueError("the loopback NAT simulator supports IPv4 only")
    return bytes(int(part) for part in octets)


def parse_binding_request(data: bytes) -> Optional[bytes]:
    """Return a RFC 5389 Binding request transaction ID, or reject the frame."""
    if len(data) < 20:
        return None
    msg_type, message_length, cookie = struct.unpack("!HHI", data[:8])
    if msg_type != BINDING_REQUEST or cookie != MAGIC_COOKIE:
        return None
    # STUN attributes are 32-bit aligned and the header length excludes the
    # 20-byte header.  Do not answer truncated/trailing frames.
    if message_length % 4 != 0 or len(data) != 20 + message_length:
        return None
    return data[8:20]


def binding_response(transaction: bytes, public_ip: str, public_port: int) -> bytes:
    """Build a RFC 5389 IPv4 Binding Success Response."""
    if len(transaction) != 12:
        raise ValueError("STUN transaction IDs are exactly 12 bytes")
    xor_port = public_port ^ (MAGIC_COOKIE >> 16)
    cookie = struct.pack("!I", MAGIC_COOKIE)
    xor_ip = bytes(a ^ b for a, b in zip(ip_bytes(public_ip), cookie[:4]))
    attribute = struct.pack("!HHBBH", XOR_MAPPED_ADDRESS, 8, 0, 1, xor_port) + xor_ip
    return struct.pack("!HHI", BINDING_RESPONSE, len(attribute), MAGIC_COOKIE) + transaction + attribute


@dataclasses.dataclass
class Mapping:
    client: Address
    destination: Address
    port: int
    transport: Optional[asyncio.DatagramTransport] = None
    bound_reported: bool = False
    bind_task: Optional[asyncio.Task] = None
    send_task: Optional[asyncio.Task] = None
    pending: Deque[Tuple[bytes, Address]] = dataclasses.field(default_factory=collections.deque)
    last_outbound_at: float = 0.0


class StunObserverProtocol(asyncio.DatagramProtocol):
    """Public STUN measurement endpoint for one simulated NAT."""

    def __init__(self, nat: "Nat") -> None:
        self.nat = nat
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.observer_addr: Optional[Address] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # Datagram endpoints always hand us a DatagramTransport.  The base
        # signature is required by asyncio's Protocol interface.
        self.transport = transport  # type: ignore[assignment]
        self.observer_addr = transport.get_extra_info("sockname")

    def datagram_received(self, data: bytes, addr: Address) -> None:
        transaction = parse_binding_request(data)
        if transaction is None or self.transport is None or self.observer_addr is None:
            return
        self.nat.handle_stun_request(self.transport, addr, self.observer_addr, transaction)


class PublicForwarderProtocol(asyncio.DatagramProtocol):
    """The only reader for a public mapping socket.

    In particular, this avoids calling ``recvfrom`` on a file descriptor that
    is already registered with an asyncio DatagramTransport.
    """

    def __init__(self, nat: "Nat", port: int) -> None:
        self.nat = nat
        self.port = port

    def datagram_received(self, data: bytes, addr: Address) -> None:
        self.nat.handle_public_datagram(self.port, data, addr)


class EgressGatewayProtocol(asyncio.DatagramProtocol):
    """A per-NAT shim ingress; every destination is observed before routing."""

    def __init__(self, nat: "Nat") -> None:
        self.nat = nat

    def datagram_received(self, data: bytes, client: Address) -> None:
        if (client[0] != "127.0.0.1" or len(data) < 16 or data[:8] != b"P2NAT001"
                or int.from_bytes(data[14:16], "big") != len(data) - 16):
            self.nat.record("egress_rejected", reason="invalid_envelope")
            return
        destination = (socket.inet_ntoa(data[8:12]), int.from_bytes(data[12:14], "big"))
        if not destination[0].startswith("127.") or destination[1] == 0:
            self.nat.record("egress_rejected", reason="destination_outside_loopback")
            return
        self.nat.record_client(client)
        self.nat.record("egress_captured", client=format_address(client),
                        destination=format_address(destination), bytes=len(data) - 16)
        self.nat.egress_activity.set()
        self.nat.activate_network()
        for transport, observer in self.nat.observers:
            if destination == observer:
                transaction = parse_binding_request(data[16:])
                if transaction is not None:
                    self.nat.handle_stun_request(transport, client, observer, transaction)
                return
        self.nat.translate_outbound(client, destination, data[16:])


class NatFabric:
    """Coordinates source translation between the two loopback NATs."""

    def __init__(self, trace: Optional[NatTrace] = None) -> None:
        self.nats: List["Nat"] = []
        self.trace = trace
        self.reciprocal_pairs: Set[Tuple[Address, Address]] = set()

    def record(self, event: str, **fields: object) -> None:
        if self.trace is not None:
            self.trace.record(event, **fields)

    def add_nat(self, nat: "Nat") -> None:
        if nat not in self.nats:
            self.nats.append(nat)

    def route_translated(self, sender: "Nat", mapping: Mapping, data: bytes, destination: Address) -> None:
        # Source mapping already exists even when the destination is unbound.
        # Never send raw packets to arbitrary host sockets/private daemon ports.
        if sender.network_outage:
            sender.record("packet_dropped_outage", direction="outbound", bytes=len(data))
            return
        if sender.block_direct or (
            sender.direct_gate_file is not None and not os.path.exists(sender.direct_gate_file)
        ):
            self.record("direct_blocked", nat=sender.name,
                        reason="permanent_blackhole" if sender.block_direct else "startup_gate_closed")
            return
        for receiver in self.nats:
            if receiver is not sender and receiver.owns_public_endpoint(destination):
                if receiver.block_direct or (
                    receiver.direct_gate_file is not None and not os.path.exists(receiver.direct_gate_file)
                ):
                    self.record("direct_blocked", nat=receiver.name, reason="receiver_gate_closed")
                    return
                receiver.handle_public_datagram(destination[1], data, (sender.public_ip, mapping.port))
                return
        self.record("outbound_destination_unmapped", nat=sender.name,
                    public_endpoint=f"{sender.public_ip}:{mapping.port}",
                    destination=format_address(destination), bytes=len(data))

    def mapping_bound(self, nat: "Nat", mapping: Mapping) -> None:
        if mapping.bound_reported:
            return
        mapping.bound_reported = True
        endpoint = (nat.public_ip, mapping.port)
        self.record("mapping_bound", nat=nat.name, client=format_address(mapping.client),
                    public_endpoint=format_address(endpoint), destination=format_address(mapping.destination))
        peer = self.mapping_for_public_endpoint(nat, mapping.destination)
        if peer is None or peer[1].destination != endpoint:
            return
        pair = tuple(sorted((endpoint, mapping.destination)))
        if pair not in self.reciprocal_pairs:
            self.reciprocal_pairs.add(pair)
            self.record("reciprocal_mapping_pair", public_endpoint_a=format_address(pair[0]),
                        public_endpoint_b=format_address(pair[1]), pair_count=len(self.reciprocal_pairs))

    def owner_for_private_client(self, addr: Address) -> Optional["Nat"]:
        for nat in self.nats:
            if addr in nat.client_sockets:
                return nat
        return None

    def is_peer_public_endpoint(self, receiver: "Nat", addr: Address) -> bool:
        return any(
            nat is not receiver and nat.owns_public_endpoint(addr)
            for nat in self.nats
        )

    def mapping_for_public_endpoint(self, receiver: "Nat", addr: Address) -> Optional[Tuple["Nat", Mapping]]:
        for nat in self.nats:
            if nat is receiver or not nat.owns_public_endpoint(addr):
                continue
            mapping = nat.mapping_by_port.get(addr[1])
            if mapping is not None:
                return nat, mapping
        return None


class Nat:
    """Address/port-dependent mapping NAT with user-space loopback routing."""

    def __init__(
        self,
        name: str,
        public_ip: str,
        step: int,
        seed: int,
        base_port: int,
        consume_before_punch: int = 0,
        loss_rate: float = 0.0,
        reorder: bool = False,
        strict_filtering: bool = False,
        block_direct: bool = False,
        mapping_mode: str = "step",
        delivery_delay_ms: int = 0,
        stun_delay_ms: int = 0,
        duplicate_rate: float = 0.0,
        direct_gate_file: Optional[str] = None,
        unassigned_egress_listeners: int = 0,
        sweep_noise_every: int = 0,
        sweep_noise_count: int = 0,
        sweep_noise_limit: int = 64,
        network_profile: Optional[NetworkProfile] = None,
    ) -> None:
        if mapping_mode not in {"step", "random"}:
            raise ValueError("mapping_mode must be 'step' or 'random'")
        if mapping_mode == "step" and step == 0:
            raise ValueError("--step must not be zero for address/port-dependent mappings")
        if not 1024 <= base_port <= 65535:
            raise ValueError("--base must be in the allocatable UDP range 1024..65535")
        if delivery_delay_ms < 0 or stun_delay_ms < 0:
            raise ValueError("simulated delays must be non-negative")
        if not 0.0 <= duplicate_rate <= 1.0:
            raise ValueError("duplicate_rate must be between 0 and 1")
        if not 0 <= unassigned_egress_listeners <= 32:
            raise ValueError("unassigned_egress_listeners must be between 0 and 32")
        if not 0 <= consume_before_punch <= 64:
            raise ValueError("consume_before_punch must be in 0..64 per measured socket")
        if not 0 <= sweep_noise_every <= 1024 or not 0 <= sweep_noise_count <= 64:
            raise ValueError("sweep noise interval/count is outside bounds")
        if not 0 <= sweep_noise_limit <= 4096:
            raise ValueError("sweep noise limit must be in 0..4096")
        self.sweep_noise_every = sweep_noise_every
        self.sweep_noise_count = sweep_noise_count
        self.sweep_noise_remaining = sweep_noise_limit
        self.initial_noise_remaining = 4096
        self.noise_ports: Set[int] = set()
        self.measurements: Dict[Address, int] = {}
        self.peer_mapping_counts: Dict[Address, int] = {}
        self.egress_gateway: Optional[asyncio.DatagramTransport] = None
        self.name = name
        self.public_ip = public_ip
        self.step = step
        self.rng = random.Random(seed)
        self.next_port = base_port
        self.consume_before_punch = consume_before_punch
        self.loss_rate = loss_rate
        self.reorder = reorder
        self.mapping_mode = mapping_mode
        self.delivery_delay_ms = delivery_delay_ms
        self.stun_delay_ms = stun_delay_ms
        self.duplicate_rate = duplicate_rate
        # Endpoint-dependent filtering: only the exact destination a client's
        # mapping was created toward may send in; a peer's other public socket
        # is not automatically admitted.
        self.strict_filtering = strict_filtering
        # Deterministic bidirectional UDP data-plane blackhole: every inter-NAT
        # datagram is dropped while STUN observers keep working, so Direct can
        # never establish but the relay data plane still carries traffic.  This
        # models the field CGNAT bidirectional UDP blackhole.
        self.block_direct = block_direct
        # Hard<->Hard experiment-only startup gate. STUN observers and the
        # TCP control/Relay planes remain live; only inter-NAT UDP is held
        # until the harness observes that both real rendezvous workers were
        # scheduled. An absent option preserves every established topology.
        self.direct_gate_file = direct_gate_file
        # Explicit loopback-only look-ahead. A provisional listener captures
        # only a registered private sender's first outbound edge; it is not a
        # peer-visible mapping and cannot admit public inbound traffic.
        self.unassigned_egress_listeners = unassigned_egress_listeners
        self.mappings: Dict[Tuple[Address, Address], Mapping] = {}
        self.mapping_by_port: Dict[int, Mapping] = {}
        self.forwarders: Dict[int, asyncio.DatagramTransport] = {}
        self.provisional_forwarders: Dict[int, asyncio.DatagramTransport] = {}
        self.client_sockets: Set[Address] = set()
        self.observers: List[Tuple[asyncio.DatagramTransport, Address]] = []
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.fabric: Optional[NatFabric] = None
        self.observed_sequence: List[int] = []
        self._egress_refresh_task: Optional[asyncio.Task] = None
        self._egress_refresh_needed = False
        self.egress_activity = None
        self.network_profile = network_profile or NetworkProfile()
        self.impairments = Impairments(self.network_profile, seed)
        self.network_outage = False
        self._network_started_at = None
        self._network_task = None
        self._network_rebound = False
        self._packet_tasks: Set[asyncio.Task] = set()
        self._retired_tasks: Set[asyncio.Task] = set()
        self._closed = False

    async def start(self, fabric: Optional[NatFabric] = None) -> "Nat":
        self.loop = asyncio.get_running_loop()
        self.egress_activity = asyncio.Event()
        self.fabric = fabric
        if fabric is not None:
            fabric.add_nat(self)
        await self._ensure_egress_listeners()
        return self

    async def close(self) -> None:
        self._closed = True
        tasks = list(self._packet_tasks | self._retired_tasks)
        if self._network_task is not None:
            tasks.append(self._network_task)
        for task in tasks:
            task.cancel()
        if self._egress_refresh_task is not None and not self._egress_refresh_task.done():
            self._egress_refresh_task.cancel()
            tasks.append(self._egress_refresh_task)
        for mapping in self.mappings.values():
            for task in (mapping.bind_task, mapping.send_task):
                if task is not None and not task.done():
                    task.cancel()
                    tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.egress_gateway is not None:
            self.egress_gateway.close()
            self.egress_gateway = None
        for transport, _ in self.observers:
            transport.close()
        for transport in self.forwarders.values():
            transport.close()
        for transport in self.provisional_forwarders.values():
            transport.close()
        self.observers.clear()
        self.forwarders.clear()
        self.provisional_forwarders.clear()

    def activate_network(self) -> None:
        if self._network_started_at is not None or self.loop is None or self._closed:
            return
        self._network_started_at = self.loop.time()
        self.record("network_conditions_started", profile=self.network_profile.to_dict())
        profile = self.network_profile
        if profile.outage_after_ms or profile.rebind_after_ms or profile.mapping_idle_ms:
            self._network_task = self.loop.create_task(self._run_network_events())

    async def _run_network_events(self) -> None:
        while not self._closed:
            self.advance_network(self.loop.time())
            await asyncio.sleep(0.05)

    def advance_network(self, now: float) -> None:
        if self._network_started_at is None:
            return
        profile = self.network_profile
        elapsed = (now - self._network_started_at) * 1000
        outage = (profile.outage_after_ms > 0
                  and profile.outage_after_ms <= elapsed < profile.outage_after_ms + profile.outage_duration_ms)
        if outage != self.network_outage:
            self.network_outage = outage
            self.record("network_outage_started" if outage else "network_outage_ended")
        if profile.rebind_after_ms and elapsed >= profile.rebind_after_ms and not self._network_rebound:
            self._network_rebound = True
            count = len(self.mappings)
            for mapping in list(self.mappings.values()):
                self.retire_mapping(mapping, "network_rebind")
            self.record("network_rebound", retired_mappings=count)
        if profile.mapping_idle_ms:
            for mapping in list(self.mappings.values()):
                if (now - mapping.last_outbound_at) * 1000 >= profile.mapping_idle_ms:
                    self.retire_mapping(mapping, "idle_timeout")

    def mapping_is_current(self, mapping: Mapping) -> bool:
        return not self._closed and self.mappings.get((mapping.client, mapping.destination)) is mapping

    def retire_mapping(self, mapping: Mapping, reason: str) -> None:
        if not self.mapping_is_current(mapping):
            return
        del self.mappings[(mapping.client, mapping.destination)]
        self.mapping_by_port.pop(mapping.port, None)
        transport = self.forwarders.pop(mapping.port, None)
        if transport is not None:
            transport.close()
        mapping.transport = None
        mapping.pending.clear()
        for task in (mapping.bind_task, mapping.send_task):
            if task is not None and not task.done():
                self._retired_tasks.add(task)
                task.add_done_callback(self._retired_tasks.discard)
                task.cancel()
        self.record("mapping_retired", public_endpoint=f"{self.public_ip}:{mapping.port}",
                    client=format_address(mapping.client), destination=format_address(mapping.destination),
                    reason=reason)

    def spawn_packet_task(self, coroutine, packet_kind: str) -> None:
        if self._closed or self.loop is None or len(self._packet_tasks) >= self.network_profile.queue_limit:
            coroutine.close()
            self.record("packet_dropped_queue", packet_kind=packet_kind, reason="pending_packet_limit")
            return
        task = self.loop.create_task(coroutine)
        self._packet_tasks.add(task)
        def completed(done):
            self._packet_tasks.discard(done)
            if not done.cancelled() and done.exception() is not None:
                self.record("network_packet_task_failed", packet_kind=packet_kind,
                            error_type=type(done.exception()).__name__)
        task.add_done_callback(completed)

    def alloc_port(self) -> int:
        if self.mapping_mode == "random":
            port = self.rng.randrange(1024, 65536)
        else:
            port = self.next_port
            # Walk the complete allocatable UDP port ring. This preserves a
            # signed step at both ends instead of folding low ports onto an
            # unrelated +1024 sequence.
            self.next_port = 1024 + ((port - 1024 + self.step) % 64512)
        self.observed_sequence.append(port)
        return port

    def _allocate_unused_port(self) -> int:
        # A mapping needs an exclusive socket.  The configured sequence is
        # preserved unless it cycles onto a live mapping or an occupied port.
        for _ in range(64512):
            port = self.alloc_port()
            if port not in self.mapping_by_port and port not in self.noise_ports:
                return port
        raise RuntimeError(f"NAT {self.name} exhausted public UDP ports")

    def _preview_unused_ports(self, count: int) -> List[int]:
        """Preview allocator outputs without advancing production state."""
        if count <= 0:
            return []
        preview_rng = random.Random()
        preview_rng.setstate(self.rng.getstate())
        next_port = self.next_port
        ports: List[int] = []
        reserved: Set[int] = set(self.mapping_by_port) | self.noise_ports
        for _ in range(64512):
            if self.mapping_mode == "random":
                port = preview_rng.randrange(1024, 65536)
            else:
                port = next_port
                next_port = 1024 + ((port - 1024 + self.step) % 64512)
            if port in reserved:
                continue
            ports.append(port)
            reserved.add(port)
            if len(ports) == count:
                break
        return ports

    def _schedule_egress_listener_refresh(self) -> None:
        if self.unassigned_egress_listeners == 0 or self.loop is None:
            return
        self._egress_refresh_needed = True
        if self._egress_refresh_task is None or self._egress_refresh_task.done():
            self._egress_refresh_task = self.loop.create_task(self._refresh_egress_listeners())

    async def _refresh_egress_listeners(self) -> None:
        while self._egress_refresh_needed:
            self._egress_refresh_needed = False
            await self._ensure_egress_listeners()

    async def _ensure_egress_listeners(self) -> None:
        """Keep only the bounded allocator look-ahead window bound."""
        if self.unassigned_egress_listeners == 0:
            return
        if self.loop is None:
            raise RuntimeError("start the NAT before binding egress listeners")
        desired = set(self._preview_unused_ports(self.unassigned_egress_listeners))
        for port in set(self.provisional_forwarders) - desired:
            self.provisional_forwarders.pop(port).close()
        for port in desired - set(self.provisional_forwarders):
            if port in self.mapping_by_port or port in self.forwarders:
                continue
            try:
                transport, _ = await self.loop.create_datagram_endpoint(
                    lambda port=port: PublicForwarderProtocol(self, port),
                    local_addr=(self.public_ip, port),
                )
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    continue
                raise
            mapping = self.mapping_by_port.get(port)
            if mapping is not None and mapping.transport is None:
                mapping.transport = transport
                self.forwarders[port] = transport
            elif mapping is None:
                self.provisional_forwarders[port] = transport
            else:
                transport.close()

    def _reassign_mapping_port(self, mapping: Mapping) -> None:
        previous = mapping.port
        if self.mapping_by_port.get(previous) is mapping:
            del self.mapping_by_port[previous]
        mapping.port = self._allocate_unused_port()
        self.mapping_by_port[mapping.port] = mapping

    def record_client(self, addr: Address) -> None:
        self.client_sockets.add(addr)

    def mapping_for(self, client: Address, destination: Address) -> Mapping:
        key = (client, destination)
        mapping = self.mappings.get(key)
        if mapping is not None:
            mapping.last_outbound_at = self.loop.time() if self.loop else time.monotonic()
            return mapping
        mapping = Mapping(client=client, destination=destination, port=self._allocate_unused_port())
        mapping.last_outbound_at = self.loop.time() if self.loop else time.monotonic()
        self.mappings[key] = mapping
        self.mapping_by_port[mapping.port] = mapping
        provisional = self.provisional_forwarders.pop(mapping.port, None)
        if provisional is not None:
            mapping.transport = provisional
            self.forwarders[mapping.port] = provisional
        self._schedule_egress_listener_refresh()
        if self.fabric is not None:
            self.fabric.record(
                "mapping_created",
                nat=self.name,
                client=format_address(client),
                public_endpoint=f"{self.public_ip}:{mapping.port}",
                destination=format_address(destination),
            )
        return mapping

    def owns_public_endpoint(self, addr: Address) -> bool:
        return addr[0] == self.public_ip and addr[1] in self.forwarders

    async def add_observer(self, host: str = "127.0.0.1") -> Address:
        if self.loop is None:
            raise RuntimeError("start the NAT before adding observers")
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: StunObserverProtocol(self), local_addr=(host, 0)
        )
        observer_addr = transport.get_extra_info("sockname")
        self.observers.append((transport, observer_addr))
        return observer_addr

    def record(self, event: str, **fields: object) -> None:
        if self.fabric is not None:
            self.fabric.record(event, nat=self.name, **fields)

    async def add_egress_gateway(self) -> Address:
        if self.loop is None:
            raise RuntimeError("start the NAT before its egress gateway")
        if self.egress_gateway is not None:
            raise RuntimeError("egress gateway already exists")
        self.egress_gateway, _ = await self.loop.create_datagram_endpoint(
            lambda: EgressGatewayProtocol(self), local_addr=("127.0.0.1", 0))
        # Bounded buffering reduces local harness loss under birthday bursts.
        # The receipt/counter reconciliation remains authoritative regardless
        # of the OS's actual SO_RCVBUF cap.
        gateway_socket = self.egress_gateway.get_extra_info("socket")
        try:
            gateway_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        except OSError:
            pass
        self.record("egress_gateway_ready", schema_version=1, capture="libc_sendto_sendmsg",
                    gateway_port=self.egress_gateway.get_extra_info("sockname")[1])
        return self.egress_gateway.get_extra_info("sockname")

    def _report_bound(self, mapping: Mapping) -> None:
        if self.fabric is not None:
            self.fabric.mapping_bound(self, mapping)

    async def ensure_bound(self, mapping: Mapping) -> None:
        if not self.mapping_is_current(mapping):
            return
        if mapping.transport is not None:
            self._report_bound(mapping)
            return
        provisional = self.provisional_forwarders.pop(mapping.port, None)
        if provisional is not None:
            mapping.transport = provisional
            self.forwarders[mapping.port] = provisional
            self._report_bound(mapping)
            return
        if mapping.bind_task is None:
            if self.loop is None:
                raise RuntimeError("start the NAT before allocating mappings")
            mapping.bind_task = self.loop.create_task(self._bind_mapping(mapping))
        await asyncio.shield(mapping.bind_task)
        if self.mapping_is_current(mapping):
            self._report_bound(mapping)

    async def _bind_mapping(self, mapping: Mapping) -> None:
        if self.loop is None:
            raise RuntimeError("start the NAT before allocating mappings")
        while mapping.transport is None:
            port = mapping.port
            provisional = self.provisional_forwarders.pop(port, None)
            if provisional is not None:
                mapping.transport = provisional
                self.forwarders[port] = provisional
                return
            try:
                transport, _ = await self.loop.create_datagram_endpoint(
                    lambda: PublicForwarderProtocol(self, port),
                    local_addr=(self.public_ip, port),
                )
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
                # A host process may own a port in our deterministic range.
                # Reallocate before either STUN or peer traffic observes it.
                self._reassign_mapping_port(mapping)
                continue
            if not self.mapping_is_current(mapping):
                transport.close()
                return
            mapping.transport = transport
            self.forwarders[port] = transport

    def handle_stun_request(
        self,
        observer_transport: asyncio.DatagramTransport,
        client: Address,
        observer: Address,
        transaction: bytes,
    ) -> None:
        self.record_client(client)
        self.activate_network()
        self.measurements[client] = self.measurements.get(client, 0) + 1
        mapping = self.mapping_for(client, observer)
        self.record("stun_mapping_observed", client=format_address(client),
                    observer=format_address(observer), sample=self.measurements[client],
                    public_endpoint=f"{self.public_ip}:{mapping.port}")
        if self.loop is None:
            return
        self.spawn_packet_task(
            self._reply_to_stun_after_bind(observer_transport, client, transaction, mapping), "stun")

    async def _reply_to_stun_after_bind(
        self,
        observer_transport: asyncio.DatagramTransport,
        client: Address,
        transaction: bytes,
        mapping: Mapping,
    ) -> None:
        try:
            await self.ensure_bound(mapping)
        except OSError:
            return
        if not self.mapping_is_current(mapping):
            return
        if self.network_outage:
            self.record("packet_dropped_outage", packet_kind="stun", bytes=20)
            return
        response = binding_response(transaction, self.public_ip, mapping.port)
        delay = self.stun_delay_ms / 1000
        if self.network_profile.impair_stun:
            reason = self.impairments.loss(self.loss_rate)
            if reason:
                self.record(reason, packet_kind="stun", bytes=len(response))
                return
            delay = self.impairments.delay(self.loop.time(), self.stun_delay_ms, len(response))
            if delay is None:
                self.record("packet_dropped_queue", packet_kind="stun", reason="queue_deadline")
                return
            self.record("packet_conditioned", packet_kind="stun", delay_ms=round(delay * 1000, 3))
        if delay > 0:
            await asyncio.sleep(delay)
        if not self.mapping_is_current(mapping):
            self.record("packet_dropped_stale_mapping", packet_kind="stun")
            return
        if self.network_outage:
            self.record("packet_dropped_outage", packet_kind="stun", bytes=len(response))
            return
        observer_transport.sendto(response, client)

    def translate_outbound(self, client: Address, destination: Address, data: bytes) -> None:
        """Source-NAT a daemon datagram then send it to the public destination."""
        if (client, destination) not in self.mappings:
            count = self.peer_mapping_counts.get(client, 0)
            measured = self.measurements.get(client, 0)
            if count == 0 and measured:
                noise = min(self.consume_before_punch, self.initial_noise_remaining)
                self._consume_noise(client, noise, "post_measurement_before_first_peer", count)
                self.initial_noise_remaining -= noise
            elif count and self.sweep_noise_every and count % self.sweep_noise_every == 0:
                noise = min(self.sweep_noise_count, self.sweep_noise_remaining)
                self._consume_noise(client, noise, "during_sweep", count)
                self.sweep_noise_remaining -= noise
            self.record("peer_mapping_started", client=format_address(client),
                        destination=format_address(destination), prior_peer_mappings=count,
                        measurement_samples=measured)
            self.peer_mapping_counts[client] = count + 1
        mapping = self.mapping_for(client, destination)
        if len(mapping.pending) >= 256:
            self.record("outbound_queue_rejected", reason="mapping_queue_capacity", bytes=len(data))
            return
        mapping.pending.append((data, destination))
        if mapping.send_task is None or mapping.send_task.done():
            if self.loop is None:
                return
            mapping.send_task = self.loop.create_task(self._flush_outbound(mapping))

    def _consume_noise(self, client: Address, count: int, stage: str, peer_count: int) -> None:
        for _ in range(count):
            port = self._allocate_unused_port()
            self.noise_ports.add(port)
            self.record("mapping_consumed", client=format_address(client), stage=stage,
                        public_endpoint=f"{self.public_ip}:{port}",
                        measurement_samples=self.measurements.get(client, 0),
                        prior_peer_mappings=peer_count)

    async def _flush_outbound(self, mapping: Mapping) -> None:
        try:
            await self.ensure_bound(mapping)
            if not self.mapping_is_current(mapping):
                return
            while mapping.pending:
                data, destination = mapping.pending.popleft()
                if mapping.transport is not None:
                    if self.egress_gateway is not None and self.fabric is not None:
                        self.fabric.route_translated(self, mapping, data, destination)
                    else:
                        mapping.transport.sendto(data, destination)
        except OSError as error:
            # A non-recoverable bind error must not leave an unobserved task
            # exception or replay stale packets on a later mapping attempt.
            self.record("outbound_mapping_error", reason="public_socket_bind_or_send_failed", errno=error.errno)
            mapping.pending.clear()
        finally:
            mapping.send_task = None

    def inbound_allowed(self, mapping: Mapping, addr: Address) -> bool:
        # Exact destination matching is the normal endpoint-dependent path.
        if addr == mapping.destination:
            return True
        if self.strict_filtering:
            # Endpoint-dependent filtering: the client's mapping was created
            # only toward `mapping.destination`; any other source (including a
            # peer's unrelated public socket) is rejected.
            return False
        # A fresh peer-facing mapping can legitimately move between the peer's
        # STUN measurement and its first authenticated punch.  In the loopback
        # model accept only a real public socket owned by the other simulated
        # NAT, never its private client socket or an arbitrary local sender.
        return self.fabric is not None and self.fabric.is_peer_public_endpoint(self, addr)

    def handle_public_datagram(self, port: int, data: bytes, addr: Address) -> None:
        mapping = self.mapping_by_port.get(port)
        source_nat = self.fabric.owner_for_private_client(addr) if self.fabric is not None else None
        if source_nat is not None:
            if source_nat is not self:
                receiver_gate_closed = self.direct_gate_file is not None and not os.path.exists(
                    self.direct_gate_file
                )
                sender_gate_closed = (
                    source_nat.direct_gate_file is not None
                    and not os.path.exists(source_nat.direct_gate_file)
                )
                if (
                    self.block_direct
                    or source_nat.block_direct
                    or receiver_gate_closed
                    or sender_gate_closed
                ):
                    # Deterministic bidirectional UDP blackhole: this is a
                    # daemon's direct data-plane datagram and the blackhole is
                    # on.  Drop it so Direct can never establish while STUN
                    # gathering and the TCP relay keep working.
                    if self.fabric is not None:
                        self.fabric.record(
                            "direct_blocked",
                            receiver_nat=self.name,
                            sender_nat=source_nat.name,
                            receiver_endpoint=f"{self.public_ip}:{port}",
                            reason=(
                                "permanent_blackhole"
                                if self.block_direct or source_nat.block_direct
                                else "startup_gate_closed"
                            ),
                        )
                    return
                # This is a daemon's direct loopback send.  Re-inject it from
                # the sender NAT's mapping socket so the receiver sees the
                # sender's public endpoint, exactly once.
                source_nat.translate_outbound(addr, (self.public_ip, port), data)
            # Hairpinning is intentionally unsupported by this harness.
            return
        # Provisional sockets exist solely to observe a registered private
        # sender's first outbound edge. Public inbound to an unassigned port
        # cannot create or impersonate a NAT mapping.
        if mapping is None:
            return
        if self.network_outage:
            self.record("packet_dropped_outage", direction="inbound", bytes=len(data))
            return
        if not self.inbound_allowed(mapping, addr):
            if self.fabric is not None:
                self.fabric.record(
                    "inbound_filter_drop",
                    nat=self.name,
                    receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                    expected_source=format_address(mapping.destination),
                    actual_source=format_address(addr),
                )
            return
        loss_reason = self.impairments.loss(self.loss_rate)
        if loss_reason:
            if self.fabric is not None:
                self.fabric.record(
                    loss_reason,
                    nat=self.name,
                    receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                    bytes=len(data),
                    **wireguard_transport_trace_fields(data),
                )
            return
        delay_seconds = self.impairments.delay(self.loop.time(), self.delivery_delay_ms, len(data))
        if delay_seconds is None:
            self.record("packet_dropped_queue", packet_kind="peer", reason="queue_deadline")
            return
        reorder_delay_injected = self.reorder and self.impairments.rng.random() < 0.25
        if reorder_delay_injected:
            delay_seconds += 0.02
        duplicate = self.duplicate_rate > 0 and self.impairments.rng.random() < self.duplicate_rate
        if delay_seconds > 0:
            source_mapping = self.fabric.mapping_for_public_endpoint(self, addr) if self.fabric else None
            if self.loop is not None:
                self.spawn_packet_task(
                    self._delayed_delivery(
                        mapping, data, addr, delay_seconds, duplicate_copy=0, source_mapping=source_mapping
                    ), "peer"
                )
                if duplicate:
                    self.spawn_packet_task(
                        self._delayed_delivery(
                            mapping, data, addr, delay_seconds + 0.001, duplicate_copy=1, source_mapping=source_mapping
                        ), "peer"
                    )
            if self.fabric is not None:
                self.fabric.record(
                    "packet_delayed",
                    nat=self.name,
                    delay_ms=round(delay_seconds * 1000),
                    duplicated=duplicate,
                    reorder_delay_injected=reorder_delay_injected,
                    bytes=len(data),
                    **wireguard_transport_trace_fields(data),
                )
                if duplicate:
                    self.fabric.record(
                        "packet_duplicated",
                        nat=self.name,
                        receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                        bytes=len(data),
                        copies=2,
                        **wireguard_transport_trace_fields(data),
                    )
            return
        if self.fabric is not None:
            self.fabric.record(
                "inbound_admitted",
                nat=self.name,
                receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                expected_source=format_address(mapping.destination),
                actual_source=format_address(addr),
                bytes=len(data),
                **wireguard_transport_trace_fields(data),
            )
        self._deliver(mapping, data, addr, duplicate_copy=0)
        if duplicate:
            if self.fabric is not None:
                self.fabric.record(
                    "packet_duplicated",
                    nat=self.name,
                    receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                    bytes=len(data),
                    copies=2,
                    **wireguard_transport_trace_fields(data),
                )
            self._deliver(mapping, data, addr, duplicate_copy=1)

    def _deliver(
        self,
        mapping: Mapping,
        data: bytes,
        source: Address,
        duplicate_copy: int = 0,
    ) -> None:
        if not self.mapping_is_current(mapping):
            self.record("packet_dropped_stale_mapping", packet_kind="peer")
            return
        if self.network_outage:
            self.record("packet_dropped_outage", direction="inbound", bytes=len(data))
            return
        if self.fabric is not None:
            self.fabric.record(
                "simulator_delivery",
                nat=self.name,
                duplicate_copy=duplicate_copy,
                bytes=len(data),
                **wireguard_transport_trace_fields(data),
            )
        peer_mapping = (
            self.fabric.mapping_for_public_endpoint(self, source)
            if self.fabric is not None
            else None
        )
        if peer_mapping is not None:
            # The receiving NAT has already applied its filtering decision.
            # Deliver through the sender's mapping socket so the private client
            # observes the real remote public source instead of this NAT's
            # forwarding port.  This is the other half of the loopback fabric
            # substitute for kernel NAT forwarding.
            peer_nat, sender_mapping = peer_mapping
            peer_nat.deliver_from_public_mapping(sender_mapping, mapping.client, data)
            return
        # This fallback covers a non-simulated external peer that was admitted
        # by the exact mapping-destination rule.  The dual-NAT harness always
        # takes the branch above, where the peer source is preserved exactly.
        if mapping.transport is not None:
            mapping.transport.sendto(data, mapping.client)

    def deliver_from_public_mapping(self, mapping: Mapping, client: Address, data: bytes) -> None:
        if mapping.transport is not None:
            mapping.transport.sendto(data, client)

    async def _delayed_delivery(
        self,
        mapping: Mapping,
        data: bytes,
        source: Address,
        delay: float,
        duplicate_copy: int = 0,
        source_mapping=None,
    ) -> None:
        await asyncio.sleep(delay)
        if source_mapping is not None and not source_mapping[0].mapping_is_current(source_mapping[1]):
            self.record("packet_dropped_stale_mapping", packet_kind="peer_source")
            return
        self._deliver(mapping, data, source, duplicate_copy=duplicate_copy)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--step-a", type=int, default=1)
    parser.add_argument("--step-b", type=int, default=1)
    parser.add_argument("--consume-a", type=int, default=0)
    parser.add_argument("--consume-b", type=int, default=0)
    parser.add_argument("--egress-capture", choices=("listeners", "shim"), default="listeners")
    parser.add_argument("--sweep-noise-every", type=int, default=0)
    parser.add_argument("--sweep-noise-count", type=int, default=0)
    parser.add_argument("--sweep-noise-limit", type=int, default=64)
    parser.add_argument("--loss", type=float, default=0.0)
    parser.add_argument("--reorder", action="store_true")
    parser.add_argument("--strict-filtering", action="store_true")
    parser.add_argument("--strict-filtering-a", action="store_true")
    parser.add_argument("--strict-filtering-b", action="store_true")
    parser.add_argument("--block-direct", action="store_true")
    parser.add_argument(
        "--direct-gate-file",
        help="hold inter-NAT UDP until this file exists (Hard<->Hard harness only)",
    )
    parser.add_argument(
        "--unassigned-egress-listeners",
        type=int,
        default=0,
        help="bind 0..32 allocator look-ahead ports for loopback egress capture",
    )
    parser.add_argument("--mapping-mode-a", choices=("step", "random"), default="step")
    parser.add_argument("--mapping-mode-b", choices=("step", "random"), default="step")
    parser.add_argument("--delay-a-ms", type=int, default=0)
    parser.add_argument("--delay-b-ms", type=int, default=0)
    parser.add_argument("--stun-delay-a-ms", type=int, default=0)
    parser.add_argument("--stun-delay-b-ms", type=int, default=0)
    parser.add_argument("--duplicate-rate", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=20260806)
    parser.add_argument("--observers", type=int, default=4)
    parser.add_argument("--base-a", type=int, default=16000)
    parser.add_argument("--base-b", type=int, default=26000)
    parser.add_argument("--trace-file", type=str)
    parser.add_argument("--background-devices", type=int, default=0)
    parser.add_argument("--background-flows", type=int, default=32)
    parser.add_argument("--background-interval-ms", type=int, default=250)
    parser.add_argument("--background-duration-ms", type=int, default=0)
    parser.add_argument("--network-profile", type=Path)
    args = parser.parse_args()
    try:
        profiles = load_profiles(args.network_profile)
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))
    if args.network_profile and args.egress_capture != "shim":
        parser.error("network profiles require complete shim capture")
    if not 0 <= args.background_devices <= 16 or not 1 <= args.background_flows <= 64 or not 10 <= args.background_interval_ms <= 5000:
        parser.error("background limits: devices 0..16, flows 1..64, interval 10..5000 ms")
    if args.background_devices and args.egress_capture != "shim":
        parser.error("background traffic requires complete shim capture")
    try:
        validate_background_limits(max(1, args.background_devices), args.background_flows,
                                   args.background_interval_ms, args.background_duration_ms)
    except ValueError as error:
        parser.error(str(error))

    async def run() -> None:
        trace = NatTrace(args.trace_file) if args.trace_file else None
        fabric = NatFabric(trace)
        background_tasks = []
        nat_a = Nat(
            "A",
            "127.0.0.1",
            args.step_a,
            args.seed,
            args.base_a,
            args.consume_a,
            args.loss,
            args.reorder,
            args.strict_filtering or args.strict_filtering_a,
            args.block_direct,
            args.mapping_mode_a,
            args.delay_a_ms,
            args.stun_delay_a_ms,
            args.duplicate_rate,
            args.direct_gate_file,
            args.unassigned_egress_listeners,
            args.sweep_noise_every,
            args.sweep_noise_count,
            args.sweep_noise_limit,
            profiles["A"],
        )
        nat_b = Nat(
            "B",
            "127.0.0.1",
            args.step_b,
            args.seed + 1,
            args.base_b,
            args.consume_b,
            args.loss,
            args.reorder,
            args.strict_filtering or args.strict_filtering_b,
            args.block_direct,
            args.mapping_mode_b,
            args.delay_b_ms,
            args.stun_delay_b_ms,
            args.duplicate_rate,
            args.direct_gate_file,
            args.unassigned_egress_listeners,
            args.sweep_noise_every,
            args.sweep_noise_count,
            args.sweep_noise_limit,
            profiles["B"],
        )
        try:
            await nat_a.start(fabric)
            await nat_b.start(fabric)
            observer_a = [await nat_a.add_observer() for _ in range(args.observers)]
            observer_b = [await nat_b.add_observer() for _ in range(args.observers)]
            if args.background_devices:
                async def background_after_join(nat, seed):
                    # Start the other clients when this subscriber first joins;
                    # their independent schedule does not observe measurements
                    # or target candidates. Slow peer startup cannot silently
                    # move all interference outside the tested traffic window.
                    await nat.egress_activity.wait()
                    await run_background(nat, args.background_devices, args.background_flows,
                                         args.background_interval_ms, seed, args.background_duration_ms)
                background_tasks = [asyncio.create_task(background_after_join(nat, args.seed + offset))
                    for offset, nat in enumerate((nat_a, nat_b))]
            if args.egress_capture == "shim":
                gateway_a = await nat_a.add_egress_gateway()
                gateway_b = await nat_b.add_egress_gateway()
                print(f"EGRESS_A_PORT={gateway_a[1]}", flush=True)
                print(f"EGRESS_B_PORT={gateway_b[1]}", flush=True)
            print("STUN_A=" + ",".join(f"{host}:{port}" for host, port in observer_a), flush=True)
            print("STUN_B=" + ",".join(f"{host}:{port}" for host, port in observer_b), flush=True)
            print("BASE_A=%d" % args.base_a, flush=True)
            print("BASE_B=%d" % args.base_b, flush=True)
            # Harness-verifiable banner: relay-only topologies assert the
            # Direct blackhole is actually active before they verify.
            print("BLOCK_DIRECT=%d" % (1 if args.block_direct else 0), flush=True)
            print("DIRECT_GATE=%d" % (1 if args.direct_gate_file else 0), flush=True)
            print(
                "NAT_FEATURES="
                + json.dumps(
                    {
                        "egress_capture": args.egress_capture,
                        "background_devices": args.background_devices,
                        "background_flows": args.background_flows,
                        "background_interval_ms": args.background_interval_ms,
                        "background_duration_ms": args.background_duration_ms,
                        "network_profiles": {name: profile.to_dict() for name, profile in profiles.items()},
                        "consume_a": args.consume_a,
                        "consume_b": args.consume_b,
                        "sweep_noise_every": args.sweep_noise_every,
                        "sweep_noise_count": args.sweep_noise_count,
                        "sweep_noise_limit": args.sweep_noise_limit,
                        "mapping_mode_a": args.mapping_mode_a,
                        "mapping_mode_b": args.mapping_mode_b,
                        "strict_filtering_a": args.strict_filtering or args.strict_filtering_a,
                        "strict_filtering_b": args.strict_filtering or args.strict_filtering_b,
                        "delay_a_ms": args.delay_a_ms,
                        "delay_b_ms": args.delay_b_ms,
                        "stun_delay_a_ms": args.stun_delay_a_ms,
                        "stun_delay_b_ms": args.stun_delay_b_ms,
                        "duplicate_rate": args.duplicate_rate,
                        "direct_gate": bool(args.direct_gate_file),
                        "direct_gate_preserves_source_allocations": args.egress_capture == "shim",
                        "unassigned_egress_listeners": args.unassigned_egress_listeners,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
            # The harness uses SIGTERM after draining the real daemons. Let
            # in-flight background flows record cancellation and close their
            # sockets before the trace is finalized.
            stopped = asyncio.Event()
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGTERM, stopped.set)
            try:
                await stopped.wait()
            finally:
                loop.remove_signal_handler(signal.SIGTERM)
        finally:
            for task in background_tasks:
                task.cancel()
            await asyncio.gather(*background_tasks, return_exceptions=True)
            await nat_a.close()
            await nat_b.close()
            if trace is not None:
                trace.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
