#!/usr/bin/env python3
"""Deterministic dual-NAT simulator for the p2wlan dual-end harness.

The simulator uses two address/port-dependent NATs on loopback.  Each mapping
owns one public UDP socket, so packets delivered to a daemon are sourced from
the mapping port that a remote peer would actually observe.

``asyncio`` cannot transparently interpose on another process's UDP sends on
macOS.  ``NatFabric`` is the deliberate loopback substitute for that missing
kernel hook: when a public forwarder receives a datagram directly from a
registered private daemon socket, it does *not* deliver that packet.  Instead
it asks the sender's NAT to allocate/reuse the (private source, public
destination) mapping and re-emits the datagram from that mapping's public
socket.  The receiving forwarder then handles the translated packet normally.
Consequently the receiver observes the sender NAT's public endpoint, rather
than its own public endpoint or the sender's private socket.

The Hard<->Hard experiment may additionally pre-bind a bounded window of the
allocator's next public ports.  Those sockets are *egress listeners*, not NAT
mappings: they can observe a registered private daemon's first packet so the
sender NAT can translate it, but they never admit public inbound traffic until
the corresponding port is consumed by a real mapping.  This models the kernel
interposition that loopback lacks without inventing a peer-visible mapping.

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
import random
import struct
import time
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
            "monotonic_ns": time.monotonic_ns(),
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
    bind_task: Optional[asyncio.Task] = None
    send_task: Optional[asyncio.Task] = None
    pending: Deque[Tuple[bytes, Address]] = dataclasses.field(default_factory=collections.deque)


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


class NatFabric:
    """Coordinates source translation between the two loopback NATs."""

    def __init__(self, trace: Optional[NatTrace] = None) -> None:
        self.nats: List["Nat"] = []
        self.trace = trace

    def record(self, event: str, **fields: object) -> None:
        if self.trace is not None:
            self.trace.record(event, **fields)

    def add_nat(self, nat: "Nat") -> None:
        if nat not in self.nats:
            self.nats.append(nat)

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

    async def start(self, fabric: Optional[NatFabric] = None) -> "Nat":
        self.loop = asyncio.get_running_loop()
        self.fabric = fabric
        if fabric is not None:
            fabric.add_nat(self)
        await self._ensure_egress_listeners()
        return self

    async def close(self) -> None:
        tasks = []
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
        for transport, _ in self.observers:
            transport.close()
        for transport in self.forwarders.values():
            transport.close()
        for transport in self.provisional_forwarders.values():
            transport.close()
        self.observers.clear()
        self.forwarders.clear()
        self.provisional_forwarders.clear()

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
            if port not in self.mapping_by_port:
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
        reserved: Set[int] = set(self.mapping_by_port)
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
            return mapping
        mapping = Mapping(client=client, destination=destination, port=self._allocate_unused_port())
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

    async def ensure_bound(self, mapping: Mapping) -> None:
        if mapping.transport is not None:
            return
        provisional = self.provisional_forwarders.pop(mapping.port, None)
        if provisional is not None:
            mapping.transport = provisional
            self.forwarders[mapping.port] = provisional
            return
        if mapping.bind_task is None:
            if self.loop is None:
                raise RuntimeError("start the NAT before allocating mappings")
            mapping.bind_task = self.loop.create_task(self._bind_mapping(mapping))
        await asyncio.shield(mapping.bind_task)

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
        if self.consume_before_punch > 0:
            for _ in range(self.consume_before_punch):
                self._allocate_unused_port()
            self.consume_before_punch = 0
        mapping = self.mapping_for(client, observer)
        if self.loop is None:
            return
        self.loop.create_task(
            self._reply_to_stun_after_bind(observer_transport, client, transaction, mapping)
        )

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
        response = binding_response(transaction, self.public_ip, mapping.port)
        if self.stun_delay_ms > 0:
            await asyncio.sleep(self.stun_delay_ms / 1000.0)
        observer_transport.sendto(response, client)

    def translate_outbound(self, client: Address, destination: Address, data: bytes) -> None:
        """Source-NAT a daemon datagram then send it to the public destination."""
        mapping = self.mapping_for(client, destination)
        mapping.pending.append((data, destination))
        if mapping.send_task is None or mapping.send_task.done():
            if self.loop is None:
                return
            mapping.send_task = self.loop.create_task(self._flush_outbound(mapping))

    async def _flush_outbound(self, mapping: Mapping) -> None:
        try:
            await self.ensure_bound(mapping)
            while mapping.pending:
                data, destination = mapping.pending.popleft()
                if mapping.transport is not None:
                    mapping.transport.sendto(data, destination)
        except OSError:
            # A non-recoverable bind error must not leave an unobserved task
            # exception or replay stale packets on a later mapping attempt.
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
        if self.loss_rate > 0 and self.rng.random() < self.loss_rate:
            if self.fabric is not None:
                self.fabric.record(
                    "packet_dropped_loss",
                    nat=self.name,
                    receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                    bytes=len(data),
                    **wireguard_transport_trace_fields(data),
                )
            return
        delay_seconds = self.delivery_delay_ms / 1000.0
        reorder_delay_injected = self.reorder and self.rng.random() < 0.25
        if reorder_delay_injected:
            delay_seconds += 0.02
        duplicate = self.duplicate_rate > 0 and self.rng.random() < self.duplicate_rate
        if delay_seconds > 0:
            if self.loop is not None:
                self.loop.create_task(
                    self._delayed_delivery(
                        mapping, data, addr, delay_seconds, duplicate_copy=0
                    )
                )
                if duplicate:
                    self.loop.create_task(
                        self._delayed_delivery(
                            mapping, data, addr, delay_seconds + 0.001, duplicate_copy=1
                        )
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
    ) -> None:
        await asyncio.sleep(delay)
        self._deliver(mapping, data, source, duplicate_copy=duplicate_copy)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--step-a", type=int, default=1)
    parser.add_argument("--step-b", type=int, default=1)
    parser.add_argument("--consume-a", type=int, default=0)
    parser.add_argument("--consume-b", type=int, default=0)
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
    args = parser.parse_args()

    async def run() -> None:
        trace = NatTrace(args.trace_file) if args.trace_file else None
        fabric = NatFabric(trace)
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
        )
        try:
            await nat_a.start(fabric)
            await nat_b.start(fabric)
            observer_a = [await nat_a.add_observer() for _ in range(args.observers)]
            observer_b = [await nat_b.add_observer() for _ in range(args.observers)]
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
                        "unassigned_egress_listeners": args.unassigned_egress_listeners,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
            await asyncio.Event().wait()
        finally:
            await nat_a.close()
            await nat_b.close()
            if trace is not None:
                trace.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
