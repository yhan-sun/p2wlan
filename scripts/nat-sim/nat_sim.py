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
    ) -> None:
        if step == 0:
            raise ValueError("--step must not be zero for address/port-dependent mappings")
        self.name = name
        self.public_ip = public_ip
        self.step = step
        self.rng = random.Random(seed)
        self.next_port = base_port
        self.consume_before_punch = consume_before_punch
        self.loss_rate = loss_rate
        self.reorder = reorder
        # Endpoint-dependent filtering: only the exact destination a client's
        # mapping was created toward may send in; a peer's other public socket
        # is not automatically admitted.
        self.strict_filtering = strict_filtering
        # Deterministic bidirectional UDP data-plane blackhole: every inter-NAT
        # datagram is dropped while STUN observers keep working, so Direct can
        # never establish but the relay data plane still carries traffic.  This
        # models the field CGNAT bidirectional UDP blackhole.
        self.block_direct = block_direct
        self.mappings: Dict[Tuple[Address, Address], Mapping] = {}
        self.mapping_by_port: Dict[int, Mapping] = {}
        self.forwarders: Dict[int, asyncio.DatagramTransport] = {}
        self.client_sockets: Set[Address] = set()
        self.observers: List[Tuple[asyncio.DatagramTransport, Address]] = []
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.fabric: Optional[NatFabric] = None
        self.observed_sequence: List[int] = []

    async def start(self, fabric: Optional[NatFabric] = None) -> "Nat":
        self.loop = asyncio.get_running_loop()
        self.fabric = fabric
        if fabric is not None:
            fabric.add_nat(self)
        return self

    async def close(self) -> None:
        tasks = []
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
        self.observers.clear()
        self.forwarders.clear()

    def alloc_port(self) -> int:
        port = self.next_port
        self.observed_sequence.append(port)
        self.next_port = (self.next_port + self.step) % 65536
        if self.next_port < 1024:
            self.next_port += 1024
        return port

    def _allocate_unused_port(self) -> int:
        # A mapping needs an exclusive socket.  The configured sequence is
        # preserved unless it cycles onto a live mapping or an occupied port.
        for _ in range(64512):
            port = self.alloc_port()
            if port not in self.mapping_by_port:
                return port
        raise RuntimeError(f"NAT {self.name} exhausted public UDP ports")

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
        observer_transport.sendto(binding_response(transaction, self.public_ip, mapping.port), client)

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
        if mapping is None:
            return
        source_nat = self.fabric.owner_for_private_client(addr) if self.fabric is not None else None
        if source_nat is not None:
            if source_nat is not self:
                if self.block_direct or source_nat.block_direct:
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
                        )
                    return
                # This is a daemon's direct loopback send.  Re-inject it from
                # the sender NAT's mapping socket so the receiver sees the
                # sender's public endpoint, exactly once.
                source_nat.translate_outbound(addr, (self.public_ip, port), data)
            # Hairpinning is intentionally unsupported by this harness.
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
            return
        if self.reorder and self.rng.random() < 0.25:
            if self.loop is not None:
                self.loop.create_task(self._delayed_delivery(mapping, data, addr, 0.02))
            return
        if self.fabric is not None:
            self.fabric.record(
                "inbound_admitted",
                nat=self.name,
                receiver_endpoint=f"{self.public_ip}:{mapping.port}",
                expected_source=format_address(mapping.destination),
                actual_source=format_address(addr),
            )
        self._deliver(mapping, data, addr)

    def _deliver(self, mapping: Mapping, data: bytes, source: Address) -> None:
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

    async def _delayed_delivery(self, mapping: Mapping, data: bytes, source: Address, delay: float) -> None:
        await asyncio.sleep(delay)
        self._deliver(mapping, data, source)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--step-a", type=int, default=1)
    parser.add_argument("--step-b", type=int, default=1)
    parser.add_argument("--consume-a", type=int, default=0)
    parser.add_argument("--consume-b", type=int, default=0)
    parser.add_argument("--loss", type=float, default=0.0)
    parser.add_argument("--reorder", action="store_true")
    parser.add_argument("--strict-filtering", action="store_true")
    parser.add_argument("--block-direct", action="store_true")
    parser.add_argument("--seed", type=int, default=20260806)
    parser.add_argument("--observers", type=int, default=4)
    parser.add_argument("--base-a", type=int, default=36000)
    parser.add_argument("--base-b", type=int, default=46000)
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
            args.strict_filtering,
            args.block_direct,
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
            args.strict_filtering,
            args.block_direct,
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
            await asyncio.Event().wait()
        finally:
            await nat_a.close()
            await nat_b.close()
            if trace is not None:
                trace.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
