# Direct DPLPMTUD business budget

## Scope and audited data path

Phase 2B makes normal Direct business traffic consume the confirmed budget
published by the Phase 2A DPLPMTUD state machine. The audited production path
is:

```text
TUN read
  -> DataPlane peer route
  -> network-outbound per-peer plaintext FIFO
  -> committed Direct path + immutable budget token
  -> WireGuard encryption
  -> exact path/revision/owner revalidation
  -> exact Direct UDP socket and endpoint
  -> UDP try_send_to
```

`DataPlane` routes a complete IP packet from the TUN into an `OutboundPacket`.
`network_outbound` is the sole business encryption owner. `UdpTransport` owns
the exact socket lease, endpoint, publication owner, and DPLPMTUD runtime used
at the final handoff.

The length governed by `overlay_payload_budget` is the **complete inner IP
packet**, including its IPv4 or IPv6 header. It is not an application payload,
TCP payload, or UDP payload length.

## Three size layers

The three relevant sizes are distinct:

1. **Plaintext / inner IP packet**: the complete packet read from the TUN.
2. **WireGuard ciphertext**: the real encrypted transport-data message,
   including the WireGuard header, padding, and authentication tag.
3. **UDP datagram**: the bytes handed to the Direct UDP socket. In the current
   transport this payload is exactly the WireGuard ciphertext; outer UDP and
   IP headers are accounted separately by DPLPMTUD.

For the BASE publication, confirmed UDP datagram size 1200 produces an overlay
payload budget of 1168. A complete 1168-byte inner packet is admissible and its
actual WireGuard datagram must be at most 1200 bytes. The pre-encryption overlay
check is only the first fence: the implementation always checks
`wire_bytes.len()` against the confirmed UDP datagram size after encryption.
The real ciphertext check is authoritative and protects against padding or a
future codec-overhead change.

## Publication model and ownership

Each concrete `UdpTransport` owns a `DplpmtudRuntime` and an immutable,
read-optimized publication mirror. A business-visible value carries the full
identity instead of relying on a peer-ID map key:

```rust
DirectBusinessBudgetPublication {
    path_identity,
    budget_revision,
    udp_datagram_size,
    overlay_payload_budget,
}

DirectBusinessBudgetUpdate {
    path_identity,
    budget_revision,
    budget: Option<DirectBusinessBudgetPublication>,
}
```

The mirror is a Tokio `watch` value containing an `Arc<HashMap<...>>`. Readers
clone one immutable entry and do not acquire the DPLPMTUD registry mutex.
Every business-visible revision change republishes the entry. Revocation and
downward recovery publish `budget: None`; they are not represented only by a
silent deletion. Tombstones make `Some -> None` observable. The mirror is
strictly bounded to 256 peer entries; at capacity an old `None` tombstone is
reclaimed before a new live entry is admitted.

`path_identity` includes the network generation, peer-session generation,
remote-candidate epoch, Direct validation owner/request, authenticated remote
endpoint, local endpoint, outer IP family, UDP transport instance, and socket
index. `udp_publication_owner` belongs to one publication of one
`UdpTransport`. Withdrawing that owner closes its DPLPMTUD runtime and publishes
`None` before the retired transport can be reused. The session-scoped
capability mirror survives transport replacement, so a negotiated peer fails
closed as managed pending while the replacement socket re-confirms BASE; it
cannot temporarily fall through the legacy path.

The diagnostic APIs `confirmed_budget_for_path()` and `snapshots()` remain
control-plane tools. Normal business packet processing does not call either
API and never takes the DPLPMTUD registry mutex per packet.

## Packet token lifecycle

When the Path State Machine has committed Direct, the sender captures this
immutable token before WireGuard encryption:

```rust
DirectBusinessSendToken {
    path_identity,
    budget_revision,
    max_udp_datagram_size,
    max_overlay_payload_size,
    udp_publication_owner,
}
```

Token capture also leases the exact socket and records its endpoint and socket
index. The sender then:

1. validates that the plaintext is one complete IP packet;
2. rejects it if the complete inner length exceeds the overlay budget;
3. encrypts while preserving per-peer WireGuard counter order;
4. rejects it if the actual ciphertext exceeds the UDP datagram budget;
5. re-reads the committed path under the network epoch fence;
6. revalidates the exact path identity, budget revision, `Some` publication,
   publication owner, transport instance, local socket, and endpoint;
7. calls nonblocking `try_send_to` on the captured socket and endpoint.

The sender never resolves a replacement endpoint after encryption and never
applies a newer budget to an older token. A stale token returns the original
plaintext to routing at most once, with a fresh WireGuard counter. A second
stale result is a typed terminal drop, preventing an ABA retry loop.

## Pending policy

A peer that negotiated DPLPMTUD is `ManagedPending` while BASE is unconfirmed,
downward recovery is re-confirming BASE, a budget is revoked, or its exact
identity/UDP publication has just changed. Its packet remains plaintext in the
existing per-peer outbound actor:

- FIFO order;
- at most 256 packets per peer;
- at most 2 MiB stored bytes per peer;
- a 3-second delivery TTL (below the 5-second ceiling);
- at most 64 packets from one peer per flush pass;
- no unbounded per-packet tasks.

Budget and committed-path `watch` notifications wake the actor. Each packet is
revalidated independently as it flushes. Per-peer flush tasks prevent one
pending peer from blocking another peer. Queue overflow drops the oldest entry
and records a typed `outbound_queue_full` loss. TTL expiry records
`outbound_delivery_deadline_expired`. Peer removal, generation replacement,
Relay activation, and worker shutdown clear or reroute the queue immediately;
shutdown and PeerLeft do not leave a queue or worker owner behind.

## Oversize and local feedback

An inner packet above the overlay budget is rejected before encryption. An
actual ciphertext above the UDP budget is rejected before socket handoff. A
managed Direct `EMSGSIZE`/`WSAEMSGSIZE` from the synchronous UDP handoff is a
typed, definite non-send. These paths publish feedback through the local TUN
injection lane:

- IPv4: ICMP Destination Unreachable, Fragmentation Needed (type 3/code 4),
  with the supported complete-inner-packet MTU and the original IPv4 header
  plus the first eight payload bytes;
- IPv6: ICMPv6 Packet Too Big (type 2/code 0), with the supported complete
  inner MTU and as much of the original packet as fits within 1280 bytes;
- queue overflow/expiry: protocol-correct host-unreachable feedback where an
  IP source can be identified.

Both outer and ICMP checksums are generated as required. Malformed/non-IP
input, fragmented IPv4 input, invalid source/destination addresses, and ICMP
error responses are suppressed fail-closed. IPv6 extension-header traversal
is deliberately not implemented: packets beginning with an extension header
are suppressed rather than risking recursive feedback. Feedback is bounded to
8 packets per peer per second, tracks at most 256 peers, and uses a bounded
256-entry broadcast channel. A daemon-generated ICMP error is injected toward
the local host and is never sent back through the business outbound path.

For an exact managed token, synchronous `EMSGSIZE` applies one idempotent
`BusinessPacketTooLarge` reducer event to that exact identity and revision. It
publishes `None`, advances the revision, withholds the business budget, wakes
the DPLPMTUD worker, and returns to BASE confirmation. It does not increment
Direct health failure state and does not request Relay fallback. Repeating the
same stale identity/revision is a no-op. Legacy/unmanaged Direct sends retain
their historical send policy, but kernel `EMSGSIZE` is still surfaced as a
typed local MTU error rather than a generic network failure.

## Lock order and linearization

Normal managed Direct business sends use this upper-to-lower order:

```text
per-peer WireGuard emit guard
  -> PeerManager network epoch gate
  -> DPLPMTUD business-publication gate
  -> synchronous nonblocking UDP try_send_to
```

Token preparation and encryption occur while the emit guard preserves counter
order. Final path selection takes a fresh network epoch guard. The
business-publication gate is independent of the DPLPMTUD registry and is held
only across token/owner validation and the nonblocking socket syscall.
DPLPMTUD reducer mutations take the registry mutex and then briefly publish
under the publication gate; they never wait for the network epoch gate.
`EMSGSIZE` reducer invalidation happens after the socket operation releases the
publication gate.

The business-send linearization point is the `try_send_to` operation inside
both the network epoch fence and publication gate. If path replacement or
budget revocation wins first, revalidation rejects the token and the UDP wire
sees no packet. If the send wins first, the kernel handoff is ordered before
the later replacement/revocation. This gives an explicit answer at the only
boundary that matters; checking a revision only before encryption would not.

## Legacy and Relay isolation

A peer without negotiated DPLPMTUD capability, or an exact platform/socket
profile that cannot support no-fragment probing, is unmanaged. It keeps the
pre-Phase-2B Direct behavior and is never assigned another peer's dynamic
budget. The implementation does not pretend that such a peer has a confirmed
budget.

Relay selection and Relay sends never read the Direct publication mirror,
never wait for a Direct budget, and never apply a Direct overlay limit. A
missing or revoked Direct budget therefore cannot block an already committed
Relay path. Oversize handling does not privately change the Path State Machine
or route one large packet around Direct.

## Non-goals

This phase does not implement overlay fragmentation, overlay reassembly,
dynamic global TUN MTU changes, a new Direct/Relay selection policy, or UI.
It does not traverse IPv6 extension-header chains for recursive-error
classification. DPLPMTUD continues to describe one exact Direct UDP path; it
is not a shared or cross-peer MTU cache.
