# Direct UDP DPLPMTUD runtime foundation

## 1. Scope and baseline

This document records the Phase 2A implementation on top of
`a7f2e71281fb40917dc89249377df384878f0fe7`. The phase adds a bounded,
authenticated Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
control loop for an already committed Direct UDP path.

The Path State Machine remains the only authority for whether Direct or Relay
is active. DPLPMTUD consumes the committed Direct-path snapshot; it does not
select, promote, demote, fail, or recover a network path.

This phase deliberately does **not**:

- discover an MTU for Relay;
- change TUN or per-route MTU;
- fragment or reassemble overlay traffic;
- generate ICMP Fragmentation Needed or Packet Too Big messages;
- size, split, reject, or reroute ordinary business packets using the result;
- turn a probe timeout into Direct-health failure or Relay fallback;
- add UI, release, version, or signing changes.

The only output intended for the next phase is the read-only confirmed UDP
size and derived overlay payload budget attached to the exact current Direct
path identity.

## 2. Audited current data path

### 2.1 Outbound Direct UDP

Ordinary data is routed to the peer, encrypted by `WireGuardTransport`, and
emitted by `UdpTransport` on a concrete UDP socket. DPLPMTUD uses the same
cryptographic and UDP transport components, but its plaintext is an internal
ICMP-shaped control packet consumed by the daemon rather than the TUN.

The DPLPMTUD worker is owned by the Direct UDP scheduler in
`lib/daemon/udp_direct.rs`. For each candidate probe it:

1. snapshots the exact committed Direct identity;
2. atomically registers one outstanding probe in `DplpmtudRuntime`;
3. builds an inner authenticated probe of the requested size;
4. releases DPLPMTUD state locks;
5. takes the existing per-peer WireGuard emit-order lock through encryption and
   the UDP handoff;
6. revalidates the path identity and worker owner, then marks `ProbeSent` at
   the send linearization point immediately before the actual socket send;
7. commits `ProbeSendFailed` only if the same expectation still owns the slot
   when the handoff reports an error;
8. waits on the worker notification, cancellation watch, probe deadline, raise
   timer, or the worker hard deadline.

### 2.2 Inbound Direct UDP

A UDP reader records the real source address, local endpoint, socket index,
UDP publication owner, and network generation in `ReceivedEncryptedPacket`.
`WireGuardTransport::run_inbound_with_udp_source` authenticates and decrypts
the datagram before parsing DPLPMTUD.

A Probe is answered only after successful WireGuard decryption and only when:

- the UDP publication still owns the datagram;
- the packet was authenticated by the current WireGuard session;
- source/local endpoint and socket index are present;
- outer IP family matches the token;
- the per-peer response rate limit admits it.

The ACK is encrypted and sent on the exact receiving Direct socket. It mirrors
the probe token and is compact, so it is never larger than the probe.

An ACK is committed only after decryption, session-current validation,
per-peer adoption serialization, the network-epoch gate, current committed
Direct-path validation, exact ingress validation, and atomic consumption of
the outstanding expectation.

### 2.3 Existing size layers and overhead

The implementation uses three strong types and never calls all three values
"MTU":

- `OuterIpPacketSize`: complete outer IP packet;
- `UdpDatagramSize`: bytes passed to `UdpSocket::send_to`;
- `OverlayPayloadBudget`: authenticated WireGuard plaintext capacity.

For this transport:

```text
outer_ip_packet_size = udp_datagram_size + outer_ip_udp_overhead
outer IPv4 + UDP overhead = 20 + 8 = 28 bytes
outer IPv6 + UDP overhead = 40 + 8 = 48 bytes

overlay_payload_budget = udp_datagram_size - wireguard_datagram_overhead
wireguard_datagram_overhead = 16-byte transport header + 16-byte AEAD tag
                            = 32 bytes
```

The conservative UDP datagram base is 1200 bytes. The current internal hard
ceilings preserve an Ethernet-sized 1500-byte outer packet:

- IPv4 UDP datagram ceiling: 1472 bytes;
- IPv6 UDP datagram ceiling: 1452 bytes.

The code does not infer outer-family overhead from a virtual/inner IPv4 packet.
It binds the DPLPMTUD identity and wire token to the real Direct endpoint's
outer IP family.

## 3. Capability compatibility

The existing Direct-validation request/ACK format ends with a fixed token that
legacy parsers locate from the end of the payload. Phase 2A inserts an additive
six-byte extension immediately before that tail:

```text
"DPM1" | capability_version=1 | dplpmtud_version=1
```

New peers recognize the exact extension and record support against the current
peer-session generation. A legacy peer still finds the unchanged Direct-
validation tail, ignores the intervening bytes, and continues normal Direct or
Relay communication. Missing, legacy, or malformed capability bytes are
fail-closed and produce `Unsupported`; no DPLPMTUD probe is sent.

Support is bounded by the same per-runtime peer limit and is invalidated when
the peer-session generation changes.

## 4. Exact path identity

`DplpmtudPathIdentity` identifies one concrete, already-authenticated Direct
UDP path. It contains:

```text
peer_id
PathEpoch {
  network_generation,
  peer_session_generation,
  remote_candidate_epoch
}
direct_validation_owner_token
direct_validation_request_id
authenticated_remote_endpoint
local_endpoint
DplpmtudSocketIdentity {
  transport_instance_id,
  socket_index
}
outer_ip_family
```

The identity is constructed from the committed `DirectValidationIdentity`, the
committed candidate pair, and the current UDP publication/socket. Mixed local
and remote address families are rejected.

Any change to any field creates a different path. Reconciliation cancels the
old worker and installs a fresh Base/Unsupported state. An arriving ACK is
never reinterpreted using a newly read generation or endpoint; it must match
the expectation and the current exact path that originally issued it.

## 5. Probe and ACK wire format

DPLPMTUD control packets are daemon-internal ICMP echo-request-shaped inner
IPv4 packets. They are encrypted as ordinary WireGuard transport data and are
consumed before TUN delivery.

Prefixes:

```text
Probe: p2wlan-dplpmtud-probe-v1
ACK:   p2wlan-dplpmtud-ack-v1
```

The fixed big-endian token is 79 bytes:

```text
sequence                         u64
nonce                            [u8; 16]
path_cookie                      [u8; 16]
network_generation               u64
peer_session_generation          u64
remote_candidate_epoch           u64
direct_validation_owner_token    u64
direct_validation_request_id     u16
candidate_udp_datagram_size      u32
outer_ip_family                  u8  (4 or 6)
```

The protocol/version is carried by the versioned prefix. Sequence, nonce, path
cookie, complete path epoch, Direct-validation owner/request, candidate size,
and outer family prevent two probes or two path incarnations from being
confused.

For a Probe, padding is placed between the prefix and token. The builder solves
for the exact plaintext size so that after WireGuard's 32-byte overhead the
actual `send_to` datagram length is exactly `candidate_udp_datagram_size`.
The parser locates the fixed token at the end and accepts the variable padding
only after a complete authenticated packet was received.

The ACK contains the ACK prefix and the exact mirrored token without probe
padding. It therefore cannot amplify the request.

## 6. State machine

Each exact Direct path owns an independent pure reducer with these states:

```text
Disabled
Unsupported
Base
Searching
SearchComplete
Error
```

State summary:

```text
Direct committed + unsupported capability -> Unsupported
Direct committed + supported capability   -> Base
Base + StartSearch                         -> Searching
Searching + matching ACK                  -> Searching or SearchComplete
Searching + exhausted timeout             -> narrower Searching or SearchComplete
SearchComplete + raise timer               -> Searching or renewed SearchComplete
send failure                               -> Error
Error + retry timer                        -> Searching or SearchComplete
identity/lifecycle cancellation            -> Disabled
new identity                               -> new Base or Unsupported machine
```

The machine records the exact identity, conservative base, confirmed lower
bound, search upper bound, pending candidate, at most one outstanding probe,
sequence/nonce/path cookie, deadline, retry, fixed granularity, raise deadline,
last success/timeout/failure, reset reason/count, revision, and diagnostic
counters.

Reducer state changes and network side effects are separate. `reduce` produces
a transition; `commit` applies only accepted state changes. Duplicate ACKs are
a special diagnostic decision: they increment only the duplicate counter and
do not change revision, timestamps, bounds, or success count. Stale ACKs
increment only the stale counter and do not move the search interval.

## 7. Bounded search

The implementation uses a deterministic aligned binary search because the
current phase has a conservative base and fixed internal ceiling, and because
the required result is a bounded safe datagram size rather than continuous
congestion adaptation.

For confirmed lower bound `L`, upper bound `U`, and granularity `G=8`:

1. choose an aligned midpoint strictly greater than `L` and no greater than
   `U`;
2. send one exact-size encrypted probe;
3. on a matching ACK, set `L=max(L,candidate)`;
4. on timeout, retry the same candidate at most two times;
5. after retries are exhausted, set
   `U=min(U,max(L,candidate-G))`;
6. continue until no candidate greater than `L` remains.

The final interval step is not skipped: when `U` is only one granularity step
above `L`, `U` itself is probed. This makes the final confirmed value no more
than one configured granularity below a deterministic blackhole threshold.

A successful ACK is accepted only when all of the following hold:

- the runtime entry and worker owner are current;
- the exact path identity matches;
- sequence, nonce, path cookie, candidate size, and all epoch/validation fields
  match the outstanding probe;
- remote endpoint, local endpoint, socket identity, and outer family match;
- the probe was actually sent;
- the ACK arrives no later than the probe deadline;
- the receipt has not already been consumed.

A timeout narrows only this search interval. The DPLPMTUD API has no operation
that records Direct failure, degrades Direct, selects Relay, or ends an already
confirmed Direct path.

After SearchComplete, a ten-minute raise timer reopens the upper interval to
the family ceiling. A send failure enters Error with a five-second retry timer.
Every worker also has a one-hour intrinsic hard lifetime.

## 8. Timer and task ownership

A bounded scheduler owns DPLPMTUD workers in a `JoinSet`. Reconciliation is
triggered by committed-path notifications and worker completion; each worker
owns its bounded probe, raise, and hard-lifetime deadlines. The scheduler does
not put a long-lived timer into a serial control branch that must poll other
work to make progress.

For each exact peer/path there is at most one owner token and one worker. The
worker owns:

- one cancellation `watch` receiver;
- one `Notify` used for ACK/state wakeups;
- the current probe deadline or raise deadline;
- a hard lifetime deadline.

Worker ingress is bounded to 256 entries. Runtime peer entries, negotiated
support entries, and response-rate buckets are also bounded to 256 peers.
Each state machine keeps at most one outstanding probe and at most 32 consumed
receipt identities. ACK responses are rate-limited to 8 per peer per second.

Owner tokens prevent an old worker's exit from clearing a replacement worker
installed for the same peer and identity. A wrapping/exhausted owner allocator
fails closed rather than sharing ownership.

## 9. Lock order and network I/O

No DPLPMTUD registry lock is held over a timer wait, WireGuard operation, or
socket send.

Actual send-side order:

```text
short DPLPMTUD registry transaction: schedule expectation
release registry
WireGuard per-peer emit lock
short session lock / encrypt
exact-path + owner + expectation recheck and `ProbeSent` linearization
(`begin_probe_send`)
UDP handoff on the bound socket
release emit lock
short DPLPMTUD registry transaction: finish send outcome
```

The `begin_probe_send` recheck includes the worker owner, exact identity,
outstanding identity, no concurrent send, and a live deadline. Cancellation or
path replacement before that linearization point prevents the send.

Actual ACK commit order after decryption:

```text
current WireGuard session evidence/emit guard (retained by inbound caller)
per-peer UDP adoption lock
network epoch gate
current peer lifecycle and exact committed Direct path checks
non-awaiting DPLPMTUD registry try-lock and expectation consumption
release network epoch gate
release adoption lock
emit diagnostics outside the state transaction
```

The nonblocking runtime `try_lock` fails closed as `Busy`; it does not wait for
an upper-layer lock while holding the network epoch. No network I/O occurs in
this transaction. The implementation does not hold the network epoch,
PeerConnection writer, handshake arbiter, or candidate-map guard across UDP
send or timer wait.

## 10. Lifecycle and cancellation

DPLPMTUD is reconciled exclusively from the authoritative committed-path
mirror. It starts only for `Online + ActiveBusinessPath::Direct` with a complete
current `PathEpoch`, authenticated Direct-validation identity, candidate pair,
local endpoint, live UDP publication, and matching socket.

The current entry is cancelled/reset for, among other reasons:

- active path is not Direct (including Relay active);
- peer leaves or becomes non-online;
- identity reset or Direct path failure;
- network generation advances;
- peer-session generation changes;
- remote candidate epoch advances;
- Direct validation owner/request/endpoint changes;
- local endpoint, socket index, or UDP transport instance changes;
- Direct pair disappears or becomes stale;
- UDP publication replacement or shutdown;
- daemon shutdown.

A repeated notification for the same exact identity is idempotent: it does not
reset state, create a second worker, or schedule a second outstanding probe.

Cancellation sets the watch, disables the machine, clears outstanding work,
and preserves a reason in the read-only snapshot. A stale worker may still
reach its exit path, but owner-token comparison prevents it from erasing the
replacement. A cancelled worker cannot pass `begin_probe_send` and cannot
publish an old retry kick.

## 11. Stale and duplicate handling

The following are rejected without changing search bounds:

- old network generation;
- old peer-session generation;
- old remote candidate epoch;
- old Direct-validation owner or request ID;
- wrong sequence, nonce, path cookie, or candidate size;
- wrong remote endpoint;
- wrong local endpoint, socket index, or UDP publication identity;
- wrong outer IP family;
- ACK authenticated by a replaced/previous session for current-path evidence;
- ACK after the deadline;
- ACK with no current expectation;
- ACK arriving while the exact state transaction cannot be acquired.

A consumed exact receipt is classified as duplicate. Receipt storage is a
bounded FIFO, and duplicate handling changes only `duplicate_ack_count`.
Malformed, legacy, or unrelated control packets are ignored by the DPLPMTUD
parser and continue through the existing handling rules.

## 12. Diagnostics and status

Stable timeline events include:

- `dplpmtud_started`
- `dplpmtud_unsupported`
- `dplpmtud_probe_scheduled`
- `dplpmtud_probe_sent`
- `dplpmtud_probe_acked`
- `dplpmtud_probe_timeout`
- `dplpmtud_search_bounds_updated`
- `dplpmtud_search_complete`
- `dplpmtud_raise_timer_started`
- `dplpmtud_reset`
- `dplpmtud_cancelled`
- `dplpmtud_stale_ack_rejected`
- `dplpmtud_duplicate_ack`
- `dplpmtud_probe_send_failed`

Events carry the available peer, path epoch, endpoints, socket publication,
sequence, candidate datagram size, bounds, and reason/decision details.

Peer diagnostics and status expose a read-only `DplpmtudSnapshot` containing:
state, capability support, path identity summary, base/confirmed/upper UDP
sizes, derived outer packet size and overlay budget, outstanding probe,
relative success/timeout/failure ages, reset reason/count, revision, probe and
result counters, stale/duplicate counters, and whether the owner worker is
live.

Snapshots are copied into a separate read-optimized map after state commits.
Status reads do not take or hold the mutable DPLPMTUD registry lock and cannot
block a worker.

## 13. Verification strategy

Reducer and runtime tests cover unsupported peers, Base-to-Searching,
successful lower-bound growth, timeout/retry and upper-bound reduction,
convergence, raise timer, exact duplicate invariants, every stale identity
dimension, deadline rejection, owner-token ABA, path replacement, bounded
containers/rate limiting, PeerLeft/shutdown cleanup, additive capability
compatibility, exact datagram padding, and IPv4/IPv6 separation.

The deterministic Linux blackhole test runs the real chain:

```text
scheduler/runtime plan
-> probe codec and exact padding
-> WireGuard encryption/authentication
-> loopback UDP send
-> threshold blackhole sink or peer UDP receive
-> WireGuard decrypt/authenticate
-> ACK codec and encryption
-> ACK UDP receive and decrypt
-> exact state commit
```

Datagrams at or below 1397 bytes are delivered; larger datagrams are silently
sent to a sink and timed out. The test observes actual encrypted UDP lengths,
requires a success below and failure above the threshold, bounds the result to
one 8-byte step, verifies duplicate no-op behavior, switches generation while
an authenticated ACK is in flight, performs PeerLeft with an outstanding probe
before send linearization, asserts Direct remains active with zero Direct
health failures and zero Relay fallbacks, and returns worker ownership to the
baseline without sleeps.

The required workflow repeats that same blackhole test five times on the exact
PR Head SHA and prints threshold, confirmed/upper bounds, probe/timeout counts,
Direct/fallback sentinels, stale/duplicate counts, generation/PeerLeft results,
and task-leak status.

## 14. Phase boundary and next-step API

Phase 2A exposes only a read-only snapshot of:

```text
confirmed_udp_datagram_size
overlay_payload_budget
outer_ip_family
exact path identity
```

No normal packet producer consumes those values in this phase. A later phase
may define a single, generation-bound API for business-packet sizing or
fragmentation policy. That consumer must revalidate the same exact path
identity and must not treat a DPLPMTUD timeout as path health or path-selection
evidence.
