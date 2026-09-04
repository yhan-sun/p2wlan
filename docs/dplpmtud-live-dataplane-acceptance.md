# DPLPMTUD live dataplane acceptance

Issue #26 closes the gap between the bounded Direct-path DPLPMTUD reducer and
the packet-size decision used by normal encrypted traffic. The Path State
Machine remains the only authority that selects Direct or Relay. DPLPMTUD owns
only the size state for one exact committed Direct identity.

## Exact identity and path isolation

One managed Direct entry is keyed by all of:

- peer identity;
- network generation;
- peer-session generation;
- remote-candidate epoch;
- authenticated Direct validation owner and request;
- authenticated remote endpoint and local endpoint;
- UDP transport instance and socket index;
- outer IP family.

A replacement in any dimension cancels the old worker, revokes its immutable
business-budget publication and requires a fresh positive BASE ACK. A Relay
selection calls the same owner-scoped cancellation boundary. Relay traffic does
not read, wait for, or inherit a Direct DPLPMTUD budget.

Probe timeout, loss, duplicate ACK, stale ACK, local scheduler pressure and
`EMSGSIZE` update only the exact DPLPMTUD entry. They never mark a peer offline,
increment Direct-health failure, select Relay, or tear down a healthy path.

## Size layers and required boundary matrix

The implementation keeps three values separate:

```text
outer IP packet
  = outer IP header + UDP header + UDP datagram

UDP datagram
  = WireGuard transport overhead + decrypted inner IP packet

overlay payload budget
  = complete decrypted inner IP packet
```

The fixed overheads are:

- IPv4 outer IP + UDP: 28 bytes;
- IPv6 outer IP + UDP: 48 bytes;
- WireGuard transport header + AEAD tag: 32 bytes.

The exact required matrix is:

| Outer packet | IPv4 UDP | IPv4 inner budget | IPv6 UDP | IPv6 inner budget |
| ---: | ---: | ---: | ---: | ---: |
| 1280 | 1252 | 1220 | 1232 | 1200 |
| 1360 | 1332 | 1300 | 1312 | 1280 |
| 1380 | 1352 | 1320 | 1332 | 1300 |
| 1420 | 1392 | 1360 | 1372 | 1340 |
| 1500 | 1472 | 1440 | 1452 | 1420 |

The 1500 rows exactly match the IPv4 and IPv6 Ethernet-sized ceilings. No
cross-family value is reused.

## Actual business decision point

For a capability-managed Direct peer, the live path is:

```text
TUN packet
→ DataPlane outbound record
→ bounded per-peer plaintext FIFO
→ committed-path lookup
→ immutable Direct budget token
→ pre-encryption inner-packet budget check
→ WireGuard encryption
→ final exact path/revision/UDP-owner check
→ ciphertext-size check
→ nonblocking send on the exact UDP socket
```

An oversize inner IPv4 packet is rejected before encryption and may produce a
bounded local ICMP Fragmentation Needed response. An oversize IPv6 packet
produces Packet Too Big only when the selected inner budget can be represented
as a standards-valid IPv6 MTU; otherwise it fails closed. Recursive ICMP error
generation is suppressed. P2WLAN does not fragment or reassemble overlay
packets in this path.

A synchronous `EMSGSIZE` at the final syscall invalidates only the exact
identity and budget revision, publishes an explicit `None` tombstone, returns
the reducer to BASE and requires a fresh positive BASE ACK. It is not a path
failure and does not consume Relay fallback credit.

The configured TUN MTU remains a static interface ceiling. The confirmed
per-peer Direct budget is enforced below it at the live plaintext and
ciphertext boundaries. Relay framing remains independent and is never governed
by a Direct budget.

## Required scenarios and machine evidence

`contracts/dplpmtud_acceptance.json` defines DP-01 through DP-10. Each scenario
maps to one exact Rust test command and one dedicated log. A component-wide exit
status cannot fan out into multiple passing records.

The collector rejects:

- a missing, renamed, failed or skipped exact test;
- a required structured marker that is missing, duplicated or malformed;
- a boundary row that does not cover 1280/1360/1380/1420/1500 for both families;
- a required semantic token missing from an existing production-path test;
- an endpoint, peer ID, nonce, path cookie or other high-cardinality value in
  the aggregate evidence;
- duplicate scenario or test mappings.

The aggregate additionally rejects source/workflow SHA mismatch, contract or
report digest mismatch, missing/extra scenarios, a failed component job, and a
pull-request run whose same-head external gate job did not succeed.

The stable aggregate check is `DPLPMTUD Required`. On pull requests it waits for
the live `Business MTU Budget Required` check. To avoid a dependency cycle, the
business-budget aggregate no longer waits for DPLPMTUD; DPLPMTUD is the final
consumer of that live business-send result.

## Operator smoke test

`scripts/mtu-smoke.sh` retains the same 1280/1360/1380/1420/1500 operator
matrix for a real deployed peer. It is useful release evidence but is not used
to replace deterministic PR tests: missing tools or a missing peer must never
turn the required CI aggregate green.

## Deferred scope

This work does not change signing, release credentials, tags or publication.
It does not implement Relay PLPMTUD or a dynamic global TUN MTU. Those are
separate protocol/product decisions; the accepted contract is exact-path
Direct discovery plus independent Relay forwarding.
