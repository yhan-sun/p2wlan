# P2WLAN NAT Traversal Acceptance Matrix

Use this document to record real-network direct success, relay fallback, and MTU behavior. It is a release-gate worksheet, not a one-time explanation.

## Goals

- Separate "STUN observed a public port" from "a peer can actually send inbound UDP to it".
- Cover full cone, restricted, port restricted, symmetric, CGNAT, campus, enterprise, and mobile-network differences.
- Verify the current ICE-like boundary: host/server-reflexive/peer-reflexive/predicted/birthday/socket-pool candidates, direct nomination, and relay fallback.
- Keep relay terminology precise: the current relay is DERP-like TCP/TLS ciphertext forwarding, not standard TURN allocation/permission/channel semantics.

## Default Matrix

| ID | A-side network | B-side network | Expected path | Required checks |
| --- | --- | --- | --- | --- |
| NAT-01 | Home broadband NAT | Home broadband NAT | Direct or relay fallback | Two STUN observers, candidate count, time to first usable path |
| NAT-02 | Home broadband NAT | Cloud public UDP | Public UDP direct | Cloud security group, host firewall, fixed UDP bind/advertise |
| NAT-03 | Campus network | Home broadband NAT | Relay fallback | UDP blocked, STUN timeout, relay RTT |
| NAT-04 | Enterprise network | Home broadband NAT | Relay fallback | UDP egress limits, TLS relay reachability |
| NAT-05 | Mobile hotspot / CGNAT | Home broadband NAT | Relay fallback; some direct may pass | Symmetric/address-or-port-dependent NAT detection |
| NAT-06 | Double symmetric NAT | Any restricted NAT | Stable relay fallback | Birthday/socket-pool probe budget and cooldown |
| NAT-07 | Relay-only policy | Any network | Relay | `relay-policy relay-only`, metadata exposure note |
| NAT-08 | High-MTU path | Relay path | No large-packet stalls | 1420/1380/1280 downgrade smoke test |

## Per-Run Record

| Field | Example | Notes |
| --- | --- | --- |
| Date / version | 2026-07-29 / v0.1.62 | Use commit or release precision |
| Scenario ID | NAT-05 | From the default matrix |
| A/B network | mobile hotspot / home NAT | Keep network type even if public IPs are redacted |
| STUN observers | 3 configured, 2 success | At least two observers are needed for useful classification |
| NAT profile | mapping=address_or_port_dependent filtering=address_or_port_dependent | From `/status` or `p2wlan doctor` |
| Candidate sources | host, srflx, peer-reflexive, predicted | Record the actual direct sources tried |
| Selected path | direct / relay | Include reason code |
| Time to first usable path | 850ms | From daemon start or peer joined to usable path |
| Relay metrics | cn-east 43ms pong=ok | Region, endpoint, RTT, error code |
| MTU result | 1420 fail, 1380 pass | Record ping, small TCP, large TCP, UDP payload |
| Failure summary | direct_probe_failed | Keep log summaries redacted: no private keys, JWTs, or tickets |

## Minimum Pass Bar

- NAT-01/NAT-02 must produce at least one direct path with bidirectional virtual-IP ping, SSH, or TCP smoke.
- NAT-03/NAT-04/NAT-05/NAT-06 must automatically fall back to relay when direct is unavailable, and UI/CLI diagnostics must explain why.
- `doctor` must warn when fewer than two STUN observers are configured.
- When relay paths exist and MTU is above `1380`, both `doctor` and the Diagnostics page must show risk.
- Every failure needs a stable reason code or log summary; it should not end as plain `unknown`.

## Suggested Commands

```bash
p2wlan doctor
p2wlan status --json
ping <peer-virtual-ip>
ssh <peer-virtual-ip>
p2wlan config set mtu 1380
p2wlan down && p2wlan up
```

## Future Implementation Gates

- Before claiming full RFC8445 ICE, expose candidate priority, nomination, checklist state, role conflict, and pair pruning.
- If standard TURN is implemented, document allocation, permission, channel, refresh, and auth semantics separately; do not rename the current DERP-like relay to TURN.
- Before automatic PMTU probing ships, keep manual MTU downgrade and fallback evidence available.
