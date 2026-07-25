# Security Review Status

Date: 2026-07-25

This document records the current repository security posture. It is not an external audit report and must not be used to claim production-grade security or UU/WebRTC-level reliability.

## Completed Controls

- Probe v2 authenticates Punch/ACK with MAC verification, explicit `session_id`, target binding, local nonce replay window, inbound/outbound probe budgets, and cross-process global probe budgets.
- Probe key derivation supports session-bound ephemeral X25519 via `probe_ephemeral_public_key`, with static-session fallback for compatibility.
- Device identity uses Ed25519 transcript signatures over probe key material, peer/device IDs, session ID, and expiration.
- Rust/Go golden vectors and the `pnch_parser` fuzz target cover PNCH parser compatibility and malformed inputs.
- Control plane supports current device credential revocation with `DELETE /api/v1/devices/credential`; deleting a device records revocation tombstones before cascade deletion.
- Relay tickets are short-lived Ed25519 JWTs bound to `device_id`, `credential_id`, `network_id`, audience, region, `jti`, and time claims.
- Relay enforces local static denylist entries from `RELAY_TICKET_REVOKED_JTIS_JSON` and `RELAY_TICKET_REVOKED_DEVICES_JSON`.
- Relay can poll the control-plane revocation feed at `GET /api/v1/relay/revocations` using `RELAY_REVOCATION_FEED_URL`, `RELAY_REVOCATION_FEED_TOKEN`, and `RELAY_REVOCATION_POLL_INTERVAL`.
- Relay feed snapshots revoke by `jti`, `device_id`, and `credential_id`; feed refresh failure keeps the previous successful snapshot active.

## Revocation Semantics

- New relay tickets include `credential_id`, so a relay with a fresh feed snapshot can reject tickets signed for a revoked credential.
- Device deletion writes both `device_id` and credential tombstones, so the feed retains revoked IDs after `device_credentials` rows are removed by cascade.
- A relay that is not configured for the online feed, cannot reach the feed, or has not yet polled a fresh snapshot may still accept an already-signed ticket until that ticket expires.
- Old tickets that do not contain `credential_id` remain compatible for the short TTL window; they can still be denied by `jti`, `device_id`, or expiry.

## Remaining Boundaries

- No external security audit has been completed.
- Deployment hardening still needs review for TLS certificates, relay keyring rollout, feed token handling, log redaction, firewall exposure, and operational alerting.
- Public UDP direct-path reliability is not proven by repository tests alone.
- Do not claim the system has reached UU/WebRTC-level reliability unless both endpoints are running the new daemon build and the strict public UDP validation passes with packet-capture evidence.

## Public UDP Acceptance Steps

Run only with permission to deploy the new daemon to both endpoints. Do not restart or kill a user's active daemon without explicit authorization.

```bash
REQUIRE_NEW_SCHEMA=1 REQUIRE_PUBLIC_UDP=1 REQUIRE_NO_RELAY=1 \
PEER=<remote VIP/node/device> CAPTURE_SECONDS=20 IFACE=<physical interface> \
P2WLAN_BIN=target/debug/p2wlan \
bash scripts/direct-path-verify.sh
```

Required evidence:

- Script prints `PASS_PUBLIC_UDP_CONFIRMED`.
- Diagnostics show `probe_key_type=ephemeral_session`.
- Selected/current candidate pair is a public UDP endpoint, not a `10.20.x.x` overlay endpoint.
- Relay fallback is absent.
- Packet capture corroborates the public UDP flow between the two endpoints.
