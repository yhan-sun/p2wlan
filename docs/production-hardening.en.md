# P2WLAN Production Hardening Checklist

This document turns the README protocol boundaries and networking caveats into concrete release gates. The goal is not to block Preview usage; it is to make production readiness measurable.

## Status Levels

| Level | Meaning | Minimum bar |
| --- | --- | --- |
| Preview | Real-world testing and self-hosting | Clear README boundaries, basic CI, explainable direct and relay paths |
| Production Preview | Low-sensitivity production traffic | P0/P1 items in this document, rollback path, useful diagnostics |
| Production | Sensitive production traffic | Independent security review, long-running stability tests, real-world network matrix |

## P0 Protocol And Security

- State the data-plane protocol explicitly: current implementation is WireGuard-like `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, without claiming official WireGuard interoperability.
- State the algorithm suite: X25519, ChaCha20-Poly1305, BLAKE2s/HKDF-BLAKE2s, and Ed25519 challenge-response.
- Add fixed test vectors for handshakes, transport packets, replay windows, rekeying, and malformed packet parsing; current coverage must retain the RFC ChaCha20-Poly1305 AEAD vector and 64-packet replay-window boundary test.
- Fixed-length handshake frames must validate exact length and type, rejecting truncated frames and trailing-byte smuggling.
- Add regression coverage for signaling signatures, candidate generation, candidate expiry, and probe ephemeral key binding.
- Never expose X25519/Ed25519 private keys, derived session keys, Noise chaining keys, relay tickets, JWTs, or device credentials in logs, diagnostics, or panic output.
- Get an external review for the in-repo crypto protocol path before claiming full Production readiness.

## P1 NAT Traversal

- Record and expose the local NAT profile: mapping behavior, filtering behavior, hairpin behavior, mapping lifetime, STUN success rate, and confidence.
- Use at least two STUN observers from different networks for production-like configuration; one observer is only limited diagnostics.
- Maintain a real-world network matrix (template: [NAT traversal acceptance matrix](nat-traversal-matrix.en.md)) covering:
  - home broadband NAT to home broadband NAT
  - home broadband NAT to cloud public UDP
  - campus network to home broadband
  - enterprise network to home broadband
  - mobile hotspot to home broadband
  - CGNAT to cloud server
  - double symmetric/address-or-port-dependent NAT
- For each scenario, record direct success, relay fallback, time to first usable path, candidate source, failure reason, and log summary.
- Budget and cool down peer-reflexive, predicted, birthday probing, and socket-pool probes to avoid probe bursts.
- When STUN fully fails or UDP appears blocked, diagnostics should clearly say direct transport will depend heavily on relay or manual port mapping.

## P1 Relay

- State that relay is a DERP-like TCP/TLS ciphertext forwarder, not standard TURN.
- Enable TLS by default for public relays; plaintext TCP should be local-development only.
- Relay tickets must carry audience, region, expiry, and a revocation path.
- Relay diagnostics should show selected region, endpoint, connect RTT, pong timing, error code, cooldown, and candidate count.
- Relay servers should keep counters for active connections, registered peers, rejected connections, authentication failures, authentication rate limits, frame errors, forwarding success/failure, and revocation-feed refresh results.
- Add rate limits for connections, source-window authentication failures, and data forwarding; expose source dimensions only as short hashed keys, and never log raw tickets, JWTs, private keys, or payload plaintext.
- State relay-visible metadata: node IDs, timing, packet sizes, and connection frequency. Relays must not see private payload plaintext.

## P1 MTU And Performance

- Keep the default MTU conservative and explain the risk profile for `1280`, `1380`, `1420`, and `1500+` in CLI/GUI diagnostics.
- When relay paths exist and MTU is above `1380`, diagnostics should call out large-packet loss and PMTU blackhole risk.
- Diagnostics `/status` should expose runtime MTU, relay-path observed, risk code, and suggested safe MTU, and CLI doctor should reuse those structured fields instead of only inferring from prose.
- Use `scripts/mtu-smoke.sh` for repeatable ICMP MTU smoke; when `TCP_PORT` / `UDP_PORT` are set, also record small TCP flow, large TCP flow, and UDP payload results, with relay path and MTU risk code called out separately.
- Later add automatic PMTU probing: start at a safe floor, raise after success, and roll back on failure.
- Document and test IPv4 fragments, DF behavior, missing ICMP fragmentation-needed messages, and Windows firewall interactions.

## P2 Control Plane And Protocol Evolution

- Keep JSON-over-HTTPS/WSS versioned and backward-compatible; durable REST signaling must send and return `protocol_version=1`.
- Unsupported durable REST signaling versions must return stable `unsupported_signal_protocol_version` and `supported_protocol_version` fields instead of silently downgrading or persisting the signal.
- Treat `proto/` as a draft until migration includes dual parsing and golden fixtures.
- Keep identity roles separate: X25519 for data-plane handshakes, Ed25519 for control-plane authentication and signaling binding.
- Preserve observable fields for relay catalog, candidate source, candidate expiry, and network generation.
- If QUIC is introduced, evaluate relay transport or QUIC DATAGRAM first. Do not force transparent layer-3 VPN traffic into application streams.

## Release Gate

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets

cd server
go vet ./...
go test ./... -count=1
cd ..

pnpm audit --audit-level high
pnpm run build
./scripts/control-smoke.sh
```

Before a real-network release, also complete:

- Bidirectional virtual-IP testing across at least two different NAT environments.
- At least one relay-only environment test.
- At least one MTU downgrade test.
- At least one daemon restart, network switch, relay reconnect, and short control-plane outage test.
- README, release notes, and known-limit updates.
