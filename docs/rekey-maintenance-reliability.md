# Rekey maintenance reliability

## Incident and scope

The reported macOS screen-sharing interruption followed expiration of the active encrypted session. The supplied diagnostic conversation records rekey checks before expiry and two Probe-v2 binding preparation failures before an offer was actually sent. The underlying logs were partially rotated: the exact contending owner is not established.

This change repairs maintenance preparation progress. It does not change the cryptographic rejection deadlines, handshake roles, authentication, network retransmission limits, Direct/Relay selection, or old receive-key overlap. Relay forwards the same encrypted business traffic; switching to Relay is not a replacement for obtaining a valid encrypted session.

## Runtime behavior

A single maintenance-owned retry map coalesces work per peer. Each entry is fenced by the network generation, online peer lifecycle, and active transport-session instance. Local retry delays are 50/100/200/400/800 ms plus 0–50 ms of deterministic peer jitter. During the last five positive seconds before the observed hard deadline the base delay is 50 ms. Observations can shorten, but never extend, that deadline. An expired deadline does not cause a zero-delay spin or extend key validity. The existing ten-second scan remains a recovery backstop.

Preparation retries consume no network attempt until an exact pending transaction has successfully staged its Probe binding and is ready to call the offer API. Network delivery ambiguity retains the existing pending-handshake retransmission and timeout ownership. A busy pending handshake remains owned by that existing transaction; local retries do not create crossing offers.

Binding admission reports epoch contention, connection-map contention, capacity, stale lifecycle, missing peer, and duplicate binding separately. A failed admission that did not create a binding performs no connection-writer cleanup. Cleanup of an actually staged binding uses an exact token and peer-lifecycle fence, never queues a writer, and cannot remove an already promoted key. Eager cleanup and retry maps each retain at most 1,024 entries. Eager cleanup has a 60-second bound; the authoritative pending binding's existing TTL remains the fallback.

Rekeys clone the already published candidate tuple without waiting for a live STUN refresh mutex. An existing relay-only session can rekey with an empty candidate set even when no UDP snapshot exists. The readiness fence for first-session gathering is unchanged.

## Automated checks

Run:

```sh
cargo test -p p2wlan-daemon --lib maintenance_ -- --test-threads=1
cargo test -p p2wlan-daemon --lib rekey -- --test-threads=1
```

`Rekey Reliability` runs these checks on Linux and macOS and repeats the real maintenance-loop contention regression ten times. That regression holds a real connection reader through three preparation attempts, verifies that no network attempt is consumed and no cleanup writer is queued, then releases it without another wake. It requires an offer before the ten-second scan, authenticates old-key business packets throughout preparation, applies a real Noise response through the daemon answer handler, and decrypts subsequent business packets with the new key.

Additional tests cover bounded ledgers, deadline retention, duplicate kicks, session replacement, peer leave/rejoin, epoch and binding-capacity failures, promoted-key preservation, cleanup TTL, and absent/contended candidate snapshots. Passing these tests is not evidence that a physical two-Mac packaged application has completed a screen-sharing soak test.

## Packaged macOS acceptance

Use two packages whose daemon build information identifies the accepted source commit. Preserve both daemon logs, rotation files, configuration summaries without secrets, and relevant macOS Screen Sharing/unified-log events. Continue high-performance screen sharing for at least one hour and count at least twenty completed key rotations; then run an overnight soak.

Correlate `maintenance_binding_deferred`, `maintenance_preparation_retry_scheduled` (debug), actual offer/answer and session installation events, and authenticated business traffic. Record the failure reason, remaining key lifetime, longest consecutive traffic gap, and any RTCP/TCP disconnection. An expired previous receive slot is normal; failure means the business-serving active key expires with no usable replacement. Do not extend key lifetimes, bypass Probe authentication, or treat an installed answer alone as proof of bidirectional continuity.

This source change does not deploy or replace an already installed daemon. Physical-device acceptance and release publication remain separate steps.
