# Cross-task integration gate

Issue #28 is a verification-only phase. It adds no product behavior. The gate proves that the
permanent Direct/Relay, Windows lifecycle, mobile lifecycle, path-state, DPLPMTUD/business-MTU,
observability, security, CI, Flutter and package checks all complete successfully on one exact
source SHA.

## Triggering every permanent gate

`client/daemon/cross_task_integration_gate_version.txt` is an inert tracked marker. The permanent
path-filtered workflows already include `client/daemon/**` (or the broader `client/**`), while CI
and Security Audit run for every pull request. Changing this marker on the integration PR therefore
forces all required gates to materialize instead of treating a missing path-filtered workflow as an
implicit pass.

The marker is not read by production code and carries no runtime behavior.

## Fail-closed manifest

`Cross-Task Integration Required` polls check-runs for the exact PR head (or explicit dispatch SHA)
and requires every check named in `contracts/cross_task_integration.json`.

Missing, pending, cancelled, timed-out, failed or skipped required checks fail the integration gate.
The generated `cross-task-integration-manifest.json` records:

- source head SHA and integration workflow blob SHA;
- workflow run ID/attempt and event type;
- every required check-run ID, status, conclusion and details URL;
- whether any required gate was skipped;
- the final pass/fail decision and reasons.

The manifest is uploaded even for a failed integration run so the failure is auditable.

## Release scope

This gate does not sign, tag, release or publish artifacts. Distribution and release verification
remain in the later final-gate issues.

## Final-gate Hard-Hard regression

On `83f1297953d3bf15d5eed6accd7e1333786f0cc7`, Path State Machine
[run 33970243659, job 101317343036](https://github.com/yhan-sun/p2wlan/actions/runs/33970243659/job/101317343036)
failed `tests::hard_hard_two_peer_stale_ack_cannot_resurrect_retired_session`:
the initiator never received the second Hard-Hard response. The failing command
was `cargo test -p p2wlan-daemon --lib hard_hard_ -- --test-threads=1`.
That revision has neither a `full` feature nor a `hard_hard_e2e` integration
target or `linux_ac_test_harness.rs`.

A reciprocal response belongs to one measured initiator session. If its
session, lifecycle, plan, recovery admission, or exact socket is lost before
the sweep starts, the response must be rejected. Treating that result as an
unavailable optimization incorrectly permits ordinary fresh-punch fallback:
after a network-generation change, the old response can acquire the new
generation's punch owner and fold the real successor behind it. An incoming
initiator offer whose responder cannot obtain a local STUN worker still uses
the existing admitted fallback path.

The stale-ACK E2E test pauses the reciprocal response after its punch claim and
before `hard_hard_begin_sweep`, advances both network generations, and then
releases the old response. It verifies that S1 ACKs cannot consume S2 pending
transactions and that both S2 paths eventually commit Direct. This ordering
reproduces the original failure without extending any timeout.

`tests::hard_hard_asymmetric_mtu_500_900` additionally runs the complete existing
Hard-Hard exact-socket convergence assertions through a userspace NAT link
with independent IPv4 path-MTU limits. The A-to-B UDP payload budget is
`500 - 20 - 8 = 472`; B-to-A is `900 - 20 - 8 = 872`. The link measures actual
UDP payloads, including protocol/encryption overhead, rejects oversize
datagrams, and requires zero oversize sends plus authenticated Direct on both
peers. This is a modeled path-MTU test, not a change to the kernel loopback MTU
or a DPLPMTUD convergence claim. Real Linux DF/EMSGSIZE coverage remains in
`client/netbind/tests/no_fragment_netns.rs`.

Targeted regression commands:

```bash
cargo test -p p2wlan-daemon --lib hard_hard_asymmetric_mtu_500_900 -- --nocapture --test-threads=1
cargo test -p p2wlan-daemon --lib tests::hard_hard_two_peer_stale_ack_cannot_resurrect_retired_session -- --exact --nocapture --test-threads=1
cargo test -p p2wlan-daemon --lib hard_hard_ -- --test-threads=1
```

Completion still requires all 17 contract checks and the downloaded machine
manifest to pass on the final post-merge `main` SHA. PR results alone do not
close Issue #28.
