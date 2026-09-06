# Cross-task integration final-gate record

Issue #28 was a verification-only phase. It added no product behavior. Its temporary automation proved that the permanent Direct/Relay, Windows lifecycle, mobile lifecycle, path-state, DPLPMTUD/business-MTU, observability, security, CI, Flutter and package checks all completed successfully on one exact source SHA.

## Final acceptance

Issue #28 is complete and closed.

- Initial cross-task integration merge: `83f1297953d3bf15d5eed6accd7e1333786f0cc7` (PR #61).
- Final accepted `main` after the Hard-Hard regression repair: `34dd364427b2260c53f35628127de12a11a42f04` (PR #62).
- Cross-Task Integration run: `34007731922`.
- Exact-head manifest job: `101421473420`.
- Artifact: `cross-task-integration-manifest-34007731922-2`.
- Issue evidence: https://github.com/yhan-sun/p2wlan/issues/28#issuecomment-5556628615

The downloaded machine-readable manifest reported:

```text
exact_head=true
required_check_count=17
observed_required_check_count=17
no_skipped_required_gate=true
result=pass
```

All 17 required checks completed successfully on the final accepted SHA:

1. `CI Required`
2. `Business MTU Budget Required`
3. `DPLPMTUD Required`
4. `Path State Machine Required`
5. `NAT Topology Required`
6. `Windows Lifecycle Required`
7. `Mobile Lifecycle Required`
8. `Path Observability Required`
9. `Security Audit Required`
10. `Analyze and Test`
11. `Android arm64 CI test APK`
12. `iOS Compile`
13. `Linux x64 Release Bundle`
14. `macOS Release Apps`
15. `Windows x64 Release Bundle`
16. `macOS arm64 test DMG`
17. `Android arm64 test APK`

## Hard-Hard final-gate regression

On `83f1297953d3bf15d5eed6accd7e1333786f0cc7`, Path State Machine run `33970243659`, job `101317343036`, exposed a stale-response race in `spawn_hard_hard_initiator_response`.

A reciprocal response belongs to one measured initiator session. If its session, lifecycle, plan, recovery admission or exact socket fence is lost before the sweep starts, that response is consumed and must be rejected. Returning `HardHardRemoteStart::NotStarted` allowed ordinary fresh-punch fallback to acquire a newer network generation's punch owner and suppress that generation's legitimate Hard-Hard retry. PR #62 changed those fence-failure results to `HardHardRemoteStart::Rejected`.

The deterministic stale-response gate now advances both network generations while the old response is paused before `hard_hard_begin_sweep`, then verifies that the old response cannot consume the successor generation. `tests::hard_hard_asymmetric_mtu_500_900` additionally verifies complete Hard-Hard convergence through a userspace NAT link with independent IPv4 path-MTU limits of 500 and 900 bytes, zero oversize sends and authenticated Direct on both peers.

Targeted regression commands remain:

```bash
cargo test -p p2wlan-daemon --lib hard_hard_asymmetric_mtu_500_900 -- --nocapture --test-threads=1
cargo test -p p2wlan-daemon --lib tests::hard_hard_two_peer_stale_ack_cannot_resurrect_retired_session -- --exact --nocapture --test-threads=1
cargo test -p p2wlan-daemon --lib hard_hard_ -- --test-threads=1
```

## Final Gate 09 retirement

Issue #29 retires the temporary #28 orchestration after acceptance is recorded. The following verification-only implementation is removed from the live repository surface:

- `.github/workflows/cross-task-integration-required.yml`
- `contracts/cross_task_integration.json`
- `scripts/cross_task_integration/aggregate_evidence.py`
- `scripts/cross_task_integration/test_aggregate_evidence.py`
- `client/daemon/cross_task_integration_gate_version.txt`

The permanent required workflows and the product/test fixes introduced while satisfying #28 remain unchanged. Historical evidence is retained by the GitHub Actions run/artifact, Issue #28 closure comment and this document.

Release versioning, release-candidate validation and publication remain owned by Final Gates #31, #32 and #33 respectively.
