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
