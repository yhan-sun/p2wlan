# Deterministic NAT topology framework

This directory contains the local, deterministic network-topology regression
used by P2WLAN. It is intentionally separate from real Mini/Air device
acceptance: loopback simulation is repeatable CI evidence, not proof that every
carrier or campus NAT behaves the same way.

## Entry points

```bash
# List registered scenarios.
bash scripts/nat-sim/run-topology-scenario.sh --list

# Fast simulator and observability unit tests.
bash scripts/nat-sim/run-topology-scenario.sh simulator-unit

# One complete end-to-end topology.
bash scripts/nat-sim/run-topology-scenario.sh direct-baseline
```

The scenario runner is the only CI-facing entry point. It pins seeds, round
counts, port-stride behavior and time budgets so a named scenario does not
silently change meaning between runs.

## Scenario contract

| Scenario | Required behavior |
| --- | --- |
| `simulator-unit` | STUN encoding, APDM mappings, filtering, loss/reordering and observability parsers remain deterministic. |
| `direct-baseline` | Two fresh daemons establish and prove bidirectional encrypted Direct traffic through independent NATs. |
| `hard-hard-strict` | Both endpoint-dependent NATs use non-unit port strides and consumed mappings; fresh mapping, prediction and bounded Birthday probing must still produce a proven Direct path. |
| `relay-blackhole` | Inter-NAT UDP is impossible while STUN works; Relay is the only usable encrypted path and the business-packet burst is lossless. |
| `relay-failover` | Killing the confirmed active Relay causes selection, confirmation and business traffic to recover on a second Relay. |
| `observability-fail-closed` | Missing required status evidence is rejected; the harness must not manufacture an empty success document. |

## CI policy

Pull requests run shell validation and the deterministic Python suite as the
stable `NAT Topology Required` check. Main-branch changes, the weekly schedule
and manual dispatch additionally execute every end-to-end scenario. Each smoke
job writes to a unique artifact directory and uploads its complete evidence,
including daemon logs, status snapshots, relay metrics and the NAT trace.

The workflow deliberately runs end-to-end jobs only for changes that can affect
NAT traversal, the daemon, Relay, the control plane or the evidence contract.
This keeps unrelated UI/documentation pull requests from paying the full
network-simulation cost.

## Failure handling

A scenario failure is a product or harness failure until its artifact proves
otherwise. Do not rerun to obtain a green result without first classifying the
reason code. The failure-injection scenario protects this rule by verifying
that unavailable or malformed required evidence remains a hard failure.
