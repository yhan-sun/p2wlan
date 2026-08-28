# NAT Topology Matrix

The topology matrix wraps `nat-sim-smoke.sh`; it does not replace the existing simulator or claim to reproduce every carrier, campus, hotspot, or mobile-network NAT.

## Pull-request gate

```bash
bash scripts/nat-sim/run-topology-matrix.sh pr
```

The required profile runs:

- `direct-baseline`: deterministic direct traversal with no loss or reordering.
- `relay-blackhole`: relay-only business traffic, proving that the harness does not accidentally count a Direct path.

Each scenario receives its own port block, deterministic seed, log file, evidence directory, and result JSON. Existing evidence is never overwritten. Each daemon also receives a separate configuration parent and diagnostics credential file; authenticated `/status` collection must use the credential belonging to that exact daemon process.

## Extended profile

```bash
bash scripts/nat-sim/run-topology-matrix.sh extended
```

The nightly/manual profile adds strict address/port-dependent mapping and filtering, packet reordering/loss, relay restart/failover, and fail-closed diagnostics injections. Expected-failure scenarios pass only when the smoke harness exits non-zero and reports the configured stable reason code.

## Evidence boundary

A successful simulated topology proves deterministic state-machine and harness behavior under that synthetic profile. Android backgrounding, Wi-Fi/cellular handoff, real CGNAT, router firmware differences, and physical-network tail latency remain separate device-validation concerns.
