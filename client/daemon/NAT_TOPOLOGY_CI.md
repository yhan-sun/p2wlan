# NAT topology CI contract

`NAT Topology Required` reuses `scripts/nat-sim/nat-sim-smoke.sh` and adds a
stable pull-request entry point in `scripts/nat-sim/run-ci-topology.sh`.

Required pull-request profiles execute serially:

1. simulator/parser unit tests;
2. one deterministic cold-start Direct topology;
3. one deterministic UDP-blackhole topology that must carry encrypted overlay
   traffic through Relay.

The wrapper preserves the smoke harness' module-level DEBUG evidence filters.
Those records are part of the acceptance contract: hiding them with a global
`info` override can make a real path indistinguishable from missing evidence.
Every profile writes a unique log/artifact directory and the aggregate gate
rejects failed, cancelled or skipped required profiles.

Scheduled/manual runs additionally inject an unavailable status surface and
must fail closed instead of treating absent diagnostics as success.
