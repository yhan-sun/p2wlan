# NAT topology CI contract

The required pull-request gate runs three deterministic profiles: simulator
unit tests, a cold-start Direct topology through two independent simulated NATs,
and a Relay-only topology with Direct traffic blackholed. Every profile keeps
its logs, status snapshots, connection timelines, and NAT trace as an artifact.

The simulator intentionally binds daemon UDP and STUN endpoints to loopback.
Production direct sockets remain pinned to the physical route interface. The
existing `fresh_mapping_harness_loopback` flag is the only exception: when it
is explicitly enabled **and** the UDP bind address is loopback, interface
pinning is omitted so the process can reach the local simulator. A non-loopback
bind can never use this exception.

Each daemon gets a separate runtime/config directory. Consequently each
process publishes a different diagnostics session token, and status evidence
is fetched with the exact token belonging to that daemon. Missing, empty, or
unauthenticated status evidence fails closed.

The scheduled/manual profile also injects a status failure and passes only when
the underlying smoke exits non-zero with a stable fail-closed reason code.
