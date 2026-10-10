#!/usr/bin/env python3
"""Run normal joining with bounded network faults; retain every outcome without retries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from network_conditions import load_profiles
from launch_identity import read_launch_evidence, source_identity


# These are synthetic stress configurations, not calibrated mobile operators.
# All cases use normal production traversal. No forced HH lane or delayed UDP gate.
SCENARIOS = {
    "strict-normal": ({}, {}),
    "relaxed-filtering": ({"STRICT_FILTERING_A": "0", "STRICT_FILTERING_B": "0"}, {}),
    "asymmetric-jitter": ({"DELAY_A_MS": "80", "DELAY_B_MS": "20",
                           "STUN_DELAY_A_MS": "80", "STUN_DELAY_B_MS": "20"},
                          {"A": {"jitter_ms": 60, "impair_stun": True},
                           "B": {"jitter_ms": 15, "impair_stun": True}}),
    "one-sided-loss": ({"STRICT_FILTERING_B": "0", "STUN_DELAY_A_MS": "30"},
                       {"A": {"loss_rate": 0.12, "jitter_ms": 20, "impair_stun": True}}),
    "correlated-burst-loss": ({}, {"A": {"burst_loss_rate": 0.12, "burst_loss_packets": 3,
                                          "impair_stun": True},
                                  "B": {"burst_loss_rate": 0.12, "burst_loss_packets": 3,
                                        "impair_stun": True}}),
    "udp-queue-pressure": ({"STRICT_FILTERING_A": "0", "STRICT_FILTERING_B": "0"},
                           {"A": {"rate_kbps": 32, "queue_limit": 4, "max_queue_delay_ms": 1000,
                                  "impair_stun": True},
                            "B": {"rate_kbps": 64, "queue_limit": 8, "impair_stun": True}}),
    "shared-allocator-jitter": ({"BACKGROUND_DEVICES": "8", "BACKGROUND_FLOWS": "16",
                                 "BACKGROUND_INTERVAL_MS": "150", "STEP_A": "2", "STEP_B": "3"},
                                {"A": {"jitter_ms": 20, "impair_stun": True},
                                 "B": {"jitter_ms": 40, "impair_stun": True}}),
    "random-shared-allocator": ({"MAPPING_MODE_A": "random", "MAPPING_MODE_B": "random",
                                 "BACKGROUND_DEVICES": "8", "BACKGROUND_FLOWS": "16",
                                 "BACKGROUND_INTERVAL_MS": "150"}, {}),
    "join-udp-outage": ({"BACKGROUND_DEVICES": "2", "BACKGROUND_FLOWS": "24",
                         "BACKGROUND_INTERVAL_MS": "400"},
                        {"A": {"outage_after_ms": 6000, "outage_duration_ms": 2500},
                         "B": {"outage_after_ms": 7000, "outage_duration_ms": 2500}}),
    "live-nat-rebind": ({"BACKGROUND_DEVICES": "2", "BACKGROUND_FLOWS": "32",
                         "BACKGROUND_INTERVAL_MS": "400"},
                        {"A": {"rebind_after_ms": 12000}}),
    "bilateral-nat-rebind": ({"BACKGROUND_DEVICES": "2", "BACKGROUND_FLOWS": "32",
                              "BACKGROUND_INTERVAL_MS": "400"},
                             {"A": {"rebind_after_ms": 10000}, "B": {"rebind_after_ms": 12000}}),
    "short-idle-stress": ({"BACKGROUND_DEVICES": "2", "BACKGROUND_FLOWS": "16",
                           "BACKGROUND_INTERVAL_MS": "100"},
                          {"A": {"mapping_idle_ms": 1500}, "B": {"mapping_idle_ms": 2000}}),
    "staggered-signal-delay": ({"SIGNAL_DELAY_A_MS": "250", "SIGNAL_DELAY_B_MS": "80",
                               "PREPARE_DELAY_B_MS": "3000", "STUN_DELAY_A_MS": "20"},
                              {"A": {"jitter_ms": 15, "impair_stun": True}}),
    "slow-relay-normal": ({"RELAY_DELAY_MS": "120"}, {}),
    "established-direct-outage": ({"STRICT_FILTERING_A": "0", "STRICT_FILTERING_B": "0",
                                   "NORMAL_REQUIRE_DIRECT_BEFORE_FAULT": "1"},
                                  {"A": {"outage_after_ms": 18000, "outage_duration_ms": 2500}}),
    "established-direct-rebind": ({"STRICT_FILTERING_A": "0", "STRICT_FILTERING_B": "0",
                                   "NORMAL_REQUIRE_DIRECT_BEFORE_FAULT": "1"},
                                  {"A": {"rebind_after_ms": 18000}}),
    "shared-allocator-continuous": ({"BACKGROUND_DEVICES": "8", "BACKGROUND_FLOWS": "16",
                                     "BACKGROUND_INTERVAL_MS": "150", "BACKGROUND_DURATION_MS": "120000",
                                     "NORMAL_OBSERVE_S": "60",
                                     "STEP_A": "2", "STEP_B": "3"},
                                    {"A": {"jitter_ms": 20, "impair_stun": True},
                                     "B": {"jitter_ms": 40, "impair_stun": True}}),
}


def case_environment(base: dict, changes: dict, directory: Path, profile: Path, seed: int) -> dict:
    # Do not inherit another experiment's fault flags or a forced traversal lane.
    env = {key: value for key, value in base.items() if key in {
        "PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL",
        "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
        "GOENV", "GOPATH", "GOCACHE", "CC", "SDKROOT", "DEVELOPER_DIR",
    }}
    env.update(MODE="normal", ROUNDS="1", EGRESS_CAPTURE="shim", STRICT_FILTERING="0",
               STRICT_FILTERING_A="1", STRICT_FILTERING_B="1", NORMAL_OBSERVE_S="30",
               OVERLAY_TIMEOUT_S="60", ROUND_TIMEOUT_S="150", NAT_SEED_BASE=str(seed),
               NETWORK_PROFILE=str(profile), NAT_SIM_ARTIFACT_DIR=str(directory))
    env.update(changes)
    return env


def read_case(directory: Path, exit_code: int, require_direct: bool = False,
              expected_source: dict | None = None) -> dict:
    errors, evidence = [], {}
    for name in ("nat-evidence", "mapping-evidence", "continuity-evidence", "cleanup"):
        try:
            value = json.loads((directory / "round-1" / f"{name}.json").read_text())
            if not isinstance(value, dict):
                raise ValueError("not an object")
            evidence[name] = value
        except (OSError, ValueError) as error:
            errors.append(f"missing_or_invalid:{name}:{type(error).__name__}")
    if exit_code:
        errors.append(f"smoke_exit:{exit_code}")
    launch_identity = read_launch_evidence(directory, expected_source)
    errors.extend(f"launch_identity:{reason}" for reason in launch_identity["errors"])
    checks = {"nat-evidence": ("result", "pass"), "mapping-evidence": ("valid", True),
              "continuity-evidence": ("valid", True), "cleanup": ("all_reaped", True)}
    for name, (field, expected) in checks.items():
        actual = evidence.get(name, {}).get(field)
        if type(actual) is not type(expected) or actual != expected:
            errors.append(f"failed:{name}")
    if evidence.get("cleanup", {}).get("forced_termination") is not False:
        errors.append("cleanup_not_graceful")
    observed = evidence.get("nat-evidence", {}).get("observed", {})
    final_paths = {}
    for side in ("a", "b"):
        if (observed.get(side, {}).get("first_usable", {}).get("path") not in {"direct", "relay"}
                or type(observed.get(side, {}).get("overlay_verified")) is not int
                or observed[side]["overlay_verified"] <= 0):
            errors.append(f"business_direction_missing:{side}")
        try:
            status = json.loads((directory / "round-1" / f"node-{side}.status.json").read_text())
            peers = status["peers"]
            if len(peers) != 1:
                raise ValueError("unexpected peer count")
            if not isinstance(peers[0].get("state"), str) or "active_path" not in peers[0]:
                raise ValueError("missing path state")
            final_paths[side] = {key: peers[0].get(key) for key in ("state", "active_path")}
            if peers[0]["active_path"] not in {"direct", "relay"} or peers[0].get("online") is not True:
                errors.append(f"final_path_unavailable:{side}")
        except (OSError, ValueError, KeyError, TypeError):
            errors.append(f"final_path_missing:{side}")
    direct_progress = None
    if require_direct:
        if any(final_paths.get(side, {}).get("active_path") != "direct" for side in ("a", "b")):
            errors.append("bilateral_direct_missing")
        try:
            samples = [json.loads(line) for line in
                       (directory / "round-1" / "business-samples.jsonl").read_text().splitlines()]
            final = samples[-1]
            base = next(row for row in samples
                        if 2_000_000_000 <= final["monotonic_ns"] - row["monotonic_ns"] <= 5_000_000_000)
            direct_progress = {side: final["direct"][side] - base["direct"][side] for side in ("a", "b")}
            if any(type(delta) is not int or delta < 2 for delta in direct_progress.values()):
                errors.append("recent_bidirectional_direct_business_missing")
        except (OSError, ValueError, KeyError, TypeError, IndexError, StopIteration):
            errors.append("direct_business_evidence_invalid")
    return {"valid": not errors, "errors": errors,
            "launch_identity": launch_identity,
            "direct_required": require_direct, "recent_direct_business_delta": direct_progress,
            "first_business_paths": {side: observed.get(side, {}).get("first_usable", {}).get("path") for side in ("a", "b")},
            "final_paths": final_paths, "continuity": evidence.get("continuity-evidence"),
            "mapping": evidence.get("mapping-evidence"), "business": evidence.get("nat-evidence", {}).get("decision")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--scenario", action="append", choices=SCENARIOS)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--seed", type=int, default=931200)
    parser.add_argument("--require-direct", action="store_true",
                        help="require both final Direct paths and recent bidirectional Direct business")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.list:
        print("\n".join(SCENARIOS))
        return 0
    selected = args.scenario or list(SCENARIOS)
    if len(set(selected)) != len(selected) or not 1 <= args.rounds <= 32 or len(selected) * args.rounds > 32:
        parser.error("choose distinct scenarios and at most 32 total executions")
    if not 0 <= args.seed <= 2**31:
        parser.error("seed must be in 0..2147483648")
    if args.output is None or not args.output.is_absolute():
        parser.error("output must be an absolute path outside a repository")
    output = args.output.resolve()
    if output.exists() or any((parent / ".git").exists() for parent in (output, *output.parents)):
        parser.error("output must be new and outside a repository")
    root = Path(__file__).resolve().parents[2]
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    source = source_identity(root)
    manifest = {"schema_version": 1, "source": source, "scope": "synthetic_ipv4_udp_normal_join",
                "valid": False, "retries": 0, "requested_runs": len(selected) * args.rounds, "runs": []}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for name in selected:
        changes, options = SCENARIOS[name]
        for repetition in range(args.rounds):
            if source_identity(root) != source:
                manifest["source_changed"] = True
                (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
                return 1
            seed = args.seed + list(SCENARIOS).index(name) * 100 + repetition
            directory = output / f"{name}-{repetition + 1}"
            profile = output / f"{name}-{repetition + 1}.profile.json"
            profile.write_text(json.dumps({"schema_version": 1, **options}, indent=2) + "\n")
            load_profiles(profile)
            env = case_environment(dict(os.environ), changes, directory, profile, seed)
            log = output / f"{name}-{repetition + 1}.log"
            started = time.monotonic()
            interrupted = False
            print(f"START {name} repetition={repetition + 1} seed_base={seed}", flush=True)
            with log.open("w") as stream:
                process = subprocess.Popen(["bash", "scripts/nat-sim/nat-sim-smoke.sh"], cwd=root,
                    env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=360)
                except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    interrupted = isinstance(error, KeyboardInterrupt)
                    code = 130 if interrupted else 124
            row = read_case(directory, code, args.require_direct, source)
            row.update(scenario=name, repetition=repetition + 1, seed_base=seed,
                       actual_nat_seed=seed + 1, environment_overrides=changes,
                       network_profile={"schema_version": 1, **options},
                       profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest(),
                       profile=str(profile), evidence_dir=str(directory), log=str(log),
                       exit_code=code, duration_s=round(time.monotonic() - started, 2))
            if source_identity(root) != source:
                row["valid"] = False
                row["errors"].append("source_changed_during_case")
            manifest["runs"].append(row)
            manifest["valid"] = (len(manifest["runs"]) == manifest["requested_runs"]
                                 and all(run["valid"] for run in manifest["runs"]))
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            print(json.dumps({key: row[key] for key in ("scenario", "valid", "errors", "first_business_paths", "duration_s")}), flush=True)
            if interrupted:
                return 130
    return 0 if manifest["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
