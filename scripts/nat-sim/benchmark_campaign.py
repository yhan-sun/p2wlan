#!/usr/bin/env python3
"""Freeze paired normal-matrix batches and retain every prescheduled outcome.

This is a synthetic experiment runner, not a real-TUN or Direct@10s gate.
Plans and evidence must be outside Git checkouts. There are no retries.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from launch_identity import read_launch_evidence, validate_launch_summary


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts/network_core_benchmark.json"
RUNNER = Path(__file__).with_name("run-network-matrix.py")
# Noninteractive parents may ignore SIGINT. Reset it inside the fresh child,
# without process-global signal mutation or unsafe preexec_fn in the parent.
MATRIX_ENTRYPOINT = (
    "import runpy,signal,sys;from pathlib import Path;"
    "signal.signal(signal.SIGINT,signal.default_int_handler);"
    "sys.path.insert(0,str(Path(sys.argv[1]).parent));"
    "sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
)
SPEC = importlib.util.spec_from_file_location("campaign_network_matrix", RUNNER)
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def harness_identity(root: Path) -> dict:
    """Bind both checkouts to the same executable simulation, excluding this coordinator."""
    names = set(subprocess.check_output(
        ["git", "ls-files", "scripts/nat-sim", "scripts/diagnostics-auth.sh", "scripts/relay_keygen.go"],
        cwd=root, text=True).splitlines())
    # Include the executable owner even before a new helper is committed.
    names.add("scripts/nat-sim/launch_identity.py")
    excluded = {"scripts/nat-sim/benchmark_campaign.py", "scripts/nat-sim/test_benchmark_campaign.py"}
    return {name: digest((root / name).read_bytes()) for name in names
            if name not in excluded and Path(name).suffix in {".py", ".sh", ".c", ".go", ".json"}}


def load_json(path: Path) -> dict:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("JSON exceeds 16 MiB")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON must be an object")
    return value


def contract() -> dict:
    value = load_json(CONTRACT)
    if value.get("schema_version") != 1 or value.get("max_batch_executions") != 32:
        raise ValueError("unsupported benchmark contract")
    return value


def build_plan(scenarios: list[str], rounds: int, seed: int, batch_size: int) -> dict:
    rules = contract()
    if not scenarios or len(set(scenarios)) != len(scenarios) or set(scenarios) - MATRIX.SCENARIOS.keys():
        raise ValueError("choose distinct existing normal-matrix scenarios")
    if type(rounds) is not int or not 1 <= rounds <= rules["max_rounds_per_scenario"]:
        raise ValueError("rounds must be in 1..1000")
    if type(batch_size) is not int or not 1 <= batch_size <= rules["max_batch_executions"]:
        raise ValueError("batch size must be in 1..32")
    if type(seed) is not int or not 0 <= seed <= 2**31 - 100000:
        raise ValueError("seed is outside the bounded campaign range")
    if rounds * len(scenarios) > rules["max_campaign_executions_per_variant"]:
        raise ValueError("campaign exceeds 10000 executions per variant")
    batches = []
    for ordinal, scenario in enumerate(scenarios):
        native_offset = list(MATRIX.SCENARIOS).index(scenario) * 100
        # Disjoint scenario ranges, paired identically across both variants.
        initial_seed = seed + ordinal * (rounds + 2000)
        for offset in range(0, rounds, batch_size):
            count = min(batch_size, rounds - offset)
            batches.append({
                "id": f"{scenario}-{offset + 1:04d}", "scenario": scenario,
                "round_offset": offset, "rounds": count,
                "runner_seed": initial_seed + offset,
                "seed_bases": [initial_seed + offset + native_offset + number for number in range(count)],
            })
    profiles = {name: MATRIX.SCENARIOS[name] for name in scenarios}
    return {
        "schema_version": 1, "scope": rules["synthetic_runner_scope"],
        "contract_sha256": digest(CONTRACT.read_bytes()),
        "harness": harness_identity(ROOT),
        "profiles_sha256": digest(json.dumps(profiles, sort_keys=True).encode()),
        "variants": rules["variants"], "retries": 0, "scenarios": scenarios,
        "rounds_per_scenario": rounds, "seed": seed, "batch_size": batch_size,
        "requested_per_variant": len(scenarios) * rounds, "batches": batches,
    }


def validate_plan(value: dict) -> None:
    expected = build_plan(value["scenarios"], value["rounds_per_scenario"], value["seed"], value["batch_size"])
    if json.dumps(value, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("plan differs from the frozen contract, profiles or sample schedule")


def external_new_path(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("output must be an absolute path")
    resolved = path.resolve()
    if resolved.exists() or any((parent / ".git").exists() for parent in (resolved, *resolved.parents)):
        raise ValueError("output must be new and outside a Git checkout")
    return resolved


def save(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.replace(path)


def save_campaign(path: Path, campaign: dict) -> None:
    # Raw batch manifests remain beside their digests. Do not duplicate all
    # rows into the campaign index: 10000 scheduled runs must remain readable
    # within the JSON input bound, including unsuccessful runs.
    index = {**campaign, "records": [
        {key: value for key, value in record.items() if key != "manifest"}
        for record in campaign["records"]]}
    save(path, index)


def wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    middle = (proportion + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, middle - radius), min(1.0, middle + radius)]


def summarize(plan: dict, records: list[dict]) -> dict:
    validate_plan(plan)
    expected = {batch["id"]: batch for batch in plan["batches"]}
    seen, sources = set(), {}
    failed_batches = {variant: 0 for variant in plan["variants"]}
    outcomes = {variant: [] for variant in plan["variants"]}
    launch_available = {variant: 0 for variant in plan["variants"]}
    for record in records:
        variant, batch_id = record["variant"], record["batch_id"]
        if variant not in outcomes or batch_id not in expected or (variant, batch_id) in seen:
            raise ValueError("unknown or duplicate variant/batch evidence")
        if type(record.get("exit_code")) is not int:
            raise ValueError("batch exit_code must be an integer")
        failed_batches[variant] += int(record["exit_code"] != 0)
        seen.add((variant, batch_id))
        batch, manifest = expected[batch_id], record["manifest"]
        if manifest is None:
            outcomes[variant].extend([False] * batch["rounds"])
            continue
        if (type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1
                or type(manifest.get("valid")) is not bool
                or manifest.get("scope") != plan["scope"]
                or type(manifest.get("retries")) is not int or manifest["retries"] != 0
                or type(manifest.get("requested_runs")) is not int or manifest["requested_runs"] != batch["rounds"]):
            raise ValueError("batch scope, retries or requested count mismatch")
        if type(manifest.get("source_changed", False)) is not bool:
            raise ValueError("source_changed must be boolean")
        source = manifest.get("source")
        if (not isinstance(source, dict)
                or not isinstance(source.get("commit"), str)
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["commit"])
                or not isinstance(source.get("patch_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", source["patch_sha256"])):
            raise ValueError("batch source identity missing")
        if variant in sources and sources[variant] != source:
            raise ValueError("source changed between batches of the same variant")
        sources[variant] = source
        runs = manifest.get("runs")
        if not isinstance(runs, list) or len(runs) > batch["rounds"]:
            raise ValueError("invalid run count")
        changes, options = MATRIX.SCENARIOS[batch["scenario"]]
        for index, row in enumerate(runs):
            if (any(type(row.get(key)) is not int for key in ("repetition", "seed_base", "actual_nat_seed"))
                    or row.get("scenario") != batch["scenario"] or row.get("repetition") != index + 1
                    or row.get("seed_base") != batch["seed_bases"][index]
                    or row.get("actual_nat_seed") != batch["seed_bases"][index] + 1):
                raise ValueError("batch seed, scenario or repetition mismatch")
            if type(row.get("valid")) is not bool or type(row.get("exit_code")) is not int:
                raise ValueError("run outcome must have typed valid and exit_code")
            errors = row.get("errors")
            if (not isinstance(errors, list) or not all(isinstance(error, str) for error in errors)
                    or row["valid"] != (row["exit_code"] == 0 and not errors)):
                raise ValueError("run validity contradicts its errors or exit code")
            if (row.get("environment_overrides") != changes
                    or row.get("network_profile") != {"schema_version": 1, **options}):
                raise ValueError("run environment or network profile differs from the frozen scenario")
            launch = row.get("launch_identity")
            validate_launch_summary(launch, source, successful=row["valid"])
            launch_available[variant] += int(isinstance(launch, dict) and launch.get("valid") is True)
            outcomes[variant].append(row["valid"] and row["exit_code"] == 0
                                     and not manifest.get("source_changed", False))
        expected_valid = len(runs) == batch["rounds"] and all(row["valid"] for row in runs)
        if manifest["valid"] != expected_valid:
            raise ValueError("manifest validity contradicts its completed outcomes")
        outcomes[variant].extend([False] * (batch["rounds"] - len(runs)))
    result = {}
    requested = plan["requested_per_variant"]
    for variant, values in outcomes.items():
        observed = len(values)
        successes = sum(values)
        result[variant] = {
            "requested": requested, "accounted": observed, "missing": requested - observed,
            "successful_valid_smoke_rounds": successes, "failed_or_incomplete": observed - successes,
            "success_fraction_of_requested": successes / requested,
            "wilson_95": wilson(successes, requested), "source": sources.get(variant),
            "failed_batches": failed_batches[variant],
            "execution_succeeded": observed == requested and successes == requested and not failed_batches[variant],
            "direct_at_10s": None, "first_business_ms": None, "application_p99_ms": None,
            "unavailable_reason": "normal matrix has no exact connection-start/real-TUN/application proof",
            "launch_identity_available_runs": launch_available[variant],
            "configuration_identity_scope": "argv_and_allowlisted_environment",
            "resolved_runtime_configuration_sha256": None,
            "resolved_runtime_configuration_unavailable_reason":
                "launch input identity excludes generated runtime configuration and stdin authorization",
            "unavailable_run_identity": ["resolved_runtime_configuration_sha256"] +
                ([] if launch_available[variant] == requested else
                 ["client_binary_sha256_at_launch", "server_binary_sha256_at_launch",
                  "configuration_input_sha256_at_launch"]),
        }
    return {"schema_version": 1, "scope": plan["scope"], "retries": 0, "variants": result,
            "complete": all(value["missing"] == 0 for value in result.values()),
            "complete_means": "all scheduled outcomes accounted for, including failed or absent manifests",
            "interpretation": "valid synthetic smoke outcomes; not independent networks or a performance improvement claim"}


def run_campaign(plan_path: Path, variant: str, output: Path, repository: Path = ROOT) -> int:
    plan = load_json(plan_path)
    validate_plan(plan)
    if variant not in plan["variants"]:
        raise ValueError("unknown variant")
    repository = repository.resolve(strict=True)
    if harness_identity(repository) != plan["harness"]:
        raise ValueError("repository harness differs from the frozen plan")
    runner = repository / RUNNER.relative_to(ROOT)
    output = external_new_path(output)
    output.mkdir(parents=True, mode=0o700)
    source = MATRIX.source_identity(repository)
    records = []
    campaign = {"schema_version": 1, "plan_sha256": digest(plan_path.read_bytes()),
                "variant": variant, "source": source, "records": records, "retries": 0,
                "harness": plan["harness"]}
    save_campaign(output / "campaign.json", campaign)
    for batch in plan["batches"]:
        if MATRIX.source_identity(repository) != source:
            raise ValueError("source changed during campaign; existing evidence is preserved")
        batch_output = output / batch["id"]
        command = [sys.executable, "-c", MATRIX_ENTRYPOINT, str(runner), "--scenario", batch["scenario"], "--rounds", str(batch["rounds"]),
                   "--seed", str(batch["runner_seed"]), "--output", str(batch_output)]
        with (output / (batch["id"] + ".log")).open("w") as stream:
            process = subprocess.Popen(command, cwd=repository, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=380 * batch["rounds"])
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                # The matrix owns a separate smoke process group. Let its
                # KeyboardInterrupt handler reap that group and seal partial
                # evidence before forcing the coordinator itself to exit.
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                code = 130 if isinstance(error, KeyboardInterrupt) else 124
        manifest_path = batch_output / "manifest.json"
        manifest = load_json(manifest_path) if manifest_path.exists() else None
        records.append({"variant": variant, "batch_id": batch["id"], "exit_code": code,
                        "manifest_path": str(manifest_path),
                        "manifest_sha256": digest(manifest_path.read_bytes()) if manifest_path.exists() else None,
                        "manifest": manifest})
        save_campaign(output / "campaign.json", campaign)
        if manifest is not None and manifest.get("source") != source:
            raise ValueError("batch source differs from the campaign checkout; evidence is preserved")
        print(f"{variant} {batch['id']}: exit={code}; failures retained", flush=True)
        if code == 130:
            return 130
    summary = summarize(plan, records)
    save(output / "summary.json", summary)
    values = summary["variants"][variant]
    return 0 if values["execution_succeeded"] else 1


def collect_campaign(path: Path, plan: dict, plan_sha256: str) -> list[dict]:
    campaign = load_json(path)
    if (type(campaign.get("schema_version")) is not int or campaign["schema_version"] != 1
            or campaign.get("plan_sha256") != plan_sha256
            or type(campaign.get("retries")) is not int or campaign["retries"] != 0
            or campaign.get("harness") != plan["harness"] or campaign.get("variant") not in plan["variants"]):
        raise ValueError("campaign differs from the frozen plan")
    expected = {batch["id"] for batch in plan["batches"]}
    for record in campaign["records"]:
        if record["variant"] != campaign["variant"] or record["batch_id"] not in expected:
            raise ValueError("record differs from its campaign variant or batch schedule")
        manifest_path = path.parent / record["batch_id"] / "manifest.json"
        if record.get("manifest_path") != str(manifest_path):
            raise ValueError("manifest path differs from its batch directory")
        if record.get("manifest_sha256") is None:
            if record.get("manifest_sha256") is not None or manifest_path.exists():
                raise ValueError("absent manifest evidence changed after collection")
            record["manifest"] = None
        else:
            manifest = load_json(manifest_path)
            if (digest(manifest_path.read_bytes()) != record["manifest_sha256"]
                    or ("manifest" in record and record["manifest"] != manifest)
                    or manifest.get("source") != campaign["source"]):
                raise ValueError("manifest digest, content or source differs from its campaign")
            record["manifest"] = manifest
        if record["manifest"] is not None:
            for index, row in enumerate(record["manifest"]["runs"]):
                profile = manifest_path.parent / f"{row['scenario']}-{index + 1}.profile.json"
                if (row.get("profile") != str(profile)
                        or row.get("profile_sha256") != digest(profile.read_bytes())
                        or row.get("network_profile") != load_json(profile)):
                    raise ValueError("raw network profile differs from the manifest")
                evidence_dir = manifest_path.parent / f"{row['scenario']}-{index + 1}"
                if row.get("evidence_dir") != str(evidence_dir):
                    raise ValueError("launch evidence path differs from its scheduled run directory")
                frozen_launch = row.get("launch_identity")
                validate_launch_summary(frozen_launch, campaign["source"], successful=row["valid"])
                reread_launch = read_launch_evidence(evidence_dir, campaign["source"])
                if frozen_launch is None:
                    if ((evidence_dir / "artifact-set.json").exists()
                            or (evidence_dir / "round-1" / "launches").exists()):
                        raise ValueError("absent launch identity changed after collection")
                elif reread_launch != frozen_launch:
                    raise ValueError("launch identity digest, content, artifact or source changed after collection")
    return campaign["records"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    planning = commands.add_parser("plan")
    planning.add_argument("--scenario", action="append", required=True, choices=MATRIX.SCENARIOS)
    planning.add_argument("--rounds", type=int, default=30)
    planning.add_argument("--seed", type=int, default=931200)
    planning.add_argument("--batch-size", type=int, default=32)
    planning.add_argument("--output", type=Path, required=True)
    running = commands.add_parser("run")
    running.add_argument("--plan", type=Path, required=True)
    running.add_argument("--variant", choices=("baseline", "candidate"), required=True)
    running.add_argument("--output", type=Path, required=True)
    running.add_argument("--repository", type=Path, default=ROOT,
                         help="baseline or candidate checkout with the identical frozen simulation harness")
    collecting = commands.add_parser("summarize")
    collecting.add_argument("--plan", type=Path, required=True)
    collecting.add_argument("--campaign", type=Path, action="append", required=True)
    collecting.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        os.umask(0o077)
        if args.action == "plan":
            plan = build_plan(args.scenario, args.rounds, args.seed, args.batch_size)
            output = external_new_path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            save(output, plan)
            print(f"frozen {plan['requested_per_variant']} rounds per variant in {len(plan['batches'])} batches")
            return 0
        if args.action == "run":
            return run_campaign(args.plan, args.variant, args.output, args.repository)
        plan = load_json(args.plan)
        records = []
        for path in args.campaign:
            records.extend(collect_campaign(path.resolve(), plan, digest(args.plan.read_bytes())))
        summary = summarize(plan, records)
        output = external_new_path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        save(output, summary)
        return 0 if summary["complete"] else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
