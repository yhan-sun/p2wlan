#!/usr/bin/env python3
"""Bind each final exec to private artifact bytes and hashed launch inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time


MAX_JSON_BYTES = 128 * 1024
MAX_RECORDS = 128
COMPONENTS = {"daemon", "control", "relay", "udp-shim"}
REQUIRED_ROLES = ["control", "relay-1", "node-a", "node-b"]
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict:
    information = path.lstat()
    if not stat.S_ISREG(information.st_mode) or information.st_size > MAX_JSON_BYTES:
        raise ValueError("launch_json_not_regular_or_bounded")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("launch_json_not_object")
    return value


def validate_source(value: object) -> None:
    if (not isinstance(value, dict) or set(value) != {"commit", "patch_sha256"}
            or not isinstance(value["commit"], str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value["commit"])
            or not isinstance(value["patch_sha256"], str) or not SHA256.fullmatch(value["patch_sha256"])):
        raise ValueError("launch_source_invalid")


def source_identity(root: Path) -> dict:
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root)
    digest = hashlib.sha256(git("diff", "--binary", "HEAD"))
    for name in sorted(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
        if name:
            digest.update(name + b"\0")
            digest.update((root / os.fsdecode(name)).read_bytes())
    return {"commit": git("rev-parse", "HEAD").decode().strip(), "patch_sha256": digest.hexdigest()}


def write_new(path: Path, value: dict) -> None:
    payload = canonical(value) + b"\n"
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("launch_json_too_large")
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)


def prepare_artifacts(base_dir: Path, binaries: dict[str, Path], source: dict) -> dict:
    """Copy completed builds once; every later exec uses these retained bytes."""
    validate_source(source)
    if not binaries or set(binaries) - COMPONENTS:
        raise ValueError("launch_components_invalid")
    destination = base_dir / "artifacts"
    destination.mkdir(mode=0o700)
    artifacts = {}
    for component, executable in sorted(binaries.items()):
        target = destination / component
        with executable.open("rb") as incoming, target.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            os.fchmod(outgoing.fileno(), 0o500)
        artifacts[component] = {"path": f"artifacts/{component}", "sha256": digest_file(target),
                                "size_bytes": target.stat().st_size}
        validate_artifact(artifacts[component], component)
    result = {"schema_version": 1, "source": source, "artifacts": artifacts}
    write_new(base_dir / "artifact-set.json", result)
    return result


def configuration_identity(argv: list[str], environment: dict[str, str], environment_keys: list[str],
                           *, config_file: Path | None = None, stdin_authorization: bool = False) -> dict:
    """Hash the actual inputs without reading stdin or retaining raw configuration."""
    if (not isinstance(argv, list) or len(argv) > 256
            or not all(isinstance(argument, str) and len(argument) <= 65536 for argument in argv)
            or not isinstance(environment_keys, list) or len(environment_keys) > 64
            or not all(isinstance(key, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key)
                       for key in environment_keys)
            or type(stdin_authorization) is not bool):
        raise ValueError("launch_configuration_inputs_invalid")
    keys = sorted(set(environment_keys))
    inputs = {key: environment.get(key) for key in keys}
    if any(value is not None and (not isinstance(value, str) or len(value) > 65536)
           for value in inputs.values()):
        raise ValueError("launch_environment_input_invalid")
    file_identity = {"state": "not_supplied", "sha256": None}
    excluded = ["stdin_authorization"] if stdin_authorization else []
    if config_file is not None:
        if config_file.exists():
            if config_file.is_symlink() or not config_file.is_file() or config_file.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("launch_configuration_file_invalid")
            file_identity = {"state": "present_at_launch", "sha256": digest_file(config_file)}
        else:
            file_identity["state"] = "absent_at_launch"
            excluded.append("generated_runtime_configuration")
    source, scope = "cli_and_controlled_environment", "argv_and_allowlisted_environment"
    digest = hashlib.sha256(canonical({"source": source, "scope": scope, "argv": argv,
        "environment": inputs, "config_file": file_identity, "excluded_inputs": sorted(excluded)})).hexdigest()
    return {"source": source, "scope": scope, "sha256": digest, "argument_count": len(argv),
            "environment_keys": keys, "config_file": file_identity, "excluded_inputs": sorted(excluded)}


def validate_artifact(value: object, component: str) -> None:
    if (not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}
            or value["path"] != f"artifacts/{component}"
            or not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"])
            or type(value["size_bytes"]) is not int or value["size_bytes"] <= 0):
        raise ValueError("launch_artifact_identity_invalid")


def validate_artifact_set(value: object) -> None:
    if (not isinstance(value, dict) or set(value) != {"schema_version", "source", "artifacts"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["artifacts"], dict) or not value["artifacts"]
            or set(value["artifacts"]) - COMPONENTS):
        raise ValueError("launch_artifact_set_invalid")
    validate_source(value["source"])
    for component, artifact in value["artifacts"].items():
        validate_artifact(artifact, component)


def verify_snapshot(base_dir: Path, component: str, artifact: dict) -> Path:
    validate_artifact(artifact, component)
    path = base_dir / artifact["path"]
    information = path.lstat()
    if (not stat.S_ISREG(information.st_mode) or information.st_size != artifact["size_bytes"]
            or stat.S_IMODE(information.st_mode) != 0o500
            or path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700
            or digest_file(path) != artifact["sha256"]):
        raise ValueError("launch_artifact_changed")
    return path


def role_component(role: str) -> str:
    if not isinstance(role, str):
        raise ValueError("launch_role_invalid")
    if role in {"node-a", "node-b"}:
        return "daemon"
    if role == "control":
        return "control"
    if isinstance(role, str) and re.fullmatch(r"relay-[1-9][0-9]{0,2}(?:-restart-[1-9][0-9]{0,2})?", role):
        return "relay"
    raise ValueError("launch_role_invalid")


def validate_configuration(value: object) -> None:
    keys = {"source", "scope", "sha256", "argument_count", "environment_keys", "config_file", "excluded_inputs"}
    if (not isinstance(value, dict) or set(value) != keys
            or value["source"] != "cli_and_controlled_environment"
            or value["scope"] != "argv_and_allowlisted_environment"
            or not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"])
            or type(value["argument_count"]) is not int or not 0 <= value["argument_count"] <= 256):
        raise ValueError("launch_configuration_identity_invalid")
    names, excluded = value["environment_keys"], value["excluded_inputs"]
    if (not isinstance(names, list) or len(names) > 64
            or not all(isinstance(name, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name) for name in names)
            or names != sorted(set(names)) or not isinstance(excluded, list)
            or not all(isinstance(name, str) for name in excluded)
            or excluded != sorted(set(excluded))
            or set(excluded) - {"stdin_authorization", "generated_runtime_configuration"}):
        raise ValueError("launch_configuration_scope_invalid")
    file = value["config_file"]
    if (not isinstance(file, dict) or set(file) != {"state", "sha256"}
            or not isinstance(file["state"], str)
            or file["state"] not in {"not_supplied", "absent_at_launch", "present_at_launch"}
            or (file["state"] == "present_at_launch"
                and (not isinstance(file["sha256"], str) or not SHA256.fullmatch(file["sha256"])))
            or (file["state"] != "present_at_launch" and file["sha256"] is not None)
            or (file["state"] == "absent_at_launch") != ("generated_runtime_configuration" in excluded)):
        raise ValueError("launch_configuration_file_identity_invalid")


def validate_record(value: object, source: dict) -> None:
    required = {"schema_version", "source", "role", "component", "state", "pid", "monotonic_ns",
                "artifact_set_sha256", "artifact", "configuration"}
    if (not isinstance(value, dict) or set(value) not in (required, required | {"exec_errno"})
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["state"], str)
            or value["state"] not in {"exec_requested", "exec_failed"}
            or type(value["pid"]) is not int or value["pid"] <= 0
            or type(value["monotonic_ns"]) is not int or value["monotonic_ns"] <= 0
            or not isinstance(value["artifact_set_sha256"], str)
            or not SHA256.fullmatch(value["artifact_set_sha256"])):
        raise ValueError("launch_record_invalid")
    validate_source(value["source"])
    if value["source"] != source or role_component(value["role"]) != value["component"]:
        raise ValueError("launch_source_or_role_mismatch")
    if (value["state"] == "exec_failed") != ("exec_errno" in value):
        raise ValueError("launch_exec_failure_invalid")
    if "exec_errno" in value and (type(value["exec_errno"]) is not int or value["exec_errno"] <= 0):
        raise ValueError("launch_exec_failure_invalid")
    validate_artifact(value["artifact"], value["component"])
    validate_configuration(value["configuration"])


def exec_launch(artifact_set: Path, component: str, record_path: Path, role: str,
                arguments: list[str], environment_keys: list[str], *,
                config_file: Path | None = None, stdin_authorization: bool = False) -> None:
    artifacts = load_object(artifact_set)
    validate_artifact_set(artifacts)
    if component != role_component(role) or component not in artifacts["artifacts"]:
        raise ValueError("launch_component_missing_or_wrong_role")
    snapshots = {name: verify_snapshot(artifact_set.parent, name, artifact)
                 for name, artifact in artifacts["artifacts"].items()}
    executable = snapshots[component]
    # The shim has already exec'd this wrapper. Hash its final controlled
    # environment here, and exec the declared artifact itself as the same PID.
    environment = os.environ.copy()
    configuration = configuration_identity(arguments, environment, environment_keys,
        config_file=config_file, stdin_authorization=stdin_authorization)
    record = {"schema_version": 1, "source": artifacts["source"], "role": role, "component": component,
              "state": "exec_requested", "pid": os.getpid(), "monotonic_ns": time.monotonic_ns(),
              "artifact_set_sha256": digest_file(artifact_set), "artifact": artifacts["artifacts"][component],
              "configuration": configuration}
    validate_record(record, artifacts["source"])
    write_new(record_path, record)
    try:
        os.execve(str(executable), [str(executable), *arguments], environment)
    except OSError as error:
        # No successful exec occurred. Keep a typed failure at the same record;
        # a missing process must not be upgraded to successful launch evidence.
        record.update(state="exec_failed", exec_errno=error.errno or 5)
        record_path.write_bytes(canonical(record) + b"\n")
        raise


def read_launch_evidence(base_dir: Path, expected_source: dict | None = None,
                         expected_roles: list[str] | None = None) -> dict:
    roles = list(REQUIRED_ROLES if expected_roles is None else expected_roles)
    records, errors, artifacts, set_identity = [], [], None, None
    source = expected_source
    try:
        artifacts = load_object(base_dir / "artifact-set.json")
        validate_artifact_set(artifacts)
        source = artifacts["source"] if source is None else source
        validate_source(source)
        if artifacts["source"] != source:
            raise ValueError("launch_source_mismatch")
        set_identity = {"path": "artifact-set.json", "sha256": digest_file(base_dir / "artifact-set.json")}
        for component, artifact in artifacts["artifacts"].items():
            verify_snapshot(base_dir, component, artifact)
    except (OSError, ValueError, TypeError, KeyError):
        errors.append("artifact_set_missing_invalid_or_changed")
    directory = base_dir / "round-1" / "launches"
    paths = sorted(directory.glob("*.json")) if directory.is_dir() and not directory.is_symlink() else []
    if len(paths) > MAX_RECORDS:
        errors.append("launch_record_limit_exceeded")
        paths = []
    seen = set()
    for path in paths:
        try:
            record = load_object(path)
            validate_record(record, source)
            role = record["role"]
            if path.name != f"{role}.json" or role in seen:
                raise ValueError("launch_role_duplicate_or_filename_mismatch")
            seen.add(role)
            if (artifacts is None or set_identity is None
                    or record["artifact_set_sha256"] != set_identity["sha256"]
                    or record["artifact"] != artifacts["artifacts"].get(record["component"])):
                raise ValueError("launch_artifact_set_mismatch")
            if record["state"] != "exec_requested":
                errors.append(f"exec_failed:{role}")
            records.append({"path": f"round-1/launches/{path.name}", "sha256": digest_file(path), "record": record})
        except (OSError, ValueError, TypeError, KeyError):
            errors.append(f"record_invalid_or_changed:{path.name}")
    errors.extend(f"missing_required_role:{role}" for role in roles if role not in seen)
    return {"schema_version": 1, "valid": not errors, "errors": errors, "source": source,
            "expected_roles": roles, "artifact_set": set_identity, "records": records}


def validate_launch_summary(value: object, source: dict, *, successful: bool) -> None:
    """Validate frozen metadata; collection additionally re-reads its raw files."""
    if value is None and not successful:
        return  # A pre-launch failure remains a failed scheduled outcome.
    required = {"schema_version", "valid", "errors", "source", "expected_roles", "artifact_set", "records"}
    if (not isinstance(value, dict) or set(value) != required or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or type(value.get("valid")) is not bool
            or not isinstance(value.get("errors"), list)
            or len(value["errors"]) > MAX_RECORDS + len(REQUIRED_ROLES) + 1
            or not all(isinstance(error, str) and len(error) <= 512 for error in value["errors"])
            or value["valid"] != (not value["errors"]) or not isinstance(value.get("records"), list)
            or len(value["records"]) > MAX_RECORDS or (successful and not value["valid"])):
        raise ValueError("launch_identity_invalid_or_missing")
    if value.get("source") != source or value.get("expected_roles") != REQUIRED_ROLES:
        raise ValueError("launch_identity_source_or_roles_mismatch")
    artifact_set = value.get("artifact_set")
    if artifact_set is None and not value["valid"] and not value["records"]:
        return  # Missing launch files preserve the scheduled failure denominator.
    if (not isinstance(artifact_set, dict) or set(artifact_set) != {"path", "sha256"}
            or artifact_set["path"] != "artifact-set.json" or not isinstance(artifact_set["sha256"], str)
            or not SHA256.fullmatch(artifact_set["sha256"])):
        raise ValueError("launch_identity_artifact_set_invalid")
    seen = set()
    for entry in value["records"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "sha256", "record"}
                or not isinstance(entry["sha256"], str) or not SHA256.fullmatch(entry["sha256"])):
            raise ValueError("launch_identity_record_digest_invalid")
        validate_record(entry["record"], source)
        record, role = entry["record"], entry["record"]["role"]
        if (role in seen or entry["path"] != f"round-1/launches/{role}.json"
                or record["artifact_set_sha256"] != artifact_set["sha256"]
                or (value["valid"] and record["state"] != "exec_requested")):
            raise ValueError("launch_identity_record_mismatch")
        seen.add(role)
    if value["valid"] and not set(REQUIRED_ROLES) <= seen:
        raise ValueError("launch_identity_required_roles_missing")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    sourcing = commands.add_parser("source")
    sourcing.add_argument("--repository", type=Path, required=True)
    sourcing.add_argument("--output", type=Path, required=True)
    preparing = commands.add_parser("prepare")
    preparing.add_argument("--base-dir", type=Path, required=True)
    preparing.add_argument("--source-file", type=Path, required=True)
    preparing.add_argument("--repository", type=Path, required=True)
    for component in sorted(COMPONENTS):
        preparing.add_argument(f"--{component}", type=Path)
    execution = commands.add_parser("exec")
    execution.add_argument("--artifact-set", type=Path, required=True)
    execution.add_argument("--component", choices=sorted(COMPONENTS), required=True)
    execution.add_argument("--record", type=Path, required=True)
    execution.add_argument("--role", required=True)
    execution.add_argument("--env-key", action="append", default=[])
    execution.add_argument("--config-file", type=Path)
    execution.add_argument("--stdin-authorization", action="store_true")
    execution.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.action == "source":
            write_new(args.output, source_identity(args.repository))
        elif args.action == "prepare":
            source = load_object(args.source_file)
            if source_identity(args.repository) != source:
                raise ValueError("launch_source_changed_during_build")
            binaries = {component: getattr(args, component.replace("-", "_")) for component in COMPONENTS
                        if getattr(args, component.replace("-", "_")) is not None}
            prepare_artifacts(args.base_dir, binaries, source)
        else:
            arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
            exec_launch(args.artifact_set, args.component, args.record, args.role, arguments, args.env_key,
                        config_file=args.config_file, stdin_authorization=args.stdin_authorization)
    except (OSError, ValueError, TypeError, KeyError) as error:
        # Error text and launch inputs can contain credentials. Emit type only.
        print(f"launch_identity_failure:{type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
