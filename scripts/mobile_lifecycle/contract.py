#!/usr/bin/env python3
"""Load and validate the single mobile lifecycle contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONTRACT_PATH = Path(__file__).resolve().parents[2] / "contracts" / "mobile_lifecycle.json"
SCHEMA_VERSION = 2
REPOSITORY = "yhan-sun/p2wlan"
COMPONENTS = ("flutter", "android_jvm", "rust")
OUTCOMES = ("applied", "duplicate", "stale_rejected", "superseded", "failed")
FORBIDDEN_OUTCOMES = ("skipped", "assumed", "manually_verified", "deferred")


class ContractError(ValueError):
    """Raised when the canonical contract is malformed."""


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read lifecycle contract {path}: {error}") from error
    if not isinstance(value, dict):
        raise ContractError("lifecycle contract must be a JSON object")
    validate_contract(value)
    return value


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != SCHEMA_VERSION:
        raise ContractError("lifecycle contract schema_version must be 2")
    if contract.get("repository") != REPOSITORY:
        raise ContractError("lifecycle contract repository is not yhan-sun/p2wlan")
    for key in ("events", "outcomes", "forbidden_outcomes", "identity_fields", "components", "required_scenarios"):
        if not isinstance(contract.get(key), list) or not contract[key]:
            raise ContractError(f"lifecycle contract {key} must be a non-empty array")
    if tuple(contract["components"]) != COMPONENTS:
        raise ContractError("lifecycle contract components are not canonical")
    if tuple(contract["outcomes"]) != OUTCOMES:
        raise ContractError("lifecycle contract outcomes are not canonical")
    if tuple(contract["forbidden_outcomes"]) != FORBIDDEN_OUTCOMES:
        raise ContractError("lifecycle contract forbidden outcomes are not canonical")
    if any(not isinstance(event, str) or not event for event in contract["events"]):
        raise ContractError("lifecycle contract events must be non-empty strings")
    if len(set(contract["outcomes"])) != len(contract["outcomes"]):
        raise ContractError("lifecycle contract has duplicate outcomes")
    if len(set(contract["forbidden_outcomes"])) != len(contract["forbidden_outcomes"]):
        raise ContractError("lifecycle contract has duplicate forbidden outcomes")
    if set(contract["outcomes"]) & set(contract["forbidden_outcomes"]):
        raise ContractError("lifecycle contract outcomes and forbidden outcomes overlap")
    if len(set(contract["events"])) != len(contract["events"]):
        raise ContractError("lifecycle contract has duplicate events")
    if len(set(contract["identity_fields"])) != len(contract["identity_fields"]):
        raise ContractError("lifecycle contract has duplicate identity fields")
    if any(not isinstance(field, str) or not field for field in contract["identity_fields"]):
        raise ContractError("lifecycle contract identity fields must be non-empty strings")

    scenarios = contract["required_scenarios"]
    if len(scenarios) != 18:
        raise ContractError("lifecycle contract must contain exactly 18 required scenarios")
    ids: list[str] = []
    names: list[str] = []
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ContractError("required scenario must be an object")
        scenario_id = scenario.get("id")
        name = scenario.get("name")
        authorities = scenario.get("authoritative_components")
        if not isinstance(scenario_id, str) or not scenario_id.startswith("ML-"):
            raise ContractError("required scenario has an invalid id")
        if not isinstance(name, str) or not name:
            raise ContractError(f"{scenario_id} has no name")
        if not isinstance(authorities, list) or not authorities:
            raise ContractError(f"{scenario_id} has no authoritative component")
        if any(component not in COMPONENTS for component in authorities):
            raise ContractError(f"{scenario_id} names an unknown component")
        if len(set(authorities)) != len(authorities):
            raise ContractError(f"{scenario_id} repeats an authoritative component")
        if scenario.get("required_decision") not in OUTCOMES:
            raise ContractError(f"{scenario_id} has no canonical required decision")
        required_invariants = scenario.get("required_invariants")
        if not isinstance(required_invariants, list) or not required_invariants:
            raise ContractError(f"{scenario_id} has no required invariants")
        if any(not isinstance(item, str) or not item for item in required_invariants):
            raise ContractError(f"{scenario_id} has an invalid required invariant")
        if len(set(required_invariants)) != len(required_invariants):
            raise ContractError(f"{scenario_id} repeats a required invariant")
        ids.append(scenario_id)
        names.append(name)
    if ids != [f"ML-{index:02d}" for index in range(1, 19)]:
        raise ContractError("required scenario IDs must be ML-01 through ML-18 in order")
    if len(set(names)) != len(names):
        raise ContractError("required scenario names must be unique")


def scenarios_by_id(contract: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    value = contract or load_contract()
    return {scenario["id"]: scenario for scenario in value["required_scenarios"]}
