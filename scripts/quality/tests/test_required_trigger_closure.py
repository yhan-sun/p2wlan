"""Check authoritative trigger coverage against the actual same-head gate graph.

The workflows use literal paths and recursive directory prefixes. This test
accepts only that small filter language and fails on new YAML/filter syntax;
it does not approximate GitHub Actions with Python's different glob rules.
"""

import ast
import copy
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def _scalar(value):
    value = value.strip()
    if value[:1] in {"'", '"'}:
        parsed = ast.literal_eval(value)
        if not isinstance(parsed, str):
            raise ValueError("trigger entries must be strings")
        return parsed
    if not re.fullmatch(r"[A-Za-z0-9_./*-]+", value):
        raise ValueError(f"unsupported trigger scalar: {value!r}")
    return value


def _event(text, event):
    header = re.search(r"(?ms)^on:\n(.*?)(?=^[A-Za-z_][\w-]*:|\Z)", text)
    if header is None:
        raise ValueError("workflow has no block-style on section")
    match = re.search(rf"(?m)^  {event}:[ \t]*$", header[1])
    if match is None:
        raise ValueError(f"workflow has no block-style {event} event")
    rest = header[1][match.end():]
    end = re.search(r"(?m)^  [A-Za-z_][\w-]*:", rest)
    block = rest[:end.start()] if end else rest
    fields = {}
    lines = block.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        field = re.fullmatch(r"    ([\w-]+):[ \t]*(.*)", line)
        if field is None or field[1] not in {"branches", "paths"}:
            raise ValueError(f"unsupported {event} trigger line: {line!r}")
        key, inline = field.groups()
        if key in fields:
            raise ValueError(f"duplicate {key} trigger field")
        values = []
        if inline:
            if not inline.startswith("[") or not inline.endswith("]"):
                raise ValueError("trigger fields need a literal list")
            values = [_scalar(item) for item in inline[1:-1].split(",")]
        else:
            while index < len(lines):
                item = lines[index]
                if not item.strip() or item.lstrip().startswith("#"):
                    index += 1
                    continue
                value = re.fullmatch(r"      - (.+)", item)
                if value is None:
                    break
                values.append(_scalar(value[1]))
                index += 1
        if not values or len(values) != len(set(values)):
            raise ValueError(f"empty or duplicate {key} trigger list")
        fields[key] = tuple(values)
    if "branches" not in fields or "main" not in fields["branches"]:
        raise ValueError(f"{event} is not enabled on main")
    for pattern in fields.get("paths", ()):
        _pattern(pattern)
    return fields.get("paths")


def _pattern(pattern):
    recursive = pattern.endswith("/**")
    literal = pattern[:-3] if recursive else pattern
    if not literal or not re.fullmatch(r"[A-Za-z0-9_./-]+", literal):
        raise ValueError(f"unsupported path filter: {pattern!r}")
    return literal, recursive


def _covers(upstream, downstream):
    source, recursive = _pattern(upstream)
    target, target_recursive = _pattern(downstream)
    if target_recursive:
        return (recursive and source == target) or source.startswith(target + "/")
    return not recursive and source == target


def _matches(path, pattern):
    prefix, recursive = _pattern(pattern)
    return path.startswith(prefix + "/") if recursive else path == prefix


def _witnesses(pattern):
    prefix, recursive = _pattern(pattern)
    if recursive:
        return (prefix + "/trigger.rs", prefix + "/nested/deep/trigger.rs")
    return (prefix,)


def _gate_owners():
    source = ROOT / "scripts/quality/check_required_gates.py"
    tree = ast.parse(source.read_text())
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "GATE_WORKFLOWS"
    ]
    if len(nodes) != 1:
        raise ValueError("the required gate owner map must be one literal")
    owners = ast.literal_eval(nodes[0].value)
    if not isinstance(owners, dict) or not owners or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in owners.items()
    ):
        raise ValueError("invalid required gate owner map")
    return owners


def _workflows():
    result = {}
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = path.read_text()
        names = re.findall(r"^name: (.+)$", text, re.MULTILINE)
        if len(names) != 1 or names[0] in result:
            raise ValueError(f"missing or duplicate workflow name: {path}")
        required = re.findall(r'--require\s+"([^"\n]+)"', text)
        if len(required) != len(re.findall(r"--require\b", text)):
            raise ValueError(f"nonliteral required gate list: {path}")
        if len(required) != len(set(required)):
            raise ValueError(f"duplicate required gate: {path}")
        result[names[0]] = {"path": path, "text": text, "required": tuple(required)}
    return result


def _dependency_failures(workflows, owners):
    failures = []
    for consumer, source in workflows.items():
        if not source["required"]:
            continue
        upstream = _event(source["text"], "pull_request")
        if upstream is None:
            raise ValueError(f"unfiltered prerequisite consumer needs an explicit policy: {consumer}")
        for gate in source["required"]:
            owner = owners[gate]
            target = workflows[owner]
            for event in ("pull_request", "push"):
                downstream = _event(target["text"], event)
                if downstream is None:
                    continue
                for pattern in upstream:
                    # Containment proves the entire supported path language;
                    # shallow/deep witnesses additionally check event matching.
                    if not any(_covers(pattern, item) for item in downstream):
                        failures.append((consumer, owner, event, pattern))
                    for witness in _witnesses(pattern):
                        if not any(_matches(witness, item) for item in downstream):
                            failures.append((consumer, owner, event, witness))
    return failures


class RequiredTriggerClosureTests(unittest.TestCase):
    def test_prerequisite_path_languages_are_closed(self):
        self.assertEqual(_dependency_failures(_workflows(), _gate_owners()), [])

    def test_required_lists_keep_the_original_gate_counts(self):
        actual = {name: len(value["required"]) for name, value in _workflows().items() if value["required"]}
        self.assertEqual(actual, {
            "Business MTU Budget Required": 14,
            "DPLPMTUD Required": 17,
            "Path State Machine": 3,
        })

    def test_dependency_graph_has_real_owners_and_no_cycles(self):
        workflows, owners = _workflows(), _gate_owners()
        self.assertTrue(set(owners.values()) <= workflows.keys())
        graph = {name: {owners[gate] for gate in item["required"]} for name, item in workflows.items()}
        def visit(name, ancestors):
            self.assertNotIn(name, ancestors, f"same-head prerequisite cycle through {name}")
            for target in graph[name]:
                visit(target, ancestors | {name})
        for name in graph:
            visit(name, set())

    def test_workflow_only_changes_trigger_all_filtered_gate_owners(self):
        workflows, owners = _workflows(), _gate_owners()
        for owner in sorted(set(owners.values())):
            for event in ("pull_request", "push"):
                paths = _event(workflows[owner]["text"], event)
                if paths is None:
                    continue
                for changed in workflows.values():
                    relative = changed["path"].relative_to(ROOT).as_posix()
                    with self.subTest(owner=owner, event=event, changed=relative):
                        self.assertTrue(any(_matches(relative, item) for item in paths))

    def test_quality_changes_trigger_all_filtered_gate_owners(self):
        workflows, owners = _workflows(), _gate_owners()
        for owner in sorted(set(owners.values())):
            for event in ("pull_request", "push"):
                paths = _event(workflows[owner]["text"], event)
                if paths is None:
                    continue
                for path in (ROOT / "scripts/quality").rglob("*.py"):
                    relative = path.relative_to(ROOT).as_posix()
                    with self.subTest(owner=owner, event=event, changed=relative):
                        self.assertTrue(any(_matches(relative, item) for item in paths))

    def test_missing_relay_trigger_is_a_dependency_violation(self):
        workflows, owners = _workflows(), _gate_owners()
        mutated = copy.deepcopy(workflows)
        flutter = mutated["Flutter Client"]["text"]
        # Removing the actual recursive Relay entry recreates the PR199 gap.
        flutter = re.sub(r'^      - "client/relay/\*\*"\n', "", flutter, flags=re.MULTILINE)
        self.assertNotEqual(flutter, mutated["Flutter Client"]["text"])
        mutated["Flutter Client"]["text"] = flutter
        findings = _dependency_failures(mutated, owners)
        self.assertIn(("DPLPMTUD Required", "Flutter Client", "pull_request", "client/relay/**"), findings)

    def test_path_coverage_is_directional_and_recursive(self):
        self.assertTrue(_covers("client/relay/**", "client/**"))
        self.assertFalse(_covers("client/**", "client/relay/**"))
        self.assertFalse(_covers("client/relay/**", "client/relay/src/client.rs"))
        self.assertTrue(_covers("client/relay/src/client.rs", "client/relay/**"))
        self.assertFalse(_matches("client/relay-other/client.rs", "client/relay/**"))
        self.assertTrue(_matches("client/relay/a/b/client.rs", "client/relay/**"))

    def test_unsupported_trigger_filters_fail_closed(self):
        for pattern in ("!client/relay/**", "client/*/src/**", "client/relay?.rs", "[ab].rs"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                _pattern(pattern)
        with self.assertRaises(ValueError):
            _event("on:\n  pull_request:\n    branches: [main]\n    paths-ignore:\n      - 'client/**'\n", "pull_request")


if __name__ == "__main__":
    unittest.main()
