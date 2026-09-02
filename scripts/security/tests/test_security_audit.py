from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

SECURITY_DIR = Path(__file__).resolve().parents[1]
if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))

import aggregate_evidence
import credential_scan
import dependency_reports
import flutter_lock_policy
import flutter_outdated_triage
import verify_release_assets
import workflow_permissions


class WorkflowPermissionTests(unittest.TestCase):
    def write_workflow(self, root: Path, name: str, content: str) -> Path:
        path = root / ".github" / "workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_read_only_workflow_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
""",
            )
            self.assertEqual(workflow_permissions.run(root)["result"], "pass")

    def test_non_release_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on:
  push:
permissions:
  contents: write
jobs: {}
""",
            )
            evidence = workflow_permissions.run(root)
            self.assertTrue(
                any(
                    item["code"] == "write_permission_not_allowlisted"
                    for item in evidence["findings"]
                )
            )

    def test_release_write_passes_with_tag_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "release.yml",
                """name: Release
on:
  push:
    tags: ["v*"]
  workflow_dispatch:
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps: []
""",
            )
            self.assertEqual(workflow_permissions.run(root)["result"], "pass")

    def test_pull_request_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on:
  pull_request_target:
permissions:
  contents: read
jobs: {}
""",
            )
            evidence = workflow_permissions.run(root)
            self.assertTrue(
                any(
                    item["code"] == "pull_request_target_forbidden"
                    for item in evidence["findings"]
                )
            )

    def test_production_signing_secret_is_release_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on:
  push:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
        env:
          ANDROID_KEY_ALIAS: ${{ secrets.ANDROID_KEY_ALIAS }}
""",
            )
            evidence = workflow_permissions.run(root)
            self.assertTrue(
                any(
                    item["code"]
                    == "production_secret_outside_release_workflow"
                    for item in evidence["findings"]
                )
            )


class CredentialScanTests(unittest.TestCase):
    def test_high_confidence_token_and_xtrace_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "ghp_" + "abcdefghijklmnopqrstuvwxyz012345"
            (root / "script.sh").write_text(
                f"set -x\nTOKEN={token}\n", encoding="utf-8"
            )
            evidence = credential_scan.run(root)
            codes = {item["code"] for item in evidence["findings"]}
            self.assertIn("shell_xtrace", codes)
            self.assertIn("github_token", codes)

    def test_actions_secret_env_mapping_and_stdin_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.yml").write_text(
                """env:
  TOKEN: ${{ secrets.API_TOKEN }}
run: printf '%s\\n' "$TOKEN" | ./daemon --token-file /dev/stdin
""",
                encoding="utf-8",
            )
            self.assertEqual(credential_scan.run(root)["result"], "pass")

    def test_direct_actions_secret_interpolation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "unsafe.yml").write_text(
                "run: echo '${{ secrets.API_TOKEN }}'\n", encoding="utf-8"
            )
            evidence = credential_scan.run(root)
            self.assertTrue(
                any(
                    item["code"] == "direct_actions_secret_interpolation"
                    for item in evidence["findings"]
                )
            )

    def test_placeholder_private_key_is_not_real(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.dart").write_text(
                "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            self.assertEqual(credential_scan.run(root)["result"], "pass")

    def test_binary_plaintext_token_fails_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "ghp_" + "abcdefghijklmnopqrstuvwxyz012345"
            (root / "artifact.bin").write_bytes(token.encode())
            evidence = credential_scan.run(root, scan_binary=True)
            self.assertTrue(
                any(
                    item["code"] == "binary_github_token"
                    for item in evidence["findings"]
                )
            )


class FlutterPolicyTests(unittest.TestCase):
    def test_hosted_and_sdk_sources_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "pubspec.lock"
            lock.write_text(
                """packages:
  crypto:
    dependency: direct main
    description:
      name: crypto
      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      url: "https://pub.dev"
    source: hosted
    version: "3.0.7"
  flutter:
    dependency: direct main
    description: flutter
    source: sdk
    version: "0.0.0"
""",
                encoding="utf-8",
            )
            self.assertEqual(flutter_lock_policy.run(lock)["result"], "pass")

    def test_git_source_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "pubspec.lock"
            lock.write_text(
                """packages:
  unsafe_dep:
    dependency: direct main
    description: {}
    source: git
    version: "1.0.0"
""",
                encoding="utf-8",
            )
            self.assertEqual(flutter_lock_policy.run(lock)["result"], "fail")

    def write_outdated(self, root: Path, packages: list[dict]) -> Path:
        path = root / "outdated.json"
        path.write_text(json.dumps({"packages": packages}), encoding="utf-8")
        return path

    def test_transitive_drift_is_classified_not_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self.write_outdated(
                Path(tmp),
                [
                    {
                        "package": "material_color_utilities",
                        "kind": "transitive",
                        "current": {"version": "0.13.0"},
                        "resolvable": {"version": "0.13.0"},
                        "latest": {"version": "0.13.1"},
                    }
                ],
            )
            evidence = flutter_outdated_triage.run(report)
            self.assertEqual(evidence["result"], "pass")
            self.assertEqual(
                evidence["packages"][0]["classification"],
                "transitive_or_sdk_pinned",
            )

    def test_direct_resolvable_update_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self.write_outdated(
                Path(tmp),
                [
                    {
                        "package": "direct_dep",
                        "kind": "direct",
                        "current": {"version": "1.0.0"},
                        "resolvable": {"version": "1.1.0"},
                        "latest": {"version": "1.1.0"},
                    }
                ],
            )
            self.assertEqual(
                flutter_outdated_triage.run(report)["result"], "fail"
            )

    def test_discontinued_package_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self.write_outdated(
                Path(tmp),
                [
                    {
                        "package": "old_dep",
                        "kind": "transitive",
                        "current": {"version": "1.0.0"},
                        "latest": {"version": "1.0.0"},
                        "isDiscontinued": True,
                    }
                ],
            )
            self.assertEqual(
                flutter_outdated_triage.run(report)["result"], "fail"
            )


class ReleaseAssetTests(unittest.TestCase):
    def make_release(self, root: Path) -> tuple[Path, Path]:
        assets_dir = root / "assets"
        assets_dir.mkdir()
        names = [
            "p2wlan-flutter-android-arm64-release.apk",
            "p2wlan-flutter-ios-arm64-unsigned.ipa",
            "p2wlan-flutter-linux-x64.tar.gz",
            "p2wlan-flutter-macos-arm64.dmg",
            "p2wlan-flutter-macos-x64.dmg",
            "p2wlan-flutter-windows-x64-setup.exe",
            "p2wlan-linux-arm64-cli.tar.gz",
            "p2wlan-linux-x64-cli.tar.gz",
        ]
        assets = []
        for index, name in enumerate(names):
            content = f"asset-{index}".encode()
            path = assets_dir / name
            path.write_bytes(content)
            assets.append(
                {
                    "name": name,
                    "state": "uploaded",
                    "size": len(content),
                    "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                }
            )
        release = root / "release.json"
        release.write_text(
            json.dumps(
                {
                    "id": 1,
                    "tag_name": "v0.1.147",
                    "draft": False,
                    "prerelease": False,
                    "assets": assets,
                }
            ),
            encoding="utf-8",
        )
        return release, assets_dir

    def test_matching_release_assets_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release, assets = self.make_release(Path(tmp))
            self.assertEqual(
                verify_release_assets.run(release, assets)["result"], "pass"
            )

    def test_digest_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release, assets = self.make_release(Path(tmp))
            (assets / "p2wlan-linux-x64-cli.tar.gz").write_bytes(b"tampered")
            evidence = verify_release_assets.run(release, assets)
            self.assertTrue(
                any(
                    item["code"] == "asset_digest_mismatch"
                    for item in evidence["findings"]
                )
            )


class DependencyReportTests(unittest.TestCase):
    def test_go_summary_counts_unique_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            govuln = root / "govuln.jsonl"
            govuln.write_text(
                json.dumps({"finding": {"osv": "GO-2026-0001"}})
                + "\n"
                + json.dumps({"osv": {"id": "GO-2026-0002"}})
                + "\n",
                encoding="utf-8",
            )
            modules = root / "modules.json"
            modules.write_text(
                '{"Path":"a"}\n{"Path":"b"}\n', encoding="utf-8"
            )
            args = type(
                "Args",
                (),
                {
                    "mod_status": 0,
                    "test_status": 0,
                    "modules_status": 0,
                    "json_status": 0,
                    "vuln_status": 0,
                    "govulncheck_json": govuln,
                    "modules_json": modules,
                    "head_sha": "a" * 40,
                    "go_version": "go1.22.12",
                    "govulncheck_version": "v1.1.4",
                },
            )()
            evidence = dependency_reports.go_summary(args)
            self.assertEqual(evidence["module_count"], 2)
            self.assertEqual(evidence["vulnerability_count"], 2)

    def test_nonzero_scanner_status_is_not_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            govuln = root / "govuln.jsonl"
            govuln.write_text("", encoding="utf-8")
            modules = root / "modules.json"
            modules.write_text('{"Path":"a"}\n', encoding="utf-8")
            args = type(
                "Args",
                (),
                {
                    "mod_status": 0,
                    "test_status": 0,
                    "modules_status": 0,
                    "json_status": 3,
                    "vuln_status": 3,
                    "govulncheck_json": govuln,
                    "modules_json": modules,
                    "head_sha": "a" * 40,
                    "go_version": "go1.22.12",
                    "govulncheck_version": "v1.1.4",
                },
            )()
            evidence = dependency_reports.go_summary(args)
            self.assertEqual(evidence["result"], "fail")
            self.assertEqual(evidence["checks"]["govulncheck_gate"], 3)


class AggregateTests(unittest.TestCase):
    def test_all_required_pass_evidence_aggregates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename in aggregate_evidence.REQUIRED:
                (root / filename).write_text(
                    '{"result":"pass"}\n', encoding="utf-8"
                )
            evidence = aggregate_evidence.run(root, "a" * 40)
            self.assertEqual(evidence["result"], "pass")
            self.assertEqual(
                evidence["product_signing"]["notarization"],
                "deferred_non_blocking",
            )

    def test_missing_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                aggregate_evidence.run(Path(tmp), "a" * 40)["result"],
                "fail",
            )


if __name__ == "__main__":
    unittest.main()
