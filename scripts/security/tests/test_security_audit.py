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
import workflow_check_contract
import workflow_permissions


HEAD_SHA = "a" * 40
WORKFLOW_SHA = "b" * 40
NEEDS_SUCCESS = {
    "repository-policy": "success",
    "rust-dependencies": "success",
    "go-dependencies": "success",
    "flutter-dependencies": "success",
    "release-assets": "success",
}


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
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
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
                any(item["code"] == "write_permission_not_allowlisted" for item in evidence["findings"])
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
                any(item["code"] == "pull_request_target_forbidden" for item in evidence["findings"])
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
                any(item["code"] == "production_secret_outside_release_workflow" for item in evidence["findings"])
            )

    def test_floating_action_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
            )
            evidence = workflow_permissions.run(root)
            self.assertTrue(any(item["code"] == "floating_action_reference" for item in evidence["findings"]))

    def test_untrusted_shell_interpolation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          printf '%s' "${{ github.event.pull_request.title }}"
""",
            )
            evidence = workflow_permissions.run(root)
            self.assertTrue(any(item["code"] == "untrusted_shell_interpolation" for item in evidence["findings"]))

    def test_remote_shell_pipe_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "ci.yml",
                """name: CI
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.invalid/install.sh | sh
""",
            )
            evidence = workflow_permissions.run(root)
            self.assertTrue(any(item["code"] == "remote_shell_pipe" for item in evidence["findings"]))


class CredentialScanTests(unittest.TestCase):
    def test_high_confidence_token_and_xtrace_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "ghp_" + "abcdefghijklmnopqrstuvwxyz012345"
            (root / "script.sh").write_text(f"set -x\nTOKEN={token}\n", encoding="utf-8")
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
            (root / "unsafe.yml").write_text("run: echo '${{ secrets.API_TOKEN }}'\n", encoding="utf-8")
            evidence = credential_scan.run(root)
            self.assertTrue(any(item["code"] == "direct_actions_secret_interpolation" for item in evidence["findings"]))

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
            self.assertTrue(any(item["code"] == "binary_github_token" for item in evidence["findings"]))

    def test_sensitive_key_filename_fails_even_when_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "id_rsa").write_bytes(b"not-a-real-key")
            evidence = credential_scan.run(root)
            self.assertTrue(any(item["code"] == "tracked_sensitive_file" for item in evidence["findings"]))

    def test_empty_scan_scope_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = credential_scan.run(Path(tmp))
            self.assertTrue(any(item["code"] == "empty_scan_scope" for item in evidence["findings"]))
            self.assertEqual(evidence["result"], "fail")

    def test_empty_workflow_scope_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = workflow_permissions.run(Path(tmp))
            self.assertTrue(any(item["code"] == "workflow_scope_empty" for item in evidence["findings"]))
            self.assertEqual(evidence["result"], "fail")

    def test_remote_shell_pipe_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "install.sh").write_text("curl https://example.invalid/x | sh\n", encoding="utf-8")
            evidence = credential_scan.run(root)
            self.assertTrue(any(item["code"] == "remote_shell_pipe" for item in evidence["findings"]))


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

    def test_manifest_override_and_path_source_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / "pubspec.lock"
            lock.write_text(
                """packages:
  safe:
    description:
      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      url: https://pub.dev
    source: hosted
    version: 1.0.0
""",
                encoding="utf-8",
            )
            manifest = root / "pubspec.yaml"
            manifest.write_text(
                """dependencies:
  local:
    path: ../local
dependency_overrides:
  safe: 1.0.1
""",
                encoding="utf-8",
            )
            evidence = flutter_lock_policy.run(lock, manifest=manifest)
            codes = {item["code"] for item in evidence["findings"]}
            self.assertIn("dependency_override", codes)
            self.assertIn("untrusted_manifest_source", codes)

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
            self.assertEqual(evidence["packages"][0]["classification"], "transitive_or_sdk_pinned")

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
            self.assertEqual(flutter_outdated_triage.run(report)["result"], "fail")

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
            self.assertEqual(flutter_outdated_triage.run(report)["result"], "fail")

    def test_advisory_affected_package_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self.write_outdated(
                Path(tmp),
                [
                    {
                        "package": "affected_dep",
                        "kind": "transitive",
                        "current": {"version": "1.0.0"},
                        "latest": {"version": "1.0.0"},
                        "isCurrentAffectedByAdvisory": True,
                    }
                ],
            )
            evidence = flutter_outdated_triage.run(report)
            self.assertEqual(evidence["result"], "fail")
            self.assertEqual(
                evidence["packages"][0]["classification"],
                "current_version_affected_by_advisory",
            )

    def test_malformed_outdated_package_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = self.write_outdated(Path(tmp), [None])
            evidence = flutter_outdated_triage.run(report)
            self.assertEqual(evidence["result"], "fail")
            self.assertTrue(any(item["code"] == "invalid_package_record" for item in evidence["findings"]))


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
            self.assertEqual(verify_release_assets.run(release, assets)["result"], "pass")

    def test_digest_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release, assets = self.make_release(Path(tmp))
            (assets / "p2wlan-linux-x64-cli.tar.gz").write_bytes(b"tampered")
            evidence = verify_release_assets.run(release, assets)
            self.assertTrue(any(item["code"] == "asset_digest_mismatch" for item in evidence["findings"]))

    def test_checksum_sidecar_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release, assets = self.make_release(root)
            name = "p2wlan-linux-x64-cli.tar.gz"
            product = assets / name
            sidecar_name = f"{name}.sha256"
            sidecar_content = f"{hashlib.sha256(product.read_bytes()).hexdigest()}  {name}\n".encode()
            (assets / sidecar_name).write_bytes(sidecar_content)
            payload = json.loads(release.read_text(encoding="utf-8"))
            payload["assets"].append(
                {
                    "name": sidecar_name,
                    "state": "uploaded",
                    "size": len(sidecar_content),
                    "digest": f"sha256:{hashlib.sha256(sidecar_content).hexdigest()}",
                }
            )
            release.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(verify_release_assets.run(release, assets)["result"], "pass")

    def test_checksum_sidecar_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release, assets = self.make_release(root)
            name = "p2wlan-linux-x64-cli.tar.gz"
            product = assets / name
            (assets / f"{name}.sha256").write_text(f"{'0' * 64}  {name}\n", encoding="utf-8")
            payload = json.loads(release.read_text(encoding="utf-8"))
            payload["assets"].append(
                {
                    "name": f"{name}.sha256",
                    "state": "uploaded",
                    "size": (assets / f"{name}.sha256").stat().st_size,
                    "digest": f"sha256:{hashlib.sha256((assets / f'{name}.sha256').read_bytes()).hexdigest()}",
                }
            )
            release.write_text(json.dumps(payload), encoding="utf-8")
            evidence = verify_release_assets.run(release, assets)
            self.assertTrue(any(item["code"] == "checksum_sidecar_mismatch" for item in evidence["findings"]))

    def test_asset_path_traversal_fails_without_reading_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release, assets = self.make_release(root)
            payload = json.loads(release.read_text(encoding="utf-8"))
            payload["assets"][0]["name"] = "../outside"
            release.write_text(json.dumps(payload), encoding="utf-8")
            evidence = verify_release_assets.run(release, assets)
            self.assertTrue(any(item["code"] == "unsafe_asset_name" for item in evidence["findings"]))


class DependencyReportTests(unittest.TestCase):
    def advisory_exception(self, advisory_id: str = "RUSTSEC-2024-0429") -> dict[str, object]:
        return {
            "advisory_id": advisory_id,
            "package": "glib",
            "affected_version": "0.18.5",
            "dependency_path": "p2wlan-tray -> tao -> tray-icon -> libappindicator -> glib",
            "status": "temporary_exception",
            "rationale": "GTK3 tray backend cannot consume the fixed glib release yet.",
            "mitigation": "Keep the tray opt-in and revisit the backend before the review date.",
            "tracking_issue": 52,
            "review_by": "2099-09-30",
        }

    def rust_args(
        self,
        root: Path,
        *,
        deny_config: Path | None = None,
        advisory_exceptions: Path | None = None,
    ) -> object:
        audit = root / "audit.json"
        audit.write_text('{"vulnerabilities":{"count":0},"warnings":{}}', encoding="utf-8")
        fuzz_audit = root / "fuzz-audit.json"
        fuzz_audit.write_text(audit.read_text(encoding="utf-8"), encoding="utf-8")
        deny = root / "deny.jsonl"
        deny.write_text("", encoding="utf-8")
        fuzz_deny = root / "fuzz-deny.jsonl"
        fuzz_deny.write_text("", encoding="utf-8")
        return type(
            "Args",
            (),
            {
                "root_audit": audit,
                "fuzz_audit": fuzz_audit,
                "root_deny": deny,
                "fuzz_deny": fuzz_deny,
                "deny_config": deny_config or root / "deny.toml",
                "advisory_exceptions": advisory_exceptions or root / "advisory-exceptions.json",
                "root_audit_status": 0,
                "fuzz_audit_status": 0,
                "root_deny_status": 0,
                "fuzz_deny_status": 0,
                "head_sha": HEAD_SHA,
                "cargo_audit_version": "cargo-audit 0.22.2",
                "cargo_deny_version": "cargo-deny 0.20.2",
            },
        )()

    def write_rust_contract(
        self,
        root: Path,
        *,
        ignored: list[str] | None = None,
        exceptions: list[dict[str, object]] | None = None,
    ) -> tuple[Path, Path]:
        deny = root / "deny.toml"
        deny.write_text(
            "[advisories]\nignore = " + json.dumps(ignored or ["RUSTSEC-2024-0429"]) + "\n",
            encoding="utf-8",
        )
        metadata = root / "advisory-exceptions.json"
        metadata.write_text(
            json.dumps({"exceptions": exceptions or [self.advisory_exception()]}),
            encoding="utf-8",
        )
        return deny, metadata

    def test_rust_report_reads_deny_and_emits_current_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.rust_args(
                root,
                deny_config=SECURITY_DIR.parents[1] / "deny.toml",
                advisory_exceptions=SECURITY_DIR.parents[1] / "security" / "advisory-exceptions.json",
            )
            evidence = dependency_reports.rust_summary(args)
            self.assertEqual(evidence["result"], "pass")
            self.assertEqual(evidence["advisory_exception_count"], 1)
            self.assertEqual(evidence["advisory_exception_ids"], ["RUSTSEC-2024-0429"])
            self.assertEqual(evidence["advisory_ignores"][0]["package"], "glib")
            self.assertEqual(evidence["advisory_ignores"][0]["tracking_issue"], 52)

    def test_rust_deny_ignore_without_metadata_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deny, metadata = self.write_rust_contract(root)
            metadata.unlink()
            evidence = dependency_reports.rust_summary(
                self.rust_args(root, deny_config=deny, advisory_exceptions=metadata)
            )
            self.assertEqual(evidence["result"], "fail")
            self.assertIn(
                "advisory_exception_metadata_invalid",
                {item["code"] for item in evidence["findings"]},
            )

    def test_rust_metadata_extra_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deny, metadata = self.write_rust_contract(
                root,
                exceptions=[self.advisory_exception(), self.advisory_exception("RUSTSEC-EXTRA")],
            )
            evidence = dependency_reports.rust_summary(
                self.rust_args(root, deny_config=deny, advisory_exceptions=metadata)
            )
            self.assertEqual(evidence["result"], "fail")
            self.assertIn(
                "advisory_exception_metadata_extra_id",
                {item["code"] for item in evidence["findings"]},
            )

    def test_rust_metadata_duplicate_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deny, metadata = self.write_rust_contract(
                root,
                exceptions=[self.advisory_exception(), self.advisory_exception()],
            )
            evidence = dependency_reports.rust_summary(
                self.rust_args(root, deny_config=deny, advisory_exceptions=metadata)
            )
            self.assertEqual(evidence["result"], "fail")
            self.assertIn(
                "advisory_exception_metadata_duplicate_id",
                {item["code"] for item in evidence["findings"]},
            )

    def test_rust_expired_review_date_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expired = self.advisory_exception()
            expired["review_by"] = "2000-01-01"
            deny, metadata = self.write_rust_contract(root, exceptions=[expired])
            evidence = dependency_reports.rust_summary(
                self.rust_args(root, deny_config=deny, advisory_exceptions=metadata)
            )
            self.assertEqual(evidence["result"], "fail")
            self.assertIn(
                "advisory_exception_review_expired",
                {item["code"] for item in evidence["findings"]},
            )

    def test_rust_missing_tracking_issue_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_tracking = self.advisory_exception()
            del missing_tracking["tracking_issue"]
            deny, metadata = self.write_rust_contract(root, exceptions=[missing_tracking])
            evidence = dependency_reports.rust_summary(
                self.rust_args(root, deny_config=deny, advisory_exceptions=metadata)
            )
            self.assertEqual(evidence["result"], "fail")
            self.assertIn(
                "advisory_exception_metadata_field_missing",
                {item["code"] for item in evidence["findings"]},
            )

    def test_go_summary_counts_actionable_unique_vulnerabilities_from_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            govuln = root / "govuln.jsonl"
            govuln.write_text(
                "\n".join(
                    [
                        json.dumps({"config": {"protocol": "https"}}, indent=2),
                        json.dumps({"osv": {"id": "GO-2026-0000", "affected": []}}),
                        json.dumps({"finding": {"osv": "GO-2026-0001", "trace": [{"package": "example/p"}]}}),
                        json.dumps({"finding": {"osv": "GO-2026-0001", "trace": [{"package": "example/p"}]}}),
                        json.dumps({"finding": {"osv": "GO-2026-0002", "trace": [{"function": "F"}]}}),
                    ]
                ),
                encoding="utf-8",
            )
            modules = root / "modules.json"
            modules.write_text('{"Path":"a"}\n{"Path":"b"}\n', encoding="utf-8")
            args = type(
                "Args",
                (),
                {
                    "mod_status": 0,
                    "test_status": 0,
                    "vet_status": 0,
                    "modules_status": 0,
                    "json_status": 0,
                    "vuln_status": 0,
                    "govulncheck_json": govuln,
                    "modules_json": modules,
                    "head_sha": HEAD_SHA,
                    "go_version": "go1.26.6",
                    "govulncheck_version": "v1.1.4",
                },
            )()
            evidence = dependency_reports.go_summary(args)
            self.assertEqual(evidence["module_count"], 2)
            self.assertEqual(evidence["vulnerability_count"], 2)
            self.assertEqual(evidence["finding_message_count"], 3)

    def test_empty_govulncheck_output_fails_even_with_zero_status(self) -> None:
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
                    "vet_status": 0,
                    "modules_status": 0,
                    "json_status": 0,
                    "vuln_status": 0,
                    "govulncheck_json": govuln,
                    "modules_json": modules,
                    "head_sha": HEAD_SHA,
                    "go_version": "go1.26.6",
                    "govulncheck_version": "v1.1.4",
                },
            )()
            evidence = dependency_reports.go_summary(args)
            self.assertEqual(evidence["result"], "fail")
            self.assertIn("empty_govulncheck_json", {item["code"] for item in evidence["findings"]})

    def test_nonzero_scanner_status_is_not_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            govuln = root / "govuln.jsonl"
            govuln.write_text(json.dumps({"config": {}}), encoding="utf-8")
            modules = root / "modules.json"
            modules.write_text('{"Path":"a"}\n', encoding="utf-8")
            args = type(
                "Args",
                (),
                {
                    "mod_status": 0,
                    "test_status": 0,
                    "vet_status": 0,
                    "modules_status": 0,
                    "json_status": 3,
                    "vuln_status": 3,
                    "govulncheck_json": govuln,
                    "modules_json": modules,
                    "head_sha": HEAD_SHA,
                    "go_version": "go1.26.6",
                    "govulncheck_version": "v1.1.4",
                },
            )()
            evidence = dependency_reports.go_summary(args)
            self.assertEqual(evidence["result"], "fail")
            self.assertEqual(evidence["checks"]["govulncheck_gate"], 3)


class AggregateTests(unittest.TestCase):
    def write_clean_reports(self, root: Path, *, head: str = HEAD_SHA, workflow: str = WORKFLOW_SHA) -> None:
        rust_exception = {
            "advisory_id": "RUSTSEC-2024-0429",
            "package": "glib",
            "affected_version": "0.18.5",
            "dependency_path": "p2wlan-tray -> tao -> tray-icon -> libappindicator -> glib",
            "status": "temporary_exception",
            "rationale": "Fixture rationale.",
            "mitigation": "Fixture mitigation.",
            "tracking_issue": 52,
            "review_by": "2099-09-30",
        }
        for filename, component in aggregate_evidence.REQUIRED.items():
            report: dict[str, object] = {
                "schema_version": 2,
                "repository": "yhan-sun/p2wlan",
                "component": component,
                "source_commit": head,
                "head_sha": head,
                "workflow_sha": workflow,
                "tool": "fixture",
                "tools": {"fixture": "1"},
                "tool_versions": {"fixture": "1"},
                "command": ["fixture"],
                "generated_at": "2026-09-02T00:00:00+00:00",
                "result": "pass",
                "failure_category": [],
                "evidence_summary": {"fixture": True},
                "findings": [],
            }
            if component == "rust_dependency_audit":
                report.update(
                    {
                        "checks": {"audit": 0},
                        "vulnerability_counts": {"total": 0},
                        "advisory_exception_count": 1,
                        "advisory_exception_ids": ["RUSTSEC-2024-0429"],
                        "advisory_ignores": [rust_exception],
                    }
                )
            elif component == "go_vulnerability_audit":
                report.update({"checks": {"govulncheck": 0}, "vulnerability_count": 0})
            elif component == "flutter_outdated_triage":
                report.update({"counts": {"blockers": 0}})
            elif component == "flutter_dependency_audit":
                report.update({"outdated_dependency_counts": {"blockers": 0}})
            elif component == "release_asset_verification":
                report.update(
                    {
                        "asset_count": 1,
                        "verified_asset_count": 1,
                        "required_asset_classes": {name: True for name in verify_release_assets.REQUIRED_ASSET_PATTERNS},
                    }
                )
            (root / filename).write_text(json.dumps(report), encoding="utf-8")
        (root / "deny.toml").write_text(
            '[advisories]\nignore = ["RUSTSEC-2024-0429"]\n',
            encoding="utf-8",
        )
        metadata = root / "security" / "advisory-exceptions.json"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text(
            json.dumps({"exceptions": [rust_exception]}),
            encoding="utf-8",
        )

    def aggregate(self, root: Path, **kwargs: object) -> dict[str, object]:
        return aggregate_evidence.run(
            root,
            HEAD_SHA,
            repository="yhan-sun/p2wlan",
            workflow_sha=WORKFLOW_SHA,
            needs_results=NEEDS_SUCCESS,
            **kwargs,
        )

    def test_all_required_pass_evidence_aggregates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            evidence = self.aggregate(root)
            self.assertEqual(evidence["result"], "pass")
            self.assertEqual(evidence["product_signing"]["notarization"], "deferred_non_blocking")

    def test_missing_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = self.aggregate(root)
            self.assertEqual(evidence["result"], "fail")
            self.assertTrue(any(item["code"] == "evidence_root_empty" for item in evidence["findings"]))

    def test_missing_report_schema_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            (root / "go-summary.json").write_text('{"result":"pass"}\n', encoding="utf-8")
            evidence = self.aggregate(root)
            self.assertTrue(any(item["code"] == "report_schema_field_missing" for item in evidence["findings"]))

    def test_forged_pass_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            path = root / "go-summary.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            report["result"] = "pass"
            report["findings"] = [{"code": "scanner_nonzero"}]
            report["failure_category"] = ["scanner_nonzero"]
            path.write_text(json.dumps(report), encoding="utf-8")
            evidence = self.aggregate(root)
            self.assertTrue(any(item["code"] == "report_result_inconsistent" for item in evidence["findings"]))

    def test_forged_empty_rust_advisory_ignores_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            path = root / "rust-summary.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            report["advisory_ignores"] = []
            path.write_text(json.dumps(report), encoding="utf-8")
            evidence = self.aggregate(root)
            self.assertTrue(
                any(item["code"] == "rust_advisory_ignores_mismatch" for item in evidence["findings"])
            )

    def test_source_sha_repository_and_workflow_sha_tampering_fails(self) -> None:
        for field, value, code in (
            ("source_commit", "c" * 40, "evidence_head_mismatch"),
            ("head_sha", "c" * 40, "evidence_head_mismatch"),
            ("repository", "evil/example", "report_repository_mismatch"),
            ("workflow_sha", "d" * 40, "evidence_workflow_sha_mismatch"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_clean_reports(root)
                path = root / "rust-summary.json"
                report = json.loads(path.read_text(encoding="utf-8"))
                report[field] = value
                path.write_text(json.dumps(report), encoding="utf-8")
                evidence = self.aggregate(root)
                self.assertTrue(any(item["code"] == code for item in evidence["findings"]))

    def test_extra_unknown_evidence_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            (root / "unexpected.json").write_text("{}\n", encoding="utf-8")
            evidence = self.aggregate(root)
            self.assertTrue(any(item["code"] == "unknown_evidence_file" for item in evidence["findings"]))

    def test_corrupt_and_duplicate_reports_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            (root / "flutter-summary.json").write_text("{not json}\n", encoding="utf-8")
            duplicate = root / "nested"
            duplicate.mkdir()
            (duplicate / "flutter-summary.json").write_text("{}\n", encoding="utf-8")
            evidence = self.aggregate(root)
            codes = {item["code"] for item in evidence["findings"]}
            self.assertIn("evidence_file_missing_or_ambiguous", codes)
            self.assertIn("unknown_evidence_file", codes)

    def test_every_non_success_need_result_fails_closed(self) -> None:
        for status in ("failure", "cancelled", "skipped"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_clean_reports(root)
                needs = dict(NEEDS_SUCCESS)
                needs["go-dependencies"] = status
                evidence = aggregate_evidence.run(
                    root,
                    HEAD_SHA,
                    repository="yhan-sun/p2wlan",
                    workflow_sha=WORKFLOW_SHA,
                    needs_results=needs,
                )
                self.assertTrue(any(item["code"] == "required_job_not_success" for item in evidence["findings"]))

    def test_missing_need_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_clean_reports(root)
            needs = dict(NEEDS_SUCCESS)
            del needs["release-assets"]
            evidence = aggregate_evidence.run(
                root,
                HEAD_SHA,
                repository="yhan-sun/p2wlan",
                workflow_sha=WORKFLOW_SHA,
                needs_results=needs,
            )
            self.assertTrue(any(item["code"] == "needs_result_missing" for item in evidence["findings"]))


class WorkflowCheckContractTests(unittest.TestCase):
    def write_workflow(self, root: Path, name: str, content: str) -> None:
        path = root / ".github" / "workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_repository_required_checks_resolve_to_unique_jobs(self) -> None:
        evidence = workflow_check_contract.run(SECURITY_DIR.parents[1])
        self.assertEqual(evidence["result"], "pass", evidence)

    def test_missing_required_check_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "contract.yml",
                """name: Contract
jobs:
  producer:
    name: Present
    runs-on: ubuntu-latest
    steps: []
  aggregate:
    name: Aggregate
    runs-on: ubuntu-latest
    steps:
      - run: |
          const requiredNames = ['Missing'];
""",
            )
            evidence = workflow_check_contract.run(root)
            self.assertTrue(
                any(item["code"] == "required_check_missing" for item in evidence["findings"])
            )

    def test_duplicate_required_name_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "contract.yml",
                """name: Contract
jobs:
  producer:
    name: Present
    runs-on: ubuntu-latest
    steps: []
  aggregate:
    name: Aggregate
    runs-on: ubuntu-latest
    steps:
      - run: |
          const requiredNames = ['Present', 'Present'];
""",
            )
            evidence = workflow_check_contract.run(root)
            self.assertTrue(
                any(item["code"] == "required_check_duplicate" for item in evidence["findings"])
            )

    def test_ambiguous_declared_name_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workflow(
                root,
                "contract.yml",
                """name: Contract
jobs:
  first:
    name: Shared
    runs-on: ubuntu-latest
    steps: []
  second:
    name: Shared
    runs-on: ubuntu-latest
    steps: []
  aggregate:
    name: Aggregate
    runs-on: ubuntu-latest
    steps:
      - run: |
          const requiredNames = ['Shared'];
""",
            )
            evidence = workflow_check_contract.run(root)
            codes = {item["code"] for item in evidence["findings"]}
            self.assertIn("declared_check_ambiguous", codes)
            self.assertIn("required_check_ambiguous", codes)


if __name__ == "__main__":
    unittest.main()
