# Security and dependency audit gate

`Security Audit Required` is P2WLAN's fail-closed dependency, workflow,
credential-transport and published-asset checksum gate. It implements Issue
#30 without conflating supply-chain verification with platform product signing.

## Exact-head rule

Every job checks out `github.event.pull_request.head.sha` (or `github.sha` for
push, scheduled and manual runs) and verifies that checkout before auditing.
Results from another branch or an older commit cannot satisfy the aggregate
check.

The workflow runs on every pull request to `main`, every push to `main`, a
weekly schedule, and manual dispatch. Consequently a version/release PR cannot
skip the gate through path filters.

## Component checks

### Rust dependency graphs

- `cargo-audit 0.22.2` checks the root and fuzz `Cargo.lock` files against the
  RustSec database.
- `cargo-deny 0.20.2` runs `advisories`, `bans`, `licenses`, and `sources` for
  both dependency graphs with `deny.toml`.
- Vulnerability, unsoundness, yanked-package, disallowed-license, wildcard
  dependency and unknown registry/Git-source findings fail.
- Multiple versions remain visible as warnings because they are not themselves
  a release vulnerability. There are no advisory ignores.
- Machine-readable scanner output, stderr, exact exit status, tool version,
  vulnerability count and warning count are retained as evidence.

### Go dependency graph

- `actions/setup-go` reads the repository's `server/go.mod` rather than a
  duplicated workflow version.
- `govulncheck v1.1.4` runs in both JSON evidence mode and normal gate mode over
  `./...`.
- `go mod verify`, `go test ./... -count=1`, and
  `go list -m -json all` must also succeed.
- Structured evidence records the module count, unique vulnerability IDs,
  finding-message count, exact command statuses and tool versions.

### Flutter dependency graph

- Flutter uses the SDK pinned by `.fvmrc`.
- The job runs `flutter pub get`, `flutter pub deps --style=compact`,
  `flutter pub outdated --json`, and `flutter analyze`.
- `flutter_lock_policy.py` permits only Flutter SDK dependencies and
  `https://pub.dev` hosted packages with lockfile SHA-256 values.
- `flutter_outdated_triage.py` classifies every outdated, discontinued or
  retracted package:
  - discontinued/retracted packages block release admissibility;
  - a direct/dev dependency with a newer resolvable version blocks until it is
    updated and retested;
  - direct dependencies constrained by the SDK and transitive/SDK-pinned drift
    are recorded but do not trigger an unrelated upgrade.
- The job verifies that dependency resolution did not silently rewrite the
  checked-in lockfile.

### Workflow permissions and production secrets

Every workflow must declare exactly one explicit top-level `permissions` map.
`write-all`, scalar shortcuts, ambiguous/empty mappings,
`pull_request_target`, and write permissions outside the allowlist fail.

The only write exception is:

| Path | Permission | Reason |
|---|---|---|
| `.github/workflows/release.yml` | `contents: write` | Create and populate the GitHub Release for an immutable `v*` tag. |

Production signing/release secrets are allowed only in `release.yml`, and that
workflow must have a release event or `push.tags` trigger. Ordinary PR, `main`
push, scheduled, and test-package workflows must not reference the stable
Android signing key.

The Flutter and package-test workflows therefore produce explicitly named,
release-mode **CI test APKs** with debug signing. Only the tag release workflow
can produce a stable-key Android distribution asset.

### Credential transport and plaintext scanning

The tracked-source scanner checks repository text, scripts and workflows for:

- high-confidence GitHub, cloud, Slack, Stripe and API token formats;
- real PEM/OpenSSH private-key blocks and tracked key/keystore filenames;
- shell xtrace;
- credentials in URLs or process arguments;
- browser local/session storage used for credentials;
- direct GitHub Actions secret interpolation into commands;
- logging calls that reference sensitive values without a safe descriptor such
  as a hash, fingerprint, presence flag or redaction status.

Policy implementation and unit-test detector fixtures are listed as exact-path
false-positive exclusions for behavioural checks; they remain subject to the
high-confidence token and private-key patterns.

The release-assets job additionally scans generated package bytes for visible
plaintext credential formats. The aggregate job scans all generated JSON,
stdout/stderr and audit-artifact evidence before accepting it. Proprietary
opaque containers are not claimed to be recursively decoded; this limitation
is recorded in the evidence instead of being hidden.

### Published release assets

The latest non-draft, non-prerelease semantic-version release is queried through
the GitHub API. Every published asset is downloaded and checked for:

- exact metadata/downloaded asset-name equality;
- `uploaded` state;
- positive and matching byte size;
- GitHub `sha256:<digest>` metadata;
- locally recomputed matching SHA-256;
- required Android, iOS, Linux, macOS, Windows and Linux CLI asset classes.

Any missing digest, asset, size mismatch or digest mismatch blocks the gate.

## Evidence contract

The final `security-audit-evidence-<run-id>` artifact requires one unambiguous,
passing report for every component. It records:

- exact audited head SHA;
- every component result and source filename;
- SHA-256 and byte size of every component evidence file;
- Rust and Go vulnerability counts;
- Flutter classified-outdated and blocker counts;
- verified release-asset count;
- scanner/tool versions;
- any policy finding without converting it to a warning.

The stable aggregate check is named exactly `Security Audit Required`.

## Product-signing boundary

Issue #30 audits dependency and release integrity. It does not claim that an
asset is Apple-notarized or Windows Authenticode-signed. Aggregate evidence
records those deferred properties explicitly as non-blocking; #32/#33 remain
responsible for their own release-candidate and publication claims.

## Local policy checks

```bash
python3 -m unittest discover -s scripts/security/tests -p 'test_*.py'
python3 scripts/security/workflow_permissions.py --root .
python3 scripts/security/credential_scan.py --root .
python3 scripts/security/flutter_lock_policy.py \
  --lockfile apps/flutter_client/pubspec.lock
```
