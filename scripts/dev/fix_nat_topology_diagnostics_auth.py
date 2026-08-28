from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


path = Path("scripts/nat-sim/nat-sim-smoke.sh")
replace_once(
    path,
    '  local url="$1" output="$2" kind="$3"\n',
    '  local url="$1" output="$2" kind="$3" auth_token_file="${4:-}"\n',
)
replace_once(
    path,
    '''  if [[ "$kind" == "status" ]]; then
    DIAGNOSTICS_AUTH_TOKEN_FILE="$ROUND_DIR/p2wlan-daemon.diag-auth" \\
      p2wlan_diagnostics_curl -fsS --max-time 5 "$url" -o "$output" || curl_status=$?
  else
''',
    '''  if [[ "$kind" == "status" ]]; then
    if [[ -z "$auth_token_file" ]]; then
      echo "[nat-sim] FAIL reason_code=status_auth_token_file_missing url=$url" >&2
      return 1
    fi
    DIAGNOSTICS_AUTH_TOKEN_FILE="$auth_token_file" \\
      p2wlan_diagnostics_curl -fsS --max-time 5 "$url" -o "$output" || curl_status=$?
  else
''',
)
replace_once(
    path,
    '''  printf '%s\\n' "$TOKEN" | P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID="$ROUND_RUN_ID" RUST_LOG="$NAT_SIM_RUST_LOG" "$ROOT_DIR/target/debug/p2wlan-daemon" \\
    --config "$ROUND_DIR/node-a.json" \\
''',
    '''  # Each daemon needs its own diagnostics auth discovery directory.
  # A shared config parent makes the second process atomically replace the
  # first process' token file, so authenticated status collection would read
  # the wrong secret and correctly receive HTTP 401.
  mkdir -p "$ROUND_DIR/node-a" "$ROUND_DIR/node-b"

  printf '%s\\n' "$TOKEN" | P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID="$ROUND_RUN_ID" RUST_LOG="$NAT_SIM_RUST_LOG" "$ROOT_DIR/target/debug/p2wlan-daemon" \\
    --config "$ROUND_DIR/node-a/config.json" \\
''',
)
replace_once(
    path,
    '    --config "$ROUND_DIR/node-b.json" \\\n',
    '    --config "$ROUND_DIR/node-b/config.json" \\\n',
)
replace_once(
    path,
    '''  fetch_required_json "http://127.0.0.1:$DIAG_A_PORT/status" "$ROUND_DIR/node-a.status.json" status || STATUS_SCHEMA_OK=0
  fetch_required_json "http://127.0.0.1:$DIAG_B_PORT/status" "$ROUND_DIR/node-b.status.json" status || STATUS_SCHEMA_OK=0
''',
    '''  fetch_required_json \\
    "http://127.0.0.1:$DIAG_A_PORT/status" \\
    "$ROUND_DIR/node-a.status.json" \\
    status \\
    "$ROUND_DIR/node-a/p2wlan-daemon.diag-auth" || STATUS_SCHEMA_OK=0
  fetch_required_json \\
    "http://127.0.0.1:$DIAG_B_PORT/status" \\
    "$ROUND_DIR/node-b.status.json" \\
    status \\
    "$ROUND_DIR/node-b/p2wlan-daemon.diag-auth" || STATUS_SCHEMA_OK=0
''',
)
