#!/usr/bin/env bash
# field-gate-verify.sh — one-shot field-Gate verifier for the dual-CGNAT run.
#
# Analyzes an EXISTING mini-air-smoke.sh artifact tree (read-only; it never
# launches daemons, never mutates the fingerprint-locked A/B sequence) and
# renders PASS/FAIL for the three things a single 10-round strict-acceptance
# run proves at once:
#
#   Gate A  Gate4 10/10        strict-acceptance rounds all ok
#   Gate B  liveness normal    zero false outbound_liveness verdict=blocked
#                              (防假阳性：正常网络下 CGNAT 黑洞不得被误标为防火墙)
#   Gate C  R1 p2v2 delivery   every non-empty peer nat_type observed on field
#                              carries the structured "p2v2:" fingerprint label
#
# Observability points (verified against the tree; do NOT rely on the debug
# "Updated endpoint" log — control::runtime::commands is not in the harness
# RUST_LOG debug list, so it is suppressed at field):
#   - nat_type:  /status peer diagnostics  ->  node-{a,b}.poll-*.json  (.peer.nat_type)
#   - liveness:  daemon structured log     ->  node-{a,b}.log  (event=outbound_liveness ...)
#
# Usage:
#   field-gate-verify.sh <BASE_DIR> <AB_SEQUENCE_DIR>
#     BASE_DIR        = $ARTIFACT_ROOT/mini-air-$RUN_ID   (has round-1..round-10/)
#     AB_SEQUENCE_DIR = dir holding sequence-results.json (written by mini-air-smoke)
#
#   field-gate-verify.sh "$ARTIFACT_ROOT/mini-air-1234" "$AB_SEQUENCE_DIR"
#
# Exit 0 = all three gates PASS; 1 = at least one FAIL; 2 = usage/artifact error.
set -uo pipefail

BASE_DIR="${1:?usage: field-gate-verify.sh <BASE_DIR> <AB_SEQUENCE_DIR>}"
AB_SEQUENCE_DIR="${2:?usage: field-gate-verify.sh <BASE_DIR> <AB_SEQUENCE_DIR>}"

[ -d "$BASE_DIR" ] || { echo "[verify] BASE_DIR not found: $BASE_DIR" >&2; exit 2; }
SEQ="$AB_SEQUENCE_DIR/sequence-results.json"
[ -f "$SEQ" ] || { echo "[verify] sequence-results.json not found: $SEQ" >&2; exit 2; }

ROUNDS_WANTED=10
overall=0

echo "==================================================================="
echo " P2WLAN field Gate verifier — dual-CGNAT strict-acceptance"
echo " BASE_DIR:      $BASE_DIR"
echo " SEQUENCE:      $SEQ"
echo "==================================================================="
echo

# ---- Gate A: strict-acceptance 10/10 -------------------------------------
gate_a=$(python3 - "$SEQ" "$ROUNDS_WANTED" <<'PY'
import json, sys
seq, want = sys.argv[1], int(sys.argv[2])
with open(seq, encoding="utf-8") as f:
    rows = json.load(f)
acc = [r for r in rows if r.get("stage") == "strict-acceptance"]
ok = [r for r in acc if r.get("ok") is True]
bad = [r for r in acc if r.get("ok") is not True]
per = " | ".join(
    "r%s:%s%s" % (r.get("round"), "ok" if r.get("ok") else "FAIL",
                  (" " + str(r.get("strict_convergence_ms")) + "ms") if r.get("strict_convergence_ms") else "")
    for r in acc)
print("rows=%d ok=%d want=%d bad=%d" % (len(acc), len(ok), want, len(bad)), per)
sys.exit(0 if (len(acc) == want and len(bad) == 0) else 1)
PY
)
rc_a=$?
echo "Gate A — Gate4 10/10 (strict-acceptance)"
echo "  $gate_a"
if [ $rc_a -eq 0 ]; then echo "  => PASS"; else echo "  => FAIL"; overall=1; fi
echo

# ---- Gate B: liveness normal (zero false blocked) -------------------------
gate_b=$(python3 - "$BASE_DIR" <<'PY'
import glob, os, re, sys
base = sys.argv[1]
ok = blocked = unknown = 0
blocked_roots = []
for log in sorted(glob.glob(os.path.join(base, "round-*", "node-?.log"))):
    try:
        txt = open(log, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    # only outbound_liveness verdict lines (not *_applied / *_pre_flight_skip)
    for m in re.finditer(r'outbound_liveness[^a-z].*?verdict="?(ok|blocked|unknown)', txt):
        v = m.group(1)
        if v == "ok": ok += 1
        elif v == "blocked":
            blocked += 1
            blocked_roots.append(os.path.basename(os.path.dirname(log)))
        else: unknown += 1
print("verdict_ok=%d verdict_blocked=%d verdict_unknown=%d blocked_rounds=%s"
      % (ok, blocked, unknown, ",".join(sorted(set(blocked_roots))) or "-"))
sys.exit(0 if blocked == 0 else 1)
PY
)
rc_b=$?
echo "Gate B — liveness normal (防假阳性: 0 false verdict=blocked on clean egress)"
echo "  $gate_b"
if [ $rc_b -eq 0 ]; then
  echo "  => PASS (zero false blocked; ok-count is informational — liveness only fires on a ScatterExtended 0-ACK wide scan)"
else
  echo "  => FAIL (CGNAT hole misattributed as firewall — false positive)"
  overall=1
fi
echo

# ---- Gate C: R1 p2v2 label delivery ---------------------------------------
gate_c=$(python3 - "$BASE_DIR" <<'PY'
import glob, json, os, sys
base = sys.argv[1]
total = 0          # non-empty nat_type values observed
p2v2 = 0
legacy_or_other = 0
a_hits = b_hits = 0
samples_bad = []
for pf in sorted(glob.glob(os.path.join(base, "round-*", "node-?.poll-*.json"))):
    side = "a" if "node-a" in os.path.basename(pf) else "b"
    try:
        with open(pf, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        continue
    peers = [doc["peer"]] if isinstance(doc, dict) and doc.get("peer") else (doc.get("peers", []) if isinstance(doc, dict) else [])
    for peer in peers:
        if not isinstance(peer, dict):
            continue
        nt = peer.get("nat_type") or ""
        if not nt:
            continue
        total += 1
        if nt.startswith("p2v2:"):
            p2v2 += 1
            if side == "a": a_hits += 1
            else: b_hits += 1
        else:
            legacy_or_other += 1
            if len(samples_bad) < 5:
                samples_bad.append("%s:%s -> %s" % (os.path.basename(os.path.dirname(pf)), side, nt[:60]))
print("nonempty_nat_type=%d p2v2=%d legacy_or_other=%d a_sees_p2v2=%d b_sees_p2v2=%d"
      % (total, p2v2, legacy_or_other, a_hits, b_hits))
if samples_bad:
    print("  non-p2v2 samples:")
    for s in samples_bad:
        print("    " + s)
# PASS requires: at least one observed in each direction, AND every non-empty is p2v2.
sys.exit(0 if (total > 0 and legacy_or_other == 0 and a_hits > 0 and b_hits > 0) else 1)
PY
)
rc_c=$?
echo "Gate C — R1 p2v2 structured NAT fingerprint delivery (both directions)"
echo "  $gate_c"
if [ $rc_c -eq 0 ]; then
  echo "  => PASS (every non-empty peer nat_type is p2v2:, observed in both a->b and b->a)"
else
  echo "  => FAIL (missing p2v2 label in at least one direction, or legacy/other value seen)"
  overall=1
fi
echo

echo "==================================================================="
if [ $overall -eq 0 ]; then
  echo " FIELD GATE: PASS — Gate4 10/10 + liveness 0-false-blocked + R1 p2v2 both dirs"
else
  echo " FIELD GATE: FAIL — see the FAIL gates above"
fi
echo "==================================================================="
exit $overall
