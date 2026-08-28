from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1))


transport = Path("client/daemon/src/transport.rs")
replace_once(
    transport,
    """                            } else if source.is_some() {
""",
    """                            } else if let Some(source) = source {
""",
    "transport source binding",
)
replace_once(
    transport,
    """                                if should_request_direct_validation_after_decrypt(
                                    owns_direct_packet,
                                    source,
                                    direct_validation,
                                ) {
                                    let source =
                                        source.expect("source checked by validation predicate");
""",
    """                                if should_request_direct_validation_after_decrypt(
                                    owns_direct_packet,
                                    Some(source),
                                    direct_validation,
                                ) {
""",
    "transport direct-validation predicate",
)

smoke = Path("scripts/nat-sim/nat-sim-smoke.sh")
replace_once(
    smoke,
    """    # Direct mode: relay-first is still mandatory.  Require BOTH Direct
    # promotions, a relay-ingress first usable proof, and a later bidirectional
    # encrypted business echo whose ingress is Direct.  The validation loop
    # targets Direct peers only after the relay-first packet, so this verifies
    # make-before-break rather than treating Direct candidate readiness as
    # first usability.
    direct_ok=0
    for _ in $(seq 1 $((DIRECT_TIMEOUT_S * 2))); do
      if grep -q '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null && \\
         grep -q 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null && \\
         grep -q 'event="first_real_business_ingress".*path="relay"' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q 'event="first_real_business_ingress".*path="relay"' "$ROUND_DIR/node-b.log" 2>/dev/null && \\
         grep -q 'overlay_payload_verified.*ingress=direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q 'overlay_payload_verified.*ingress=direct' "$ROUND_DIR/node-b.log" 2>/dev/null; then
        direct_ok=1
        break
      fi
      sleep 0.5
    done
""",
    """    # Direct mode proves make-before-break without asking the Direct-only
    # overlay generator to manufacture Relay business traffic.  Each side must
    # first confirm Relay with an encrypted probe ACK, then promote Direct via
    # the owned encrypted request/ACK flow, and finally complete a real
    # bidirectional business overlay whose authenticated ingress is Direct.
    direct_ok=0
    for _ in $(seq 1 $((DIRECT_TIMEOUT_S * 2))); do
      if grep -q 'event="relay_peer_confirmed"' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q 'event="relay_peer_confirmed"' "$ROUND_DIR/node-b.log" 2>/dev/null && \\
         grep -q '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null && \\
         grep -q 'overlay_payload_verified.*ingress=direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \\
         grep -q 'overlay_payload_verified.*ingress=direct' "$ROUND_DIR/node-b.log" 2>/dev/null; then
        direct_ok=1
        break
      fi
      sleep 0.5
    done
""",
    "Direct convergence predicate",
)
replace_once(
    smoke,
    """    # A single-sided Direct, missing relay-first evidence, unverified Direct
    # echo, loss/replay/invalid packets, or a missing/slow relay-ready delta is
    # a failure.  The direct validation loop cannot use Relay for the post-
    # promotion echo in this mode.
""",
    """    # A single-sided Direct, Relay confirmation after Direct promotion,
    # unverified Direct business ingress, loss/replay/invalid packets, or a
    # missing/slow relay-ready-to-business delta is a failure.  The Direct-only
    # overlay generator intentionally does not create Relay business traffic.
""",
    "Direct acceptance comment",
)
replace_once(
    smoke,
    """    a_relay_first=0
    b_relay_first=0
    [[ "$A_INGRESS" == relay:* ]] && a_relay_first=1
    [[ "$B_INGRESS" == relay:* ]] && b_relay_first=1
""",
    """    A_RELAY_CONFIRMED_TMS=$(node_event_tms "$ROUND_DIR/node-a.log" relay_peer_confirmed)
    B_RELAY_CONFIRMED_TMS=$(node_event_tms "$ROUND_DIR/node-b.log" relay_peer_confirmed)
    A_DIRECT_PROMOTED_TMS=$(node_event_tms "$ROUND_DIR/node-a.log" direct_promoted)
    B_DIRECT_PROMOTED_TMS=$(node_event_tms "$ROUND_DIR/node-b.log" direct_promoted)
    relay_before_direct_ok=1
    if [[ ! "$A_RELAY_CONFIRMED_TMS" =~ ^[0-9]+$ || ! "$B_RELAY_CONFIRMED_TMS" =~ ^[0-9]+$ \\
          || ! "$A_DIRECT_PROMOTED_TMS" =~ ^[0-9]+$ || ! "$B_DIRECT_PROMOTED_TMS" =~ ^[0-9]+$ ]]; then
      relay_before_direct_ok=0
    elif (( A_RELAY_CONFIRMED_TMS > A_DIRECT_PROMOTED_TMS \\
            || B_RELAY_CONFIRMED_TMS > B_DIRECT_PROMOTED_TMS )); then
      relay_before_direct_ok=0
    fi
    a_direct_business=0
    b_direct_business=0
    [[ "$A_INGRESS" == "direct" ]] && a_direct_business=1
    [[ "$B_INGRESS" == "direct" ]] && b_direct_business=1
""",
    "Direct ordering evidence",
)
replace_once(
    smoke,
    """          && "$A_RELAY_CONFIRMED" -ge 1 && "$B_RELAY_CONFIRMED" -ge 1 \\
          && "$a_relay_first" -eq 1 && "$b_relay_first" -eq 1 \\
          && "$A_DROPS" -eq 0 && "$B_DROPS" -eq 0 \\
""",
    """          && "$A_RELAY_CONFIRMED" -ge 1 && "$B_RELAY_CONFIRMED" -ge 1 \\
          && "$relay_before_direct_ok" -eq 1 \\
          && "$a_direct_business" -eq 1 && "$b_direct_business" -eq 1 \\
          && "$A_DROPS" -eq 0 && "$B_DROPS" -eq 0 \\
""",
    "Direct final predicate",
)
replace_once(
    smoke,
    """      elif [[ "$A_RELAY_CONFIRMED" -lt 1 || "$B_RELAY_CONFIRMED" -lt 1 || "$a_relay_first" -ne 1 || "$b_relay_first" -ne 1 ]]; then
        DIRECT_REASON="relay_first_evidence_missing"
""",
    """      elif [[ "$A_RELAY_CONFIRMED" -lt 1 || "$B_RELAY_CONFIRMED" -lt 1 ]]; then
        DIRECT_REASON="relay_confirmation_missing"
      elif [[ "$relay_before_direct_ok" -ne 1 ]]; then
        DIRECT_REASON="relay_not_confirmed_before_direct"
      elif [[ "$a_direct_business" -ne 1 || "$b_direct_business" -ne 1 ]]; then
        DIRECT_REASON="direct_business_ingress_missing"
""",
    "Direct failure reasons",
)
replace_once(
    smoke,
    """      echo "[nat-sim] ROUND $round: PASS both_direct a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} elapsed_ms=$ELAPSED_MS failure_reason=${FAIL_CODE:-none} (a_direct=$A_DIRECT b_direct=$B_DIRECT) a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY evidence=$ROUND_DIR/evidence.log"
""",
    """      echo "[nat-sim] ROUND $round: PASS both_direct relay_before_direct=1 a_relay_confirmed_t_ms=$A_RELAY_CONFIRMED_TMS b_relay_confirmed_t_ms=$B_RELAY_CONFIRMED_TMS a_direct_promoted_t_ms=$A_DIRECT_PROMOTED_TMS b_direct_promoted_t_ms=$B_DIRECT_PROMOTED_TMS a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} elapsed_ms=$ELAPSED_MS failure_reason=${FAIL_CODE:-none} (a_direct=$A_DIRECT b_direct=$B_DIRECT) a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY evidence=$ROUND_DIR/evidence.log"
""",
    "Direct PASS evidence",
)
