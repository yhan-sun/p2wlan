from pathlib import Path

path = Path("client/daemon/src/peer/manager/direct_success.rs")
text = path.read_text(encoding="utf-8")
old = """            // This ACK commit can happen before the live per-peer relay slot
            // is published.  Keep the topology-level relay expectation for
            // the selector snapshot intentionally: the selector argument is
            // a fallback-availability signal here, not proof that relay has
            // delivered business traffic.  Dataplane callers pass the live
            // relay availability separately.
            let relay_expected = self.relay_first_required();
            if relay_expected && conn.relay_first.gate_generation != Some(generation) {
                // Direct validation can complete before the relay supervisor
                // publishes its transport. Arm the gate here as well as at
                // catalog/peer admission so an inbound peer cannot use this
                // ACK to become the first business path.
                conn.relay_first.gate_generation = Some(generation);
                conn.relay_first.gate_started_at = Some(Instant::now());
                self.emit_timeline(
                    \"relay_first_gate_armed\",
                    Some(\"relay\"),
                    Some(\"direct_ack_raced_relay_startup\"),
                    Some(format!(
                        \"peer={node_id} generation={generation} source=direct_ack\"
                    )),
                );
            }
"""
new = """            // A valid Direct ACK may race the forced-relay ACK by a few
            // milliseconds. When relay-first is configured, retain the
            // single-flight validation worker but do not publish ANY Direct
            // business state until RelayPeerConfirmed is committed for this
            // exact generation. The worker has a bounded multi-request budget,
            // so a later ACK retries this same atomic commit after Relay is
            // ready without creating another task or accepting stale evidence.
            let relay_expected = self.relay_first_required();
            if relay_expected {
                if conn.relay_first.gate_generation != Some(generation) {
                    conn.relay_first.gate_generation = Some(generation);
                    conn.relay_first.gate_started_at = Some(Instant::now());
                    self.emit_timeline(
                        \"relay_first_gate_armed\",
                        Some(\"relay\"),
                        Some(\"direct_ack_raced_relay_startup\"),
                        Some(format!(
                            \"peer={node_id} generation={generation} source=direct_ack\"
                        )),
                    );
                }
                let relay_confirmed = conn.relay_confirmed_at.is_some()
                    && conn.relay_confirmed_generation == Some(generation)
                    && conn
                        .relay_confirmed_endpoint
                        .as_deref()
                        .is_some_and(|endpoint| !endpoint.is_empty());
                if !relay_confirmed {
                    conn.record_direct_event(
                        generation,
                        \"direct_confirmation_waiting_for_relay\",
                        Some(selected_endpoint_value),
                        None,
                        None,
                        \"owned encrypted Direct ACK arrived before RelayPeerConfirmed; deferred atomic Direct commit\",
                    );
                    self.emit_timeline(
                        \"direct_confirmation_deferred\",
                        Some(\"direct\"),
                        Some(\"relay_peer_not_confirmed\"),
                        Some(format!(
                            \"peer={node_id} generation={generation} endpoint={selected_endpoint_value}\"
                        )),
                    );
                    return false;
                }
            }
"""
count = text.count(old)
if count != 1:
    raise SystemExit(f"relay-before-direct block: expected exactly one match, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
