"""Pure comparison of already collected native frame records.

Matching JSON cannot certify an OS write, device, daemon or current owner.
Only KernelCaptures, after its actual owned process/socket/clock and original
write-stream checks, may use this comparison in its evidence result.
"""


class ComparisonError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise ComparisonError(code)


def integer(value, lower=0):
    return type(value) is int and lower <= value <= (1 << 64) - 1


def ordinals(values):
    return (isinstance(values, list) and 1 <= len(values) <= 1024
            and all(integer(value, 1) for value in values)
            and values == sorted(set(values)))


def add_spans(packet, slot, length, covered):
    spans = packet.get("spans")
    require(isinstance(spans, list) and 1 <= len(spans) <= 8, "native_frame_span_capacity")
    slots = set()
    before = len(covered)
    for span in spans:
        require(isinstance(span, dict) and all(integer(span.get(k)) for k in ["slot", "start", "end"])
                and span["slot"] < 8 and span["slot"] not in slots
                and span["start"] < span["end"] <= length, "native_frame_span_shape")
        slots.add(span["slot"])
        if span["slot"] == slot:
            covered.update(range(span["start"], span["end"]))
    require(len(covered) > before, "native_frame_noncontributing_source")


def frame_comparison(snapshot, row, window):
    """Return comparison data only; no object produced here owns authority."""
    credit = row.get("native_credit")
    require(isinstance(credit, dict) and credit.get("status") == "committed"
            and credit.get("once_committed") is True
            and credit.get("physical_send_verified") is True
            and credit.get("canonical_current_owner_verified") is True
            and credit.get("native_os_write_verified") is False, "native_frame_original_once_missing")
    point = credit.get("commit_monotonic_ns")
    sent, end, receipt = (window.get(k) for k in ["original_sent_ns", "original_deadline_ns", "received_monotonic_ns"])
    require(integer(sent, 1) and integer(end, sent + 1) and integer(receipt, sent)
            and integer(point, receipt) and point < end, "native_frame_original_commit_deadline")
    flow, slot = row.get("flow"), row.get("sequence")
    require(integer(flow) and integer(slot) and slot < 8 and row.get("protocol") in {"udp", "tcp"}
            and row.get("kind") in {"request", "response"}, "native_frame_flow_identity")
    peer = row.get("original_peer")
    require(isinstance(peer, dict) and peer.get("known") is True
            and integer(peer.get("network_generation")) and integer(peer.get("peer_lifecycle"), 1)
            and integer(credit.get("network_generation"))
            and credit.get("network_generation") == peer["network_generation"]
            and credit.get("physical_path") in {"udp", "relay"}, "native_frame_first_peer_identity")
    length = 195 if row["protocol"] == "tcp" else 1
    read_ids, write_ids = credit.get("original_kernel_read_ordinals"), credit.get("original_system_write_ordinals")
    require(ordinals(read_ids) and ordinals(write_ids), "native_frame_original_source_ordinals")
    histories = (snapshot.get("historical_full_packets"), snapshot.get("system_tun_full_writes"))
    require(all(isinstance(rows, list) and len(rows) <= 1024 and all(isinstance(p, dict) for p in rows)
                for rows in histories), "native_frame_history_capacity")
    full, writes = {}, {}
    for records, key, target in [(histories[0], "read_ordinal", full), (histories[1], "write_ordinal", writes)]:
        for packet in records:
            ordinal = packet.get(key)
            require(integer(ordinal, 1) and ordinal not in target, "native_frame_duplicate_history_ordinal")
            target[ordinal] = packet
    read_coverage, write_coverage = set(), set()
    sessions = set()
    full_times, authenticated_times, write_times = [], [], []
    for ordinal in read_ids:
        require(ordinal in full, "native_frame_original_full_missing")
        packet = full[ordinal]
        first, publication, complete = (packet.get(k) for k in ["read_monotonic_ns", "publication_observed_monotonic_ns", "full_observed_monotonic_ns"])
        require(integer(packet.get("flow")) and packet["flow"] == flow and integer(first, sent) and integer(publication, first) and integer(complete, publication)
                and complete <= point and integer(packet.get("encryption_generation")) and packet["encryption_generation"] == peer["network_generation"]
                and integer(packet.get("encryption_peer_lifecycle"), 1)
                and packet.get("encryption_peer_lifecycle") == peer["peer_lifecycle"]
                and packet.get("physical_path") == credit["physical_path"]
                and integer(packet.get("encryption_session_instance"), 1), "native_frame_original_full_identity_or_time")
        add_spans(packet, slot, length, read_coverage)
        full_times.append(publication)
        sessions.add(packet["encryption_session_instance"])
    for ordinal in write_ids:
        require(ordinal in writes, "native_frame_original_system_write_missing")
        packet = writes[ordinal]
        authenticated, complete = packet.get("authenticated_observed_monotonic_ns"), packet.get("write_observed_monotonic_ns")
        require(packet.get("scope") == "original_authenticated_system_tun_full_history_only"
                and integer(packet.get("flow")) and packet["flow"] == flow and integer(authenticated, sent) and integer(complete, authenticated)
                and integer(packet.get("network_generation")) and integer(packet.get("peer_lifecycle"), 1)
                and complete <= point and packet.get("network_generation") == peer["network_generation"]
                and packet.get("peer_lifecycle") == peer["peer_lifecycle"] and packet.get("original_session_role") == "active"
                and integer(packet.get("session_instance"), 1)
                and packet.get("canonical_current_owner_verified") is False, "native_frame_original_write_identity_or_time")
        add_spans(packet, slot, length, write_coverage)
        rooms = packet.get("original_room_captured")
        require(isinstance(rooms, list) and len(rooms) == len(packet["spans"]) and all(value is True for value in rooms),
                "native_frame_original_write_room_missing")
        authenticated_times.append(authenticated)
        write_times.append(complete)
        sessions.add(packet["session_instance"])
    require(len(sessions) == 1 and len(read_coverage) == len(write_coverage) == length,
            "native_frame_incomplete_or_mixed_session")
    # Exact receive-before-publication ordering is checked by the sealed native
    # transaction; these native clock upper bounds independently reject reversal.
    if row["kind"] == "request":
        require(max(full_times) <= min(authenticated_times), "native_frame_response_before_original_full")
    else:
        require(max(write_times) <= min(full[i]["read_monotonic_ns"] for i in read_ids),
                "native_frame_response_read_before_original_request_write")
    skipped = credit.get("original_non_delivery_attempts")
    require(isinstance(skipped, list) and len(skipped) <= 1024
            and all(isinstance(pair, list) and len(pair) == 2 and integer(pair[0], 1) and integer(pair[1], 1)
                    and pair[0] < max(read_ids) and pair[0] not in read_ids for pair in skipped)
            and [pair[0] for pair in skipped] == sorted(set(pair[0] for pair in skipped)),
            "native_frame_original_non_delivery_fences")
    result = dict(matched=True, physical_path=credit["physical_path"], commit_monotonic_ns=point, original_kernel_read_ordinals=read_ids,
                  original_system_write_ordinals=write_ids, original_non_delivery_attempts=skipped)
    if credit["physical_path"] == "udp":
        families = {full[i].get("udp_destination_family") for i in read_ids}
        if len(families) == 1 and families <= {"ipv4", "ipv6"}:
            result["udp_destination_family"] = families.pop()
    return result


def frame_comparison_or_gap(snapshot, row, window):
    """Preserve a typed data-comparison gap for this slot, never native credit."""
    try:
        return frame_comparison(snapshot, row, window)
    except ComparisonError as error:
        return dict(matched=False, gap_reason=error.code)
