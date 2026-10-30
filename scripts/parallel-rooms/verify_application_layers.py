#!/usr/bin/env python3
"""Verify original baseline TCP layers after the existing real-TUN run ends."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/dual-end'))
from application_layer_report import QUEUE_CLOCK, QUEUE_SCOPE, read_input
from udp_business_probe import UNVERIFIED


def verify(root, head):
    if not re.fullmatch('[0-9a-f]{40}', head):
        raise ValueError('exact_source_required')
    original, _ = read_input(root / 'report.json')
    if (original['source_commit'] != head or original['scope'] != 'linux_same_host_kernel_tun_application'
            or original['passed'] is not True or original['cleanup_complete'] is not True):
        raise ValueError('original_baseline_source_or_result_changed')
    for name in ['tcp_business_probe.py', 'tcp_socket_observation.py', 'application_layer_report.py', 'application_layer_export.py']:
        path = 'scripts/dual-end/' + name
        raw = subprocess.check_output(['git', 'show', head + ':' + path], cwd=ROOT)
        if original['source_sha256'][path] != hashlib.sha256(raw).hexdigest():
            raise ValueError('original_tool_source_changed')
    summary = original['layered_application_observations']
    rows = summary['reports']
    if (summary['extra_daemon_snapshot_requests'] != 0 or summary['packet_intervals_summed'] is not False
            or summary['business_outcomes_reclassified'] is not False or len(rows) != 2
            or {r['file'] for r in rows} != {'tcp-a-to-b-layers.json', 'tcp-b-to-a-layers.json'}):
        raise ValueError('fixed_baseline_layer_reports_changed')
    requests = 0
    for row in rows:
        report, receipt = read_input(root / row['file'])
        if receipt['sha256'] != row['sha256'] or report['evidence'] != UNVERIFIED:
            raise ValueError('layer_report_digest_or_credit_changed')
        if report['fixed_denominator'] != 8 or report['outcomes']['success'] != 8:
            raise ValueError('original_TCP_eight_requests_changed')
        if (report['cross_host_clocks_subtracted'] is not False or report['RTT_minus_service_used_as_network_RTT'] is not False
                or report['packet_intervals_summed_into_request_latency'] is not False):
            raise ValueError('layer_scope_changed')
        for request in report['requests']:
            if request['service_observation']['availability'] != 'available':
                raise ValueError('original_service_interval_unavailable')
            packets = request['daemon_queue_observations']
            if {p['kind'] for p in packets} != {'request', 'response'}:
                raise ValueError('both_original_daemon_packet_directions_required')
            for packet in packets:
                intervals = packet['intervals']
                if (intervals.get('scope'), intervals.get('clock')) != (QUEUE_SCOPE, QUEUE_CLOCK):
                    raise ValueError('original_queue_interval_scope_unavailable')
                for key in ['dataplane_queue', 'network_outbound_queue']:
                    interval = intervals[key]
                    if interval['availability'] != 'available' or type(interval['nanoseconds']) is not int or interval['nanoseconds'] < 0:
                        raise ValueError('same_packet_original_queue_boundary_missing')
            requests += 1
    if requests != 16:
        raise ValueError('fixed_TCP_denominator_changed')
    return dict(scope='original_real_TUN_TCP_layers_only', source=head, requests=16,
                original_report_sha256=hashlib.sha256((root / 'report.json').read_bytes()).hexdigest(),
                extra_daemon_snapshot_requests=0, no_native_credit_added=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--head', required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.root, args.head), sort_keys=True))
