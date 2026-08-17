// Contract test: pins the JSON wire contract shared with the Rust daemon.
//
// The fixtures live in `contracts/fixtures/` at the repository root — the SAME
// files the Rust daemon contract test (`client/daemon/tests/contract_fixture.rs`)
// deserializes. If either side renames or drops a field, one of the two tests
// fails so the daemon and the Flutter client cannot drift silently.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';

Future<Map<String, dynamic>> _readFixture(String name) async {
  final file = File('../../contracts/fixtures/$name');
  final raw = await file.readAsString();
  final decoded = jsonDecode(raw);
  if (decoded is! Map<String, dynamic>) {
    throw StateError('fixture $name must be a JSON object');
  }
  return decoded;
}

void main() {
  group('/status contract (shared fixture)', () {
    test('shared status.json parses and carries revision + readyPhase', () async {
      final json = await _readFixture('status.json');
      final snapshot = DiagnosticsSnapshot.fromJson(json);
      expect(snapshot.nodeId, 'node-a');
      expect(snapshot.networkId, 'net1');
      expect(snapshot.virtualIp, '10.20.0.7');
      expect(snapshot.revision, greaterThan(0));
      expect(snapshot.readyPhase, isNotEmpty);
    });

    test('every documented readyPhase value round-trips through the model', () async {
      const phases = [
        'connecting_control',
        'connected_manual',
        'connected_direct',
        'connected_relay',
        'discovering_peers',
        'allocating_virtual_ip',
        'credential_reauth_required',
        'error',
        'stopping',
      ];
      for (final phase in phases) {
        final raw = jsonDecode(jsonEncode({
          'node_id': 'node-a',
          'virtual_ip': '10.20.0.7',
          'revision': 1,
          'ready_phase': phase,
          'peers': <Map<String, dynamic>>[],
          'health': <String, dynamic>{},
          'stats': <String, dynamic>{},
          'relay_selection': <String, dynamic>{},
        })) as Map<String, dynamic>;
        expect(DiagnosticsSnapshot.fromJson(raw).readyPhase, phase);
      }
    });
  });

  group('/events contract (shared fixture)', () {
    test('response shape: {revision, events:[{seq, event, at_ms, ...}]}', () async {
      final json = await _readFixture('events.json');
      expect(json['revision'], greaterThanOrEqualTo(3));
      final events = json['events'] as List;
      expect(events.length, 3);
      // seq is monotonic and usable as the /events?since=N cursor.
      final seqs = [
        for (final e in events) (e as Map<String, dynamic>)['seq'] as int,
      ];
      for (var i = 1; i < seqs.length; i++) {
        expect(seqs[i], greaterThan(seqs[i - 1]));
      }
      // Optional fields may be absent on some events.
      expect((events[0] as Map<String, dynamic>).containsKey('peer_id'), isFalse);
    });
  });

  group('/routes contract (shared fixture)', () {
    test('response shape: {interface, mtu, healthy, conflictCount, entries[]}',
        () async {
      final json = await _readFixture('routes.json');
      expect(json['interface'], 'p2wlan0');
      expect(json['mtu'], 1420);
      expect(json['healthy'], true);
      expect(json['conflictCount'], 0);
      final entries = json['entries'] as List;
      final entry = entries.first as Map<String, dynamic>;
      expect(entry['cidr'], '10.20.0.0/16');
      expect(entry['expected_interface'], 'p2wlan0');
      expect(entry['actual_interface'], 'p2wlan0');
      expect(entry['state'], 'installed');
      expect(entry['owned'], true);
    });

    test('repair response never restarts the daemon', () async {
      final json = await _readFixture('route_repair.json');
      // `restartedDaemon` MUST be false — repair never restarts daemon/TUN/sessions.
      expect(json['restartedDaemon'], isFalse);
      expect(json['changed'], isTrue);
      expect(json['after'], 'installed');
      expect(json['reason'], 'installed');
    });
  });
}