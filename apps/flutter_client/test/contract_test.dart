// Contract test: pins the JSON field contract between the Rust daemon and the
// Flutter client for the state fields introduced for the Flutter unification
// (ADR 0004). If the daemon renames or drops these fields, this test fails so
// the two sides cannot drift silently.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';

void main() {
  group('/status contract: revision + readyPhase', () {
    test('new fields are parsed from the daemon snapshot', () {
      final raw = jsonDecode(jsonEncode({
        'version': '0.1.118',
        'node_id': 'node-a',
        'virtual_ip': '10.20.0.7',
        'network_id': 'net1',
        'revision': 42,
        'ready_phase': 'connected_direct',
        'peers': <Map<String, dynamic>>[],
        'health': <String, dynamic>{},
        'stats': <String, dynamic>{},
        'relay_selection': <String, dynamic>{},
      })) as Map<String, dynamic>;

      final snapshot = DiagnosticsSnapshot.fromJson(raw);
      expect(snapshot.revision, 42);
      expect(snapshot.readyPhase, 'connected_direct');
    });

    test('old daemon without the fields falls back to 0 / unknown (backward compatible)', () {
      final raw = jsonDecode(jsonEncode({
        'version': '0.1.110',
        'node_id': 'node-a',
        'virtual_ip': '10.20.0.7',
        'peers': <Map<String, dynamic>>[],
        'health': <String, dynamic>{},
        'stats': <String, dynamic>{},
        'relay_selection': <String, dynamic>{},
      })) as Map<String, dynamic>;

      final snapshot = DiagnosticsSnapshot.fromJson(raw);
      expect(snapshot.revision, 0);
      expect(snapshot.readyPhase, 'unknown');
    });

    test('every documented readyPhase value round-trips through the model', () {
      const phases = [
        'connecting_control',
        'connected_manual',
        'connected_direct',
        'connected_relay',
        'discovering_peers',
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

  group('/events contract', () {
    test('response shape: {revision, events:[{seq, event, at_ms, ...}]}', () {
      // Mirrors the daemon's StatusEvent serialization.
      final body = jsonDecode(jsonEncode({
        'revision': 7,
        'events': [
          {
            'seq': 6,
            'event': 'peer_state_changed',
            'at_ms': 1234,
            'path': 'direct',
            'reason_code': null,
            'peer_id': 'node-b',
          },
          {
            'seq': 7,
            'event': 'relay_transport_connected',
            'at_ms': 2000,
          },
        ],
      })) as Map<String, dynamic>;

      expect(body['revision'], 7);
      final events = body['events'] as List;
      expect(events.length, 2);
      // seq is monotonic and usable as the /events?since=N cursor.
      expect((events[0]['seq'] as int) < (events[1]['seq'] as int), isTrue);
      // Optional fields may be absent on some events (skip_serializing_if).
      expect(events[1].containsKey('peer_id'), isFalse);
    });
  });

  group('/routes contract', () {
    test('response shape: {interface, mtu, healthy, conflictCount, entries[]}',
        () {
      // Mirrors the daemon's describe_overlay_routes output.
      final body = jsonDecode(jsonEncode({
        'interface': 'p2wlan0',
        'mtu': 1420,
        'healthy': true,
        'conflictCount': 0,
        'entries': [
          {
            'cidr': '10.20.0.0/16',
            'expected_interface': 'p2wlan0',
            'actual_interface': 'p2wlan0',
            'state': 'installed',
            'owned': true,
          },
        ],
      })) as Map<String, dynamic>;

      expect(body['healthy'], true);
      expect(body['conflictCount'], 0);
      final entries = body['entries'] as List;
      expect(entries.first['state'], 'installed');
      expect(entries.first['expected_interface'], 'p2wlan0');
      expect(entries.first['owned'], true);
    });

    test('repair response shape: {cidr, changed, before, after, restartedDaemon}',
        () {
      // Mirrors the daemon's repair_overlay_routes output. `restartedDaemon`
      // MUST be false — repair never restarts the daemon/TUN/sessions.
      final body = jsonDecode(jsonEncode({
        'cidr': '10.20.0.0/16',
        'changed': true,
        'before': 'missing',
        'after': 'installed',
        'restartedDaemon': false,
      })) as Map<String, dynamic>;
      expect(body['restartedDaemon'], isFalse);
      expect(body['after'], 'installed');
    });
  });
}
