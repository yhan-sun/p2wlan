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
    test(
      'shared status.json parses and carries revision + readyPhase',
      () async {
        final json = await _readFixture('status.json');
        final response = StatusResponse.fromJson(json);
        final snapshot = response.snapshot;
        expect(response.contractVersion, 1);
        expect(snapshot.nodeId, 'node-a');
        expect(snapshot.networkId, 'net1');
        expect(snapshot.virtualIp, '10.20.0.7');
        expect(snapshot.revision, greaterThan(0));
        expect(snapshot.readyPhase, isNotEmpty);
        expect(snapshot.stats.pathObservability.activeSockets, 1);
        expect(
          snapshot.stats.pathObservability.directTimeToConnectMs.boundsMs,
          [50, 100, 250, 500, 1000, 3000, 10000, 30000],
        );
      },
    );

    test(
      'every documented readyPhase value round-trips through the model',
      () async {
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
          final raw = jsonDecode(
            jsonEncode({
              'node_id': 'node-a',
              'virtual_ip': '10.20.0.7',
              'revision': 1,
              'ready_phase': phase,
              'peers': <Map<String, dynamic>>[],
              'health': <String, dynamic>{},
              'stats': <String, dynamic>{},
              'relay_selection': <String, dynamic>{},
            }),
          ) as Map<String, dynamic>;
          expect(DiagnosticsSnapshot.fromJson(raw).readyPhase, phase);
        }
      },
    );

    test(
      'path observability is additive and old peer snapshots still parse',
      () {
        final legacyPeer = PeerSnapshot.fromJson({
          'node_id': 'legacy-peer',
          'device_name': 'Legacy',
          'app_version': '0.1.146',
          'virtual_ip': '10.20.0.2',
          'nat_type': 'unknown',
          'online': true,
          'last_seen': 1,
          'state': 'connecting',
          'direct_type': 'unknown',
          'is_relay': false,
          'bytes_sent': 0,
          'bytes_received': 0,
          'direct': <String, dynamic>{},
          'relay': <String, dynamic>{},
        });
        expect(legacyPeer.pathObservability.schemaVersion, 0);
        expect(legacyPeer.pathObservability.transitions, isEmpty);

        final currentPeer = PeerSnapshot.fromJson({
          'node_id': 'current-peer',
          'device_name': 'Current',
          'app_version': '0.1.147',
          'virtual_ip': '10.20.0.3',
          'nat_type': 'endpoint_independent',
          'online': true,
          'last_seen': 1,
          'state': 'direct',
          'active_path': 'direct',
          'direct_type': 'public_udp',
          'is_relay': false,
          'bytes_sent': 10,
          'bytes_received': 20,
          'direct': <String, dynamic>{},
          'relay': <String, dynamic>{},
          'path_observability': {
            'schema_version': 1,
            'network_epoch': {
              'network_generation': 7,
              'peer_session_generation': 3,
              'remote_candidate_epoch': 11,
            },
            'lifecycle': 'online',
            'current_path': 'direct',
            'previous_path': 'relay',
            'transition_reason': 'direct_committed',
            'path_age_ms': 12,
            'path_state_revision': 9,
            'direct_state': 'committed',
            'relay_state': 'usable',
            'recovery_state': 'stable',
            'direct_health': <String, dynamic>{},
            'relay_health': <String, dynamic>{},
            'latest_handshake': <String, dynamic>{},
            'latest_validation': {'validation_rtt_ms': 18},
            'candidate_punch': {
              'candidate_pair_count': 2,
              'signaled_candidate_count': 3,
            },
            'selected_path_mtu': 1360,
            'metrics': <String, dynamic>{},
            'transitions': [
              {
                'age_ms': 12,
                'revision': 9,
                'event_kind': 'direct_committed',
                'decision': 'applied',
                'reason_code': 'direct_committed',
                'current_path': 'direct',
              },
            ],
          },
        });
        expect(currentPeer.pathObservability.schemaVersion, 1);
        expect(currentPeer.pathObservability.currentPath, 'direct');
        expect(currentPeer.pathObservability.previousPath, 'relay');
        expect(currentPeer.pathObservability.selectedPathMtu, 1360);
        expect(
          currentPeer.pathObservability.latestValidation.validationRttMs,
          18,
        );
        expect(
          currentPeer.pathObservability.transitions.single.decision,
          'applied',
        );
      },
    );
  });

  group('/events contract (shared fixture)', () {
    test('production EventsResponse parses the shared fixture', () async {
      final json = await _readFixture('events.json');
      final response = EventsResponse.fromJson(json);
      expect(response.contractVersion, 1);
      expect(response.revision, greaterThanOrEqualTo(3));
      final events = response.events;
      expect(events.length, 3);
      // seq is monotonic and usable as the /events?since=N cursor.
      final seqs = [for (final event in events) event.seq];
      for (var i = 1; i < seqs.length; i++) {
        expect(seqs[i], greaterThan(seqs[i - 1]));
      }
      // Optional fields may be absent on some events.
      expect(events[0].peerId, isNull);
    });
  });

  group('/routes contract (shared fixture)', () {
    test('production RoutesResponse parses the shared fixture', () async {
      final json = await _readFixture('routes.json');
      final response = RoutesResponse.fromJson(json);
      expect(response.contractVersion, 1);
      expect(response.interfaceName, 'p2wlan0');
      expect(response.mtu, 1420);
      expect(response.healthy, isTrue);
      expect(response.conflictCount, 0);
      final entry = response.entries.first;
      expect(entry.cidr, '10.20.0.0/16');
      expect(entry.expectedInterface, 'p2wlan0');
      expect(entry.actualInterface, 'p2wlan0');
      expect(entry.state, 'installed');
      expect(entry.owned, isTrue);
    });

    test('repair response never restarts the daemon', () async {
      final json = await _readFixture('route_repair.json');
      final response = RouteRepairResponse.fromJson(json);
      // `restartedDaemon` MUST be false — repair never restarts daemon/TUN/sessions.
      expect(response.contractVersion, 1);
      expect(response.restartedDaemon, isFalse);
      expect(response.changed, isTrue);
      expect(response.after, 'installed');
      expect(response.reason, 'installed');
    });
  });

  test('production PeersPageResponse and PermissionPreflightResponse parse fixtures', () async {
    final peers = PeersPageResponse.fromJson(
      await _readFixture('peers_page.json'),
    );
    expect(peers.contractVersion, 1);
    expect(peers.peers, isEmpty);
    final permission = PermissionPreflightResponse.fromJson(
      await _readFixture('permission_preflight.json'),
    );
    expect(permission.contractVersion, 1);
    expect(permission.state, 'runtimeVerificationRequired');
    expect(permission.canCreateTun, isNull);
    expect(permission.canModifyRoutes, isTrue);
  });

  test('unsupported contract versions fail explicitly', () async {
    final json = await _readFixture('routes.json');
    json['contractVersion'] = supportedDiagnosticsContractVersion + 1;
    expect(
      () => RoutesResponse.fromJson(json),
      throwsA(isA<UnsupportedDiagnosticsContractException>()),
    );
  });

  test('removing a required route field fails the production parser', () async {
    final json = await _readFixture('routes.json');
    (json['entries'] as List).first.remove('state');
    expect(() => RoutesResponse.fromJson(json), throwsFormatException);
  });
}
