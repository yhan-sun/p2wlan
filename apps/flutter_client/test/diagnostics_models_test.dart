import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';

void main() {
  test('app settings persist language without breaking old settings', () {
    final oldSettings = AppSettings.fromJson({
      'diagnosticsUrl': 'http://127.0.0.1:39277/status',
    });
    expect(oldSettings.languageCode, defaultLanguageCode);

    final zhSettings = oldSettings.copyWith(languageCode: 'zh_CN');
    expect(zhSettings.languageCode, AppLanguage.simplifiedChinese.code);
    expect(zhSettings.toJson()['languageCode'], 'zh-Hans');
  });

  test('parses connected /status fixture', () async {
    final raw = await File(
      'test/fixtures/status_connected.json',
    ).readAsString();
    final snapshot = DiagnosticsSnapshot.fromJson(
      jsonDecode(raw) as Map<String, dynamic>,
    );

    expect(snapshot.nodeId, 'node-local-abcdef1234567890');
    expect(snapshot.virtualIp, '10.20.0.10');
    expect(snapshot.networkId, 'default');
    expect(snapshot.udpLocalAddr, '192.0.2.10:60207');
    expect(snapshot.health.status, 'healthy');
    expect(snapshot.health.controlConnected, isTrue);
    expect(snapshot.health.controlApiReachable, isTrue);
    expect(snapshot.health.deviceLeaseHealthy, isTrue);
    expect(snapshot.health.lastDeviceLeaseSuccessSecsAgo, 1);
    expect(snapshot.relayConnected, isTrue);
    expect(snapshot.relaySelection.selectedRegion, 'cn-east');
    expect(snapshot.relaySelection.selectedEndpoint, '203.0.113.10:18081');
    expect(snapshot.relaySelection.latencyMs, 38);
    expect(snapshot.stats.totalPeers, 2);
    expect(snapshot.stats.directConnections, 1);
    expect(snapshot.stats.relayConnections, 1);
    expect(snapshot.natProfile?.mappingBehavior, 'endpoint_independent');
    expect(snapshot.natProfile?.filteringBehavior, 'address_dependent');
    expect(snapshot.natProfile?.publicEndpoint, '198.51.100.20:62000');
    expect(snapshot.natProfile?.traversalType, NatTraversalType.restrictedCone);
    expect(snapshot.natProfile?.probabilityTotal, closeTo(100, 0.01));
    expect(snapshot.natProfile?.maxTypeProbabilities, hasLength(1));
    expect(
      snapshot.natProfile?.maxTypeProbabilities.single.type,
      NatTraversalType.restrictedCone,
    );
    expect(
      snapshot.natProfile?.maxTypeProbabilities.single.probability,
      closeTo(70, 0.01),
    );

    final directPeer = snapshot.peers.firstWhere(
      (peer) => peer.nodeId == 'peer-direct-001',
    );
    expect(directPeer.virtualIp, '10.20.0.11');
    expect(directPeer.path, 'direct');
    expect(directPeer.connectionType, 'public_udp');
    expect(directPeer.latencyMs, 24);

    final relayPeer = snapshot.peers.firstWhere(
      (peer) => peer.nodeId == 'peer-relay-002',
    );
    expect(relayPeer.virtualIp, '10.20.0.12');
    expect(relayPeer.path, 'relay');
    expect(relayPeer.connectionType, 'relay');
    expect(relayPeer.latencyMs, 43);
    expect(relayPeer.lastError, 'direct probe timed out');
  });

  test('old health snapshots inherit the composite control state', () {
    final health = HealthSnapshot.fromJson({
      'status': 'healthy',
      'control_connected': true,
    });

    expect(health.controlApiReachable, isTrue);
    expect(health.deviceLeaseHealthy, isTrue);
  });

  test('classifies NAT traversal types from mapping and filtering', () {
    NatTraversalType classify(String mapping, String filtering) {
      return NatProfileSnapshot.fromJson({
        'mapping_behavior': mapping,
        'filtering_behavior': filtering,
      }).traversalType;
    }

    expect(
      classify('endpoint_independent', 'endpoint_independent'),
      NatTraversalType.fullCone,
    );
    expect(
      classify('endpoint_independent', 'address_dependent'),
      NatTraversalType.restrictedCone,
    );
    expect(
      classify('endpoint_independent', 'address_or_port_dependent'),
      NatTraversalType.portRestrictedCone,
    );
    expect(
      classify('address_or_port_dependent', 'address_or_port_dependent'),
      NatTraversalType.symmetric,
    );
  });

  test('infers probabilities when filtering behavior is still unknown', () {
    final profile = NatProfileSnapshot.fromJson({
      'mapping_behavior': 'endpoint_independent',
      'filtering_behavior': 'unknown',
      'confidence': 90,
    });
    final probabilities = {
      for (final item in profile.typeProbabilities) item.type: item.probability,
    };

    expect(profile.traversalType, NatTraversalType.unknown);
    expect(profile.probabilityTotal, closeTo(100, 0.01));
    expect(probabilities[NatTraversalType.fullCone], closeTo(30, 0.01));
    expect(probabilities[NatTraversalType.restrictedCone], closeTo(30, 0.01));
    expect(
      probabilities[NatTraversalType.portRestrictedCone],
      closeTo(30, 0.01),
    );
    expect(probabilities[NatTraversalType.symmetric], closeTo(10, 0.01));
    expect(
      profile.maxTypeProbabilities.map((item) => item.type),
      orderedEquals([
        NatTraversalType.fullCone,
        NatTraversalType.restrictedCone,
        NatTraversalType.portRestrictedCone,
      ]),
    );
  });

  test('normalizes explicit NAT probability payloads', () {
    final profile = NatProfileSnapshot.fromJson({
      'mapping_behavior': 'endpoint_independent',
      'filtering_behavior': 'address_dependent',
      'type_probabilities': {
        'full_cone': 0.1,
        'restricted_cone': 0.7,
        'port_restricted_cone': 0.1,
        'symmetric': 0.1,
      },
    });
    final probabilities = {
      for (final item in profile.typeProbabilities) item.type: item.probability,
    };

    expect(profile.probabilityTotal, closeTo(100, 0.01));
    expect(probabilities[NatTraversalType.restrictedCone], closeTo(70, 0.01));
    expect(
      profile.maxTypeProbabilities.single.type,
      NatTraversalType.restrictedCone,
    );
  });

  test(
    'peer latency prefers ewma and relay selection exposes pong latency',
    () {
      final peer = PeerSnapshot.fromJson({
        'node_id': 'direct-peer',
        'device_name': 'studio',
        'app_version': '0.1.68',
        'virtual_ip': '10.20.0.30',
        'online': true,
        'state': 'direct',
        'active_path': 'direct',
        'direct_type': 'public_udp',
        'is_relay': false,
        'direct': {'latency_ms': 48, 'rtt_ewma_ms': 31},
        'relay': <String, dynamic>{},
      });
      final relaySelection = RelaySelectionSnapshot.fromJson({
        'selected_connect_latency_ms': 45,
        'selected_last_pong_rtt_ms': 19,
        'selected_rtt_ewma_ms': 25,
      });

      expect(peer.latencyMs, 31);
      expect(peer.appVersion, '0.1.68');
      expect(relaySelection.latencyMs, 25);
    },
  );

  test('remote relay RTT is not presented as local peer RTT', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'relay-peer',
      'device_name': 'relay-device',
      'virtual_ip': '10.20.0.50',
      'online': true,
      'state': 'relay',
      'active_path': 'relay',
      'direct_type': 'relay',
      'is_relay': true,
      'remote_relay_latency_ms': 38,
      'relay_confirmed_endpoint': 'relay.test:443',
      'relay_confirmed_generation': 1,
      'direct': <String, dynamic>{},
      'relay': <String, dynamic>{},
    });

    expect(peer.latencyMs, isNull);
  });

  test('online peer without a verified path remains probing, not offline', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'online-pending-peer',
      'device_name': 'pending-device',
      'virtual_ip': '10.20.0.51',
      'online': true,
      'state': 'idle',
      'active_path': null,
      'direct': <String, dynamic>{},
      'relay': <String, dynamic>{},
    });

    expect(peer.path, 'probing');
    expect(peer.connectionType, 'probing');
    expect(peer.latencyMs, isNull);
  });

  test('network generation refresh is not surfaced as peer error', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'relay-peer',
      'device_name': 'travel-mac',
      'virtual_ip': '10.20.0.40',
      'online': true,
      'state': 'relay',
      'active_path': 'relay',
      'direct_type': 'relay',
      'is_relay': true,
      'relay_confirmed_endpoint': 'relay.test:443',
      'relay_confirmed_generation': 0,
      'direct': {
        'last_error_code': 'network_generation_changed',
        'last_error': 'network_generation_changed: refreshed UDP candidates',
      },
      'relay': {'latency_ms': 33},
    });

    expect(peer.path, 'relay');
    expect(peer.lastError, isNull);
  });

  test('direct peer ignores a historical relay transport failure', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'direct-peer',
      'device_name': 'studio-mac',
      'virtual_ip': '10.20.0.41',
      'online': true,
      'state': 'direct',
      'active_path': 'direct',
      'direct_type': 'public_udp',
      'is_relay': false,
      'direct': {'last_success_age_ms': 250, 'consecutive_failures': 0},
      'relay': {
        'last_failure_age_ms': 120000,
        'consecutive_failures': 1,
        'last_error_code': 'relay_transport_failed',
        'last_error': 'relay connection closed',
      },
    });

    expect(peer.path, 'direct');
    expect(peer.connectionType, 'public_udp');
    expect(peer.lastError, isNull);
  });

  test('active path errors take precedence over fallback path errors', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'relay-peer',
      'device_name': 'travel-mac',
      'virtual_ip': '10.20.0.42',
      'online': true,
      'state': 'relay',
      'active_path': 'relay',
      'direct_type': 'relay',
      'is_relay': true,
      'relay_confirmed_endpoint': 'relay.test:443',
      'relay_confirmed_generation': 0,
      'direct': {
        'last_error_code': 'direct_probe_failed',
        'last_error': 'direct probe timed out',
      },
      'relay': {
        'last_error_code': 'relay_transport_failed',
        'last_error': 'relay connection closed',
      },
    });

    expect(peer.lastError, 'relay connection closed');
  });

  test('offline peers stay offline even when path selection says relay', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'offline-peer',
      'device_name': 'old-mac',
      'virtual_ip': '10.20.0.20',
      'online': false,
      'last_seen': 1784710187,
      'state': 'closed',
      'active_path': null,
      'direct_type': 'unknown',
      'is_relay': false,
      'direct': <String, dynamic>{},
      'relay': <String, dynamic>{},
      'current_path_selection': {
        'path': 'relay',
        'reason': 'relay would be preferred if reachable',
      },
    });

    expect(peer.online, isFalse);
    expect(peer.path, 'offline');
    expect(peer.connectionType, 'offline');
    expect(peer.latencyMs, isNull);
  });

  test('missing online lifecycle evidence fails closed', () {
    for (final fixture in <Map<String, dynamic>>[
      {
        'state': 'direct',
        'active_path': 'direct',
        'direct_type': 'public_udp',
        'direct': {'latency_ms': 7},
        'relay': <String, dynamic>{},
      },
      {
        'state': 'relay',
        'active_path': 'relay',
        'direct_type': 'relay',
        'relay_confirmed_endpoint': 'relay.test:443',
        'relay_confirmed_generation': 2,
        'direct': <String, dynamic>{},
        'relay': {'latency_ms': 19},
      },
    ]) {
      final peer = PeerSnapshot.fromJson({
        'node_id': 'partial-peer',
        'device_name': 'partial',
        'virtual_ip': '10.20.0.60',
        ...fixture,
      });
      expect(peer.online, isFalse);
      expect(peer.path, 'offline');
      expect(peer.connectionType, 'offline');
      expect(peer.latencyMs, isNull);
    }
  });

  test('candidate probe RTT is never displayed as connection latency', () {
    // A peer whose direct candidate probe succeeded with 8ms is STILL not a
    // direct connection: probing state must expose the probe RTT only through
    // probeLatencyMs, and latencyMs (the number rendered as the peer's
    // latency) must be null.
    final peer = PeerSnapshot.fromJson({
      'node_id': 'probing-peer',
      'device_name': 'air-mac',
      'virtual_ip': '10.20.0.50',
      'online': true,
      'state': 'hole_punching',
      'active_path': null,
      'direct_type': 'unknown',
      'is_relay': false,
      'direct': {'latency_ms': 8, 'rtt_ewma_ms': 8},
      'relay': <String, dynamic>{},
      'current_path_selection': {
        'path': 'direct',
        'reason': 'direct trial',
        'reason_code': 'direct_trial',
        'direct_confirmed': false,
        'relay_hedged': false,
      },
    });

    expect(peer.path, 'direct_trial');
    expect(peer.connectionType, 'probing');
    expect(peer.isDirectVerified, isFalse);
    expect(
      peer.latencyMs,
      isNull,
      reason: 'a candidate probe RTT must never be shown as connection latency',
    );
    expect(peer.probeLatencyMs, 8);
  });

  test('relay verified requires the daemon relay_confirmed_endpoint', () {
    // active_path relay alone (e.g. a relay fallback with no matching probe
    // ACK evidence) must NOT be presented as "中继已验证".
    final notVerified = PeerSnapshot.fromJson({
      'node_id': 'relay-peer',
      'device_name': 'travel-mac',
      'virtual_ip': '10.20.0.51',
      'online': true,
      'state': 'relay',
      'active_path': 'relay',
      'direct_type': 'relay',
      'is_relay': true,
      'direct': <String, dynamic>{},
      'relay': {'latency_ms': 33},
    });
    expect(notVerified.path, 'probing');
    expect(notVerified.relayConfirmedEndpoint, isNull);
    expect(notVerified.isRelayVerified, isFalse);
    expect(
      notVerified.latencyMs,
      isNull,
      reason:
          'relay RTT without encrypted relay confirmation is not usable latency',
    );
    expect(
      notVerified.probeLatencyMs,
      isNull,
      reason: 'relay health RTT is not a candidate probe RTT',
    );

    // A matching encrypted relay probe ACK sets relay_confirmed_endpoint; only
    // then is the peer "中继已验证".
    final verified = PeerSnapshot.fromJson({
      'node_id': 'relay-peer',
      'device_name': 'travel-mac',
      'virtual_ip': '10.20.0.51',
      'online': true,
      'state': 'relay',
      'active_path': 'relay',
      'direct_type': 'relay',
      'is_relay': true,
      'direct': <String, dynamic>{},
      'relay': {'latency_ms': 33},
      'relay_confirmed_endpoint': 'tcp://relay.test:18081',
      'relay_confirmed_generation': 3,
    });
    expect(verified.isRelayVerified, isTrue);
    expect(verified.latencyMs, 33);
  });

  test('direct verified requires the daemon direct state', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'direct-peer',
      'device_name': 'studio-mac',
      'virtual_ip': '10.20.0.52',
      'online': true,
      'state': 'direct',
      'active_path': 'direct',
      'direct_type': 'public_udp',
      'is_relay': false,
      'direct': {'latency_ms': 12},
      'relay': <String, dynamic>{},
    });
    expect(peer.path, 'direct');
    expect(peer.isDirectVerified, isTrue);
    expect(peer.latencyMs, 12);
  });

  test('direct proof pending relay-first promotion is still probing', () {
    final peer = PeerSnapshot.fromJson({
      'node_id': 'relay-first-peer',
      'device_name': 'air-mac',
      'virtual_ip': '10.20.0.53',
      'online': true,
      'state': 'direct',
      'active_path': null,
      'direct_type': 'public_udp',
      'is_relay': false,
      'direct': {'latency_ms': 8, 'rtt_ewma_ms': 8},
      'relay': {'latency_ms': 4},
      'current_path_selection': {
        'path': null,
        'reason_code': 'path_relay_first_pending',
        'direct_confirmed': false,
      },
    });

    expect(peer.path, 'probing');
    expect(peer.isDirectVerified, isFalse);
    expect(peer.latencyMs, isNull);
  });
}
