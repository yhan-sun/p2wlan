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
    expect(snapshot.relayConnected, isTrue);
    expect(snapshot.relaySelection.selectedRegion, 'cn-east');
    expect(snapshot.relaySelection.selectedEndpoint, '203.0.113.10:18081');
    expect(snapshot.relaySelection.latencyMs, 38);
    expect(snapshot.stats.totalPeers, 2);
    expect(snapshot.stats.directConnections, 1);
    expect(snapshot.stats.relayConnections, 1);

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

  test(
    'peer latency prefers ewma and relay selection exposes pong latency',
    () {
      final peer = PeerSnapshot.fromJson({
        'node_id': 'direct-peer',
        'device_name': 'studio',
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
      expect(relaySelection.latencyMs, 25);
    },
  );

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
}
