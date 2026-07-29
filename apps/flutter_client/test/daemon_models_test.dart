import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/daemon_models.dart';

void main() {
  test('parses connected /status fixture', () async {
    final raw = await File(
      'test/fixtures/status_connected.json',
    ).readAsString();
    final snapshot = DaemonSnapshot.fromJson(
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
}
