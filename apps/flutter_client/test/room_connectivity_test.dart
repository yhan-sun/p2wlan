import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_connectivity.dart';

PeerSnapshot peer(String path, {bool online = true}) => PeerSnapshot.fromJson({
  'node_id': path,
  'online': online,
  'state': path,
  'active_path': path,
  if (path == 'relay') 'relay_confirmed_endpoint': 'tls://relay.example:443',
  if (path == 'relay') 'relay_confirmed_generation': 1,
});

void main() {
  test('partial and mixed rooms never claim every peer is direct', () {
    final partial = RoomConnectivitySummary.fromPeers([
      peer('direct'),
      peer('relay'),
      peer('connecting'),
      peer('direct', online: false),
    ]);
    expect(partial.label, '部分连通');
    expect(partial.reachable, 2);
    expect(partial.online, 3);
    expect(partial.offline, 1);
    expect(partial.details, contains('直连 1 / 中继 1 / 未连通 1'));
    expect(
      RoomConnectivitySummary.fromPeers([peer('direct'), peer('relay')]).label,
      '直连与中继',
    );
    expect(RoomConnectivitySummary.fromPeers([peer('direct')]).label, '已直连');
    expect(RoomConnectivitySummary.fromPeers([peer('relay')]).label, '中继可用');
  });
  test('online presence does not imply a usable path', () {
    final unverified = PeerSnapshot.fromJson({
      'online': true,
      'active_path': 'relay',
      'state': 'connecting',
    });
    expect(RoomConnectivitySummary.fromPeers([unverified]).reachable, 0);
    expect(RoomConnectivitySummary.fromPeers([unverified]).label, '建立加密会话');
    expect(
      RoomConnectivitySummary.fromPeers([peer('hole_punching')]).label,
      '直连探测',
    );
    expect(RoomConnectivitySummary.fromPeers([]).label, '等待好友');
  });
}
