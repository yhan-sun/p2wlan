import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_connectivity.dart';

const device = {'id': 'b', 'virtual_ip': '10.21.1.3'};
PeerSnapshot direct(String id, String ip) => PeerSnapshot.fromJson({
  'node_id': id,
  'virtual_ip': ip,
  'online': true,
  'state': 'direct',
  'active_path': 'direct',
});
DiagnosticsSnapshot snapshot({
  String state = 'valid',
  int lease = 30000,
  Map<String, dynamic>? drop,
  int received = 0,
}) => DiagnosticsSnapshot.fromJson({
  'network_id': 'room-test',
  'node_id': 'a',
  'virtual_ip': '10.21.1.2',
  'peers': [
    {
      'node_id': 'b',
      'virtual_ip': '10.21.1.3',
      'online': true,
      'state': 'direct',
      'active_path': 'direct',
    },
  ],
  'room_dataplane': {
    'authorization_state': state,
    'local_ip': '10.21.1.2',
    'lease_remaining_ms': lease,
    'last_drop': drop,
    'peers': [
      {
        'node_id': 'b',
        'virtual_ip': '10.21.1.3',
        'rx_delivered_packets': received,
        if (received > 0) 'last_rx_age_ms': 0,
      },
    ],
  },
});

void main() {
  test('room peer identity and address must both match', () {
    final peer = direct('b', '10.21.1.3');
    expect(roomPeerForDevice(device, [peer]), same(peer));
    expect(
      roomPeerForDevice({'node_id': 'b', 'virtual_ip': '10.21.1.3'}, [peer]),
      same(peer),
    );
    expect(roomPeerForDevice(device, [direct('b', '10.21.1.9')]), isNull);
    expect(
      roomPeerForDevice(device, [direct('old-device', '10.21.1.3')]),
      isNull,
    );
    expect(roomPeerForDevice({'virtual_ip': '10.21.1.3'}, [peer]), isNull);
    expect(roomPeerForDevice(device, [peer, peer]), isNull);
    expect(
      roomDeviceMappingMismatch(device, [direct('b', '10.21.1.9')]),
      isTrue,
    );
    expect(
      roomDeviceMappingMismatch(device, [direct('old', '10.21.1.3')]),
      isTrue,
    );
  });
  test('local address reuse cannot turn another identity into this device', () {
    expect(
      roomDeviceIsSnapshotLocal({
        'id': 'a',
        'virtual_ip': '10.21.1.2',
      }, snapshot()),
      isTrue,
    );
    expect(
      roomDeviceIsSnapshotLocal({
        'id': 'b',
        'virtual_ip': '10.21.1.2',
      }, snapshot()),
      isFalse,
    );
  });
  test('transport Direct does not claim room IP reachability', () {
    final current = snapshot();
    expect(current.peers.single.isDirectVerified, isTrue);
    expect(
      RoomConnectivitySummary.fromSnapshot(current).details,
      isNot(contains('可互通')),
    );
    expect(roomDeviceDataLabel(device, current), '尚未验证收包');
    expect(roomDeviceDataLabel(device, snapshot(received: 1)), '近期已收房间数据');
  });
  test(
    'lease failures and expiry override room summary without falsifying Direct',
    () {
      for (final state in ['missing', 'expired', 'local_ip_mismatch']) {
        final current = snapshot(state: state);
        expect(current.peers.single.isDirectVerified, isTrue);
        expect(
          RoomConnectivitySummary.fromSnapshot(current).label,
          current.roomDataPlane!.blockingLabel,
        );
        expect(
          roomDeviceDataLabel(device, current),
          current.roomDataPlane!.blockingLabel,
        );
      }
      expect(roomDeviceDataLabel(device, snapshot(lease: 0)), '房间授权已过期');
    },
  );
  test('old daemon and stale peers remain explicitly unverified', () {
    final old = DiagnosticsSnapshot.fromJson({'peers': []});
    expect(roomDeviceDataLabel(device, old), '数据状态未验证');
    final stale = DiagnosticsSnapshot.fromJson({
      ...snapshot().raw,
      'peer_snapshot_stale': true,
    });
    expect(roomDeviceDataLabel(device, stale), '状态待更新');
  });
  test('only recent attributable packet failures are shown', () {
    final drop = {
      'reason': 'peer_ip_mismatch',
      'peer_id': 'b',
      'direction': 'rx',
      'age_ms': 0,
    };
    expect(roomDeviceDataLabel(device, snapshot(drop: drop)), '地址映射异常');
    expect(
      roomDeviceDataLabel(
        device,
        snapshot(drop: {...drop, 'peer_id': 'other'}),
      ),
      '尚未验证收包',
    );
    expect(
      roomDeviceDataLabel(device, snapshot(drop: {...drop, 'age_ms': 10001})),
      '尚未验证收包',
    );
    expect(
      roomDeviceDataLabel(
        device,
        snapshot(received: 1, drop: {...drop, 'age_ms': 100}),
      ),
      '近期已收房间数据',
    );
  });
}
