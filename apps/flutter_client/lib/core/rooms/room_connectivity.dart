import '../models/diagnostics_models.dart';

class RoomConnectivitySummary {
  const RoomConnectivitySummary({
    required this.direct,
    required this.relay,
    required this.pending,
    required this.offline,
    this.establishingSession = false,
    this.punching = false,
    this.dataWarning,
  });

  factory RoomConnectivitySummary.fromPeers(Iterable<PeerSnapshot> peers) {
    var direct = 0, relay = 0, pending = 0, offline = 0;
    var establishingSession = false, punching = false;
    for (final peer in peers) {
      if (!peer.online) {
        offline++;
      } else if (peer.isDirectVerified) {
        direct++;
      } else if (peer.isRelayVerified) {
        relay++;
      } else {
        pending++;
        final state = peer.state.toLowerCase();
        establishingSession |=
            state.contains('handshake') || state.contains('connect');
        punching |= state.contains('punch') || state.contains('prob');
      }
    }
    return RoomConnectivitySummary(
      direct: direct,
      relay: relay,
      pending: pending,
      offline: offline,
      establishingSession: establishingSession,
      punching: punching,
    );
  }

  factory RoomConnectivitySummary.fromSnapshot(DiagnosticsSnapshot snapshot) {
    final paths = RoomConnectivitySummary.fromPeers(snapshot.peers);
    return RoomConnectivitySummary(
      direct: paths.direct,
      relay: paths.relay,
      pending: paths.pending,
      offline: paths.offline,
      establishingSession: paths.establishingSession,
      punching: paths.punching,
      dataWarning: snapshot.roomDataPlane?.blockingLabel,
    );
  }

  final String? dataWarning;
  final int direct;
  final int relay;
  final int pending;
  final int offline;
  final bool establishingSession;
  final bool punching;
  int get established => direct + relay;
  int get online => established + pending;

  String get label {
    if (dataWarning != null) return dataWarning!;
    if (online == 0) return '等待好友';
    if (established == 0) {
      if (establishingSession) return '建立加密会话';
      if (punching) return '直连探测';
      return '建立连接中';
    }
    if (pending > 0) return '部分链路已建立';
    if (direct > 0 && relay > 0) return '直连与中继';
    return direct > 0 ? '直连已建立' : '中继已建立';
  }

  String get details =>
      '在线 $online · 链路已建立 $established · 直连 $direct / 中继 $relay / 待建链 $pending';
}

String roomDeviceNodeId(Map<String, dynamic> device) {
  final nodeId = device['node_id'];
  if (nodeId is String && nodeId.trim().isNotEmpty) return nodeId.trim();
  final id = device['id'];
  return id is String ? id.trim() : '';
}

PeerSnapshot? roomPeerForDevice(
  Map<String, dynamic> device,
  Iterable<PeerSnapshot> peers,
) {
  final id = roomDeviceNodeId(device);
  final ip = device['virtual_ip'];
  if (id.isEmpty || ip is! String || ip.isEmpty) return null;
  PeerSnapshot? matched;
  for (final peer in peers) {
    if (peer.nodeId == id && peer.virtualIp == ip) {
      if (matched != null) return null;
      matched = peer;
    }
  }
  return matched;
}

bool roomDeviceIsSnapshotLocal(
  Map<String, dynamic> device,
  DiagnosticsSnapshot? snapshot,
) =>
    snapshot != null &&
    snapshot.nodeId.isNotEmpty &&
    snapshot.virtualIp.isNotEmpty &&
    roomDeviceNodeId(device) == snapshot.nodeId &&
    device['virtual_ip'] == snapshot.virtualIp;

bool roomDeviceMappingMismatch(
  Map<String, dynamic> device,
  Iterable<PeerSnapshot> peers,
) =>
    roomPeerForDevice(device, peers) == null &&
    peers.any(
      (peer) =>
          roomDeviceNodeId(device).isNotEmpty &&
              peer.nodeId == roomDeviceNodeId(device) ||
          device['virtual_ip'] is String &&
              device['virtual_ip'] != '' &&
              peer.virtualIp == device['virtual_ip'],
    );

String roomDeviceDataLabel(
  Map<String, dynamic> device,
  DiagnosticsSnapshot? snapshot,
) {
  if (snapshot == null) return '本机未连接';
  if (snapshot.peerSnapshotStale) return '状态待更新';
  if (roomDeviceMappingMismatch(device, snapshot.peers)) return '地址待同步';
  final data = snapshot.roomDataPlane;
  if (data == null) return '数据状态未验证';
  if (data.blockingLabel case final label?) return label;
  if (data.localIp != snapshot.virtualIp) return '本机地址待同步';
  if (roomDeviceIsSnapshotLocal(device, snapshot)) return '房间授权有效';
  final id = roomDeviceNodeId(device);
  final ip = device['virtual_ip'];
  Map<String, dynamic>? traffic;
  for (final peer in data.peers) {
    if (id.isNotEmpty && peer['node_id'] == id && peer['virtual_ip'] == ip) {
      traffic = peer;
      break;
    }
  }
  if (traffic == null) return '成员授权待同步';
  final drop = data.lastDrop;
  if (drop != null &&
      drop['age_ms'] is num &&
      (drop['age_ms'] as num) + data.elapsedMs < 10000 &&
      (drop['peer_id'] == id || drop['destination_ip'] == ip)) {
    final lastSuccess =
        traffic[drop['direction'] == 'rx'
            ? 'last_rx_age_ms'
            : 'last_tx_age_ms'];
    if (lastSuccess is! num || lastSuccess > (drop['age_ms'] as num)) {
      return switch (drop['reason']) {
        'source_not_local' || 'overlay_source_rejected' => '源地址被拒绝',
        'unknown_virtual_ip' || 'peer_ip_mismatch' => '地址映射异常',
        'local_ip_mismatch' => '本机地址待同步',
        'acl_denied' => '访问规则已阻止',
        'authorization_expired' => '房间授权已过期',
        'authorization_missing' ||
        'authorization_changed' ||
        'peer_missing' => '房间授权待同步',
        _ => '房间数据包被拒绝',
      };
    }
  }
  final receivedAge = traffic['last_rx_age_ms'];
  if (receivedAge is num &&
      receivedAge + data.elapsedMs < 30000 &&
      traffic['rx_delivered_packets'] is num &&
      (traffic['rx_delivered_packets'] as num) > 0) {
    return '近期已收房间数据';
  }
  return '尚未验证收包';
}
