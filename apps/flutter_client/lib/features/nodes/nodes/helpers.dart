part of '../nodes_page.dart';

String _routeLabel(AppStrings strings, PeerSnapshot peer) =>
    strings.routeLabel(peer.path, peer.isRelay);

List<_PeerGroup> _buildPeerGroups(
  List<PeerSnapshot> peers,
  AppStrings strings,
) {
  final attention = <PeerSnapshot>[];
  final direct = <PeerSnapshot>[];
  final relay = <PeerSnapshot>[];
  final offline = <PeerSnapshot>[];

  for (final peer in peers) {
    if (_peerIsOffline(peer)) {
      offline.add(peer);
    } else if (_peerNeedsAttention(peer)) {
      attention.add(peer);
    } else if (peer.path == 'direct') {
      direct.add(peer);
    } else if (peer.path == 'relay') {
      relay.add(peer);
    } else {
      offline.add(peer);
    }
  }

  return [
    if (attention.isNotEmpty)
      _PeerGroup(
        title: strings.attentionDevices,
        tone: StatusTone.bad,
        peers: attention,
      ),
    if (direct.isNotEmpty)
      _PeerGroup(
        title: strings.directDevices,
        tone: StatusTone.good,
        peers: direct,
      ),
    if (relay.isNotEmpty)
      _PeerGroup(
        title: strings.relayDevices,
        tone: StatusTone.warn,
        peers: relay,
      ),
    if (offline.isNotEmpty)
      _PeerGroup(
        title: strings.offlineDevices,
        tone: StatusTone.neutral,
        peers: offline,
      ),
  ];
}

List<PeerSnapshot> _dedupeAndSortPeers(List<PeerSnapshot> peers) {
  final byKey = <String, PeerSnapshot>{};
  for (final peer in peers) {
    final key = _peerDedupeKey(peer);
    final known = byKey[key];
    if (known == null || _comparePeers(peer, known) < 0) {
      byKey[key] = peer;
    }
  }
  final sorted = byKey.values.toList(growable: false);
  sorted.sort(_comparePeers);
  return sorted;
}

String _peerDedupeKey(PeerSnapshot peer) {
  final ip = peer.virtualIp.trim();
  if (ip.isNotEmpty) return 'ip:$ip';
  return 'node:${peer.nodeId}';
}

int _comparePeers(PeerSnapshot left, PeerSnapshot right) {
  final rank = _peerSortRank(left).compareTo(_peerSortRank(right));
  if (rank != 0) return rank;
  final recent = right.sortTimestampMs.compareTo(left.sortTimestampMs);
  if (recent != 0) return recent;
  return left.displayName.compareTo(right.displayName);
}

int _peerSortRank(PeerSnapshot peer) {
  if (_peerIsOffline(peer)) return 3;
  if (_peerNeedsAttention(peer)) return 0;
  if (peer.path == 'direct') return 1;
  if (peer.path == 'relay') return 2;
  return 3;
}

bool _peerNeedsAttention(PeerSnapshot peer) {
  if (_peerIsOffline(peer)) return false;
  if (peer.lastError != null) return true;
  return peer.online && (peer.path == 'probing' || peer.path == 'direct_trial');
}

bool _peerIsOffline(PeerSnapshot peer) =>
    !peer.online || peer.path == 'offline';

bool _canRunSpeedTest(PeerSnapshot peer) =>
    peer.online && peer.virtualIp.trim().isNotEmpty;

String _connectionLabel(AppStrings strings, PeerSnapshot peer) {
  if (_peerIsOffline(peer)) return strings.offline;
  if (peer.path == 'relay') return strings.relay;
  if (peer.path == 'direct_trial' || peer.path == 'probing') {
    return strings.probing;
  }
  if (peer.path == 'direct') {
    return switch (peer.connectionType) {
      'public_udp' => strings.isZh ? '公网直连' : 'Public direct',
      'lan' => strings.isZh ? '局域网直连' : 'LAN direct',
      'overlay' => strings.isZh ? 'Overlay 直连' : 'Overlay direct',
      _ => strings.direct,
    };
  }
  return strings.pathLabel(peer.path);
}

String _formatLastSeen(PeerSnapshot peer) {
  final value = peer.lastSeenAt;
  if (value == null) return '—';
  final local = value.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${local.year}-${two(local.month)}-${two(local.day)} ${two(local.hour)}:${two(local.minute)}';
}
