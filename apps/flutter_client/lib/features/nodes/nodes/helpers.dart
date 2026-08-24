part of '../nodes_page.dart';

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
  if (peer.path == 'relay') {
    // Only a matching encrypted relay probe ACK is "中继已验证" (the daemon's
    // relay_confirmed_endpoint is set solely by that ACK).
    return peer.isRelayVerified ? strings.relay : strings.probing;
  }
  if (peer.path == 'direct_trial' || peer.path == 'probing') {
    // A candidate probe RTT is NOT a connection: show it only inside the
    // probing label, never as the peer's latency.
    return strings.probingWithProbeRtt(peer.probeLatencyMs);
  }
  if (peer.path == 'direct') {
    // "直连已验证" requires the daemon's encrypted direct validation ACK.
    if (!peer.isDirectVerified) return strings.probing;
    return switch (peer.connectionType) {
      'public_udp' => strings.directTypePublic,
      'lan' => strings.directTypeLan,
      'overlay' => strings.directTypeOverlay,
      _ => strings.direct,
    };
  }
  return strings.pathLabel(peer.path);
}

/// First-level path label: short, and never a stale direct/relay claim for an
/// offline device. Offline always wins.
String _rowPathLabel(AppStrings strings, PeerSnapshot peer) {
  if (_peerIsOffline(peer)) return strings.offline;
  if (peer.path == 'probing' || peer.path == 'direct_trial') {
    return strings.probing;
  }
  if (peer.path == 'relay') return strings.relay;
  if (peer.path == 'direct' && peer.isDirectVerified) return strings.direct;
  return strings.probing;
}

/// Semantic but low-saturation dot color: direct=good, relay=neutral accent,
/// probing=warn, offline=neutral. Text always accompanies the dot.
Color _rowStatusColor(BuildContext context, PeerSnapshot peer) {
  final c = P2WlanColors.of(context);
  if (_peerIsOffline(peer)) return c.offline;
  return switch (peer.path) {
    'direct' => c.direct,
    'relay' => c.relay,
    'probing' || 'direct_trial' => c.probing,
    _ => c.offline,
  };
}

String _formatLastSeen(PeerSnapshot peer) {
  final value = peer.lastSeenAt;
  if (value == null) return '—';
  final local = value.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${local.year}-${two(local.month)}-${two(local.day)} ${two(local.hour)}:${two(local.minute)}';
}

enum _NodeFilter { all, online, direct, relay, attention, offline }

enum _NodeSort { recommended, name, latency }

bool _filterMatches(_NodeFilter filter, PeerSnapshot peer) {
  return switch (filter) {
    _NodeFilter.all => true,
    _NodeFilter.online => peer.online && !_peerIsOffline(peer),
    _NodeFilter.direct => peer.path == 'direct',
    _NodeFilter.relay => peer.path == 'relay',
    _NodeFilter.attention => _peerNeedsAttention(peer),
    _NodeFilter.offline => _peerIsOffline(peer),
  };
}

List<PeerSnapshot> _applySearch(List<PeerSnapshot> peers, String query) {
  final trimmed = query.trim().toLowerCase();
  if (trimmed.isEmpty) return peers;
  return peers
      .where(
        (peer) =>
            peer.displayName.toLowerCase().contains(trimmed) ||
            peer.virtualIp.toLowerCase().contains(trimmed) ||
            peer.nodeId.toLowerCase().contains(trimmed),
      )
      .toList(growable: false);
}

List<PeerSnapshot> _applySort(List<PeerSnapshot> peers, _NodeSort sort) {
  final sorted = [...peers];
  switch (sort) {
    case _NodeSort.recommended:
      // The input is already the StatusStore's first-seen order. Keeping this
      // branch a no-op is what prevents live path/latency updates from moving
      // rows. Name and latency remain explicit, user-selected sorts.
      break;
    case _NodeSort.name:
      sorted.sort(_compareByName);
    case _NodeSort.latency:
      sorted.sort(_compareByLatency);
  }
  return sorted;
}

int _compareByName(PeerSnapshot left, PeerSnapshot right) {
  return left.displayName.toLowerCase().compareTo(
    right.displayName.toLowerCase(),
  );
}

/// Verified latency ascending; peers without a verified latency sort last.
/// Probe RTT is never treated as a latency for sorting.
int _compareByLatency(PeerSnapshot left, PeerSnapshot right) {
  final leftLatency = left.latencyMs;
  final rightLatency = right.latencyMs;
  if (leftLatency == null && rightLatency == null) {
    return _compareByName(left, right);
  }
  if (leftLatency == null) return 1;
  if (rightLatency == null) return -1;
  final byLatency = leftLatency.compareTo(rightLatency);
  if (byLatency != 0) return byLatency;
  return _compareByName(left, right);
}

int _filterCount(List<PeerSnapshot> peers, _NodeFilter filter) {
  var count = 0;
  for (final peer in peers) {
    if (_filterMatches(filter, peer)) count += 1;
  }
  return count;
}
