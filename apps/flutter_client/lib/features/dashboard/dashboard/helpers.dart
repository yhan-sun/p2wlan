part of '../dashboard_page.dart';

/// Overall virtual-network state derived ONLY from the daemon's own signals
/// (snapshot presence, staleness, health.status). No inferred states.
enum _NetworkStatus { stopped, healthy, degraded, stale }

_NetworkStatus _networkStatus(
  DiagnosticsSnapshot? snapshot, {
  required bool snapshotStale,
}) {
  if (snapshotStale) return _NetworkStatus.stale;
  if (snapshot == null) return _NetworkStatus.stopped;
  return snapshot.health.status.toLowerCase() == 'healthy'
      ? _NetworkStatus.healthy
      : _NetworkStatus.degraded;
}

StatusTone _networkStatusTone(_NetworkStatus status) => switch (status) {
  _NetworkStatus.stopped => StatusTone.neutral,
  _NetworkStatus.healthy => StatusTone.good,
  _NetworkStatus.degraded || _NetworkStatus.stale => StatusTone.warn,
};

String _networkStatusLabel(
  AppStrings strings,
  _NetworkStatus status,
  bool canControlLocalDaemon,
) => switch (status) {
  _NetworkStatus.stopped =>
    canControlLocalDaemon ? strings.virtualNetworkStopped : strings.unavailable,
  _NetworkStatus.healthy => strings.healthy,
  _NetworkStatus.degraded => strings.degraded,
  _NetworkStatus.stale => strings.stale,
};

/// Connection counts derived from peer state only (path/online), never from
/// stats or daemon-side counters.
class _PeerCounts {
  const _PeerCounts({
    required this.online,
    required this.direct,
    required this.relay,
    required this.probing,
    required this.offline,
    required this.total,
  });

  final int online;
  final int direct;
  final int relay;
  final int probing;
  final int offline;
  final int total;
}

_PeerCounts _countPeers(List<PeerSnapshot> peers) {
  var online = 0;
  var direct = 0;
  var relay = 0;
  var probing = 0;
  var offline = 0;
  for (final peer in peers) {
    if (peer.online) online += 1;
    switch (peer.path) {
      case 'direct':
        direct += 1;
      case 'relay':
        relay += 1;
      case 'probing' || 'direct_trial':
        probing += 1;
      default:
        offline += 1;
    }
  }
  return _PeerCounts(
    online: online,
    direct: direct,
    relay: relay,
    probing: probing,
    offline: offline,
    total: peers.length,
  );
}

/// Most relevant peers for the dashboard overview: attention first, then
/// relay, direct, remaining online, offline last. Capped so offline devices
/// never fill the page.
List<PeerSnapshot> _topOverviewPeers(
  List<PeerSnapshot> peers, {
  int limit = 6,
}) {
  final sorted = [...peers]..sort(_compareDashboardPeers);
  if (sorted.length <= limit) return sorted;
  return sorted.sublist(0, limit);
}

int _compareDashboardPeers(PeerSnapshot left, PeerSnapshot right) {
  final rank = _dashboardPeerRank(left).compareTo(_dashboardPeerRank(right));
  if (rank != 0) return rank;
  final recent = right.sortTimestampMs.compareTo(left.sortTimestampMs);
  if (recent != 0) return recent;
  return left.displayName.compareTo(right.displayName);
}

int _dashboardPeerRank(PeerSnapshot peer) {
  if (!peer.online || peer.path == 'offline') return 4;
  if (peer.lastError != null ||
      peer.path == 'probing' ||
      peer.path == 'direct_trial') {
    return 0;
  }
  if (peer.path == 'relay') return 1;
  if (peer.path == 'direct') return 2;
  return 3;
}

String _peerStatusLabel(AppStrings strings, PeerSnapshot peer) {
  if (!peer.online || peer.path == 'offline') return strings.offline;
  return switch (peer.path) {
    'direct' => strings.direct,
    'relay' => strings.relay,
    'probing' || 'direct_trial' => strings.probing,
    _ => strings.offline,
  };
}

/// Status color semantics: Direct=good, Relay=brand accent (a normal usable
/// path, never an error), probing=warn, offline=neutral.
Color _peerStatusColor(BuildContext context, PeerSnapshot peer) {
  final isDark = Theme.of(context).brightness == Brightness.dark;
  if (!peer.online || peer.path == 'offline') {
    return isDark ? AppTokens.colorDarkNeutralText : AppTokens.colorNeutralText;
  }
  return switch (peer.path) {
    'direct' => isDark ? AppTokens.colorDarkGoodText : AppTokens.colorGoodText,
    'relay' => isDark ? AppTokens.colorDarkAccent : AppTokens.colorAccent,
    'probing' || 'direct_trial' =>
      isDark ? AppTokens.colorDarkWarnText : AppTokens.colorWarnText,
    _ => isDark ? AppTokens.colorDarkNeutralText : AppTokens.colorNeutralText,
  };
}

/// Verified path latency, else probe RTT explicitly labeled as a probe, else
/// no data. A candidate probe RTT is never shown as the connection latency.
String _peerLatencyLabel(AppStrings strings, PeerSnapshot peer) {
  final latency = peer.latencyMs;
  if (latency != null) return formatLatency(latency);
  final probe = peer.probeLatencyMs;
  if (probe != null) return strings.probeRtt(probe);
  return '—';
}

String? _dashboardIssueMessage({
  required AppStrings strings,
  required bool daemonAvailable,
  required bool snapshotStale,
  required bool statusReachable,
  required String? statusError,
  required bool healthReachable,
  required String? healthError,
  required String? error,
  required DiagnosticsSnapshot? snapshot,
}) {
  if (!daemonAvailable) return strings.offlineSnapshotMessage;
  if (snapshotStale) return strings.staleSnapshotMessage;
  if (!statusReachable && statusError != null) {
    return strings.statusMessage(statusError) ?? statusError;
  }
  if (!healthReachable && healthError != null) {
    return strings.statusMessage(healthError) ?? healthError;
  }
  final status = _networkStatus(snapshot, snapshotStale: snapshotStale);
  if (status != _NetworkStatus.healthy && error != null) {
    return strings.statusMessage(error) ?? error;
  }
  final health = snapshot?.health;
  if (health?.reauthRequired == true) return strings.issueReauthRequired;
  if (health != null && !health.controlConnected) {
    return strings.issueControlDisconnected;
  }
  final reason = health?.reason?.trim();
  if (reason != null && reason.isNotEmpty) return reason;
  return null;
}

({Color bg, Color border, Color text}) _tonePanelColors(
  BuildContext context,
  StatusTone tone,
) {
  final theme = Theme.of(context);
  final isDark = theme.brightness == Brightness.dark;
  if (isDark) {
    return switch (tone) {
      StatusTone.good => (
        bg: AppTokens.colorDarkGoodBg,
        border: AppTokens.colorDarkGoodBorder,
        text: AppTokens.colorDarkGoodText,
      ),
      StatusTone.warn => (
        bg: AppTokens.colorDarkWarnBg,
        border: AppTokens.colorDarkWarnBorder,
        text: AppTokens.colorDarkWarnText,
      ),
      StatusTone.bad => (
        bg: AppTokens.colorDarkBadBg,
        border: AppTokens.colorDarkBadBorder,
        text: AppTokens.colorDarkBadText,
      ),
      StatusTone.neutral => (
        bg: AppTokens.colorDarkNeutralBg,
        border: AppTokens.colorDarkNeutralBorder,
        text: AppTokens.colorDarkNeutralText,
      ),
    };
  }

  return switch (tone) {
    StatusTone.good => (
      bg: AppTokens.colorGoodBg,
      border: AppTokens.colorGoodBorder,
      text: AppTokens.colorGoodText,
    ),
    StatusTone.warn => (
      bg: AppTokens.colorWarnBg,
      border: AppTokens.colorWarnBorder,
      text: AppTokens.colorWarnText,
    ),
    StatusTone.bad => (
      bg: AppTokens.colorBadBg,
      border: AppTokens.colorBadBorder,
      text: AppTokens.colorBadText,
    ),
    StatusTone.neutral => (
      bg: theme.colorScheme.surfaceContainerHighest,
      border: theme.colorScheme.outline,
      text: theme.colorScheme.onSurfaceVariant,
    ),
  };
}
