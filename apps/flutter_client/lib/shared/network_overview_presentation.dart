import '../app/app_strings.dart';
import '../core/presentation/network_overview.dart';
import 'widgets/status_badge.dart';

String networkScopeLabel(AppStrings strings, NetworkScopeSnapshot scope) =>
    scope.name ?? (strings.isZh ? '当前网络' : 'Current network');

String networkDisplayStateLabel(
  AppStrings strings,
  NetworkDisplayState state,
) => switch (state) {
  NetworkDisplayState.stopped => strings.notRunning,
  NetworkDisplayState.starting => strings.isZh ? '连接中' : 'Connecting',
  NetworkDisplayState.running => strings.isZh ? '运行中' : 'Running',
  NetworkDisplayState.attention => strings.needsAttention,
  NetworkDisplayState.stale => strings.stale,
  NetworkDisplayState.unavailable =>
    strings.isZh ? '状态不可读' : 'Status unavailable',
  NetworkDisplayState.stopping => strings.isZh ? '断开中' : 'Disconnecting',
  NetworkDisplayState.failed => strings.isZh ? '连接失败' : 'Connection failed',
};

StatusTone networkDisplayStateTone(NetworkDisplayState state) =>
    switch (state) {
      NetworkDisplayState.running => StatusTone.good,
      NetworkDisplayState.attention ||
      NetworkDisplayState.stale ||
      NetworkDisplayState.unavailable => StatusTone.warn,
      NetworkDisplayState.failed => StatusTone.bad,
      _ => StatusTone.neutral,
    };

(StatusTone, String, String) networkOverviewStatus(
  AppStrings strings,
  NetworkOverview overview,
) {
  if (overview.hasRooms) {
    if (overview.runningRooms > 0) {
      return (
        overview.needsAttention ? StatusTone.warn : StatusTone.good,
        strings.isZh ? '房间已连接' : 'Rooms connected',
        strings.isZh
            ? '${overview.runningRooms} 个房间运行中'
            : '${overview.runningRooms} active rooms',
      );
    }
    if (overview.hasRunningNetwork) {
      final stopping = overview.rooms.any(
        (scope) => scope.state == NetworkDisplayState.stopping,
      );
      return (
        overview.needsAttention ? StatusTone.warn : StatusTone.good,
        overview.needsAttention
            ? strings.shellStatusAttention
            : strings.shellStatusHealthy,
        stopping
            ? (strings.isZh
                  ? '本机网络运行中，房间正在断开'
                  : 'Local network running; rooms disconnecting')
            : overview.isStarting
            ? (strings.isZh
                  ? '本机网络运行中，正在连接房间'
                  : 'Local network running; rooms connecting')
            : (strings.isZh
                  ? '本机网络运行中，请检查房间状态'
                  : 'Local network running; check room status'),
      );
    }
    if (overview.isStarting) {
      return (
        StatusTone.neutral,
        strings.isZh ? '连接中' : 'Connecting',
        strings.isZh ? '正在准备房间网络' : 'Preparing room networks',
      );
    }
    if (overview.needsAttention) {
      return (
        StatusTone.warn,
        strings.shellStatusAttention,
        strings.needsAttention,
      );
    }
    return (
      StatusTone.neutral,
      strings.isZh ? '断开中' : 'Disconnecting',
      strings.isZh ? '正在关闭房间网络' : 'Stopping room networks',
    );
  }
  final primary = overview.scopes.first;
  return switch (primary.state) {
    NetworkDisplayState.running => (
      StatusTone.good,
      strings.shellStatusHealthy,
      strings.shellPeersOnline(overview.onlineCount),
    ),
    NetworkDisplayState.stale => (
      StatusTone.warn,
      strings.stale,
      strings.shellStatusStaleDetail,
    ),
    NetworkDisplayState.starting => (
      StatusTone.neutral,
      strings.isZh ? '连接中' : 'Connecting',
      strings.isZh ? '正在准备本机网络' : 'Preparing the local network',
    ),
    NetworkDisplayState.stopped => (
      StatusTone.neutral,
      strings.shellStatusOffline,
      strings.shellStatusOfflineDetail,
    ),
    _ => (
      StatusTone.warn,
      strings.shellStatusAttention,
      strings.needsAttention,
    ),
  };
}
