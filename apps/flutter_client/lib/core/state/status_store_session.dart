part of 'status_store.dart';

class AccountSessionChangeException implements Exception {
  const AccountSessionChangeException(this.message);
  final String message;
  @override
  String toString() => message;
}

extension StatusStoreAccountSession on StatusStore {
  Future<void> _applyAccountChange(
    AppSettings current,
    AppSettings next,
    Future<void> Function() commit,
  ) async {
    if (accountSessionKey(current) == accountSessionKey(next)) {
      await commit();
      return;
    }
    if (_disposed || _daemonBusy || _sessionChanging) {
      throw const AccountSessionChangeException('网络操作尚未完成，请稍后再切换账号。');
    }
    _sessionChanging = true;
    _refreshGeneration++;
    lifecycleCoordinator.invalidateEventLoop();
    _eventLoopFuture = null;
    cancelSpeedTest();
    try {
      await parallelRooms.withConnectionsPaused(() async {
        if (Platform.isWindows ||
            Platform.isMacOS ||
            Platform.isLinux ||
            Platform.isAndroid) {
          final result = await stopDaemon();
          if (!result.ok) {
            throw const AccountSessionChangeException(
              '旧账号的网络未能停止，账号没有切换。请先断开本机网络后重试。',
            );
          }
        }
        _accountRequiresRestart = next.authToken.trim().isNotEmpty;
        _healthReachable = false;
        _routeHealthy = false;
        _clearSnapshot();
        _clearAccountHistory();
        await commit();
      });
    } finally {
      _sessionChanging = false;
      _notifySessionChanged();
    }
  }

  void _clearAccountHistory() {
    _peerOrder.clear();
    _peerOnlineOrder.clear();
    _peerOnlineState.clear();
    _nextPeerOrder = 0;
    _nextPeerOnlineOrder = 0;
    _lastSpeedTestResult = null;
    _lastSpeedTestError = null;
    _speedTestPeerVirtualIp = null;
    _lastSuccessfulStatusAt = null;
    _lastRouteVerificationAt = null;
  }
}
