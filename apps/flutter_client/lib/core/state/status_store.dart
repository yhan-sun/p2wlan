import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart' show AppLifecycleState;

import '../api/diagnostics_api.dart';
import '../daemon/daemon_controller.dart';
import '../models/diagnostics_models.dart';
import 'settings_store.dart';

class StatusStore extends ChangeNotifier {
  StatusStore({
    required this.settingsStore,
    required this.diagnosticsApi,
    DaemonController? daemonController,
    this.autoRefreshInterval = defaultActivePollingInterval,
    this.backgroundRefreshInterval = defaultBackgroundPollingInterval,
    this.maxSnapshotAge = defaultMaxSnapshotAge,
    this.enableFreshnessTimer = false,
    this.startupCatalogRefreshTimeout = defaultStartupCatalogRefreshTimeout,
    this.startupCatalogRefreshInterval = defaultStartupCatalogRefreshInterval,
  }) : daemonController =
           daemonController ??
           DaemonController(diagnosticsApi: diagnosticsApi) {
    _lastDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;
    settingsStore.addListener(_handleSettingsChanged);
  }

  /// A near-real-time view while the app is visible, without a push protocol.
  static const defaultActivePollingInterval = Duration(seconds: 5);
  static const defaultBackgroundPollingInterval = Duration(seconds: 60);
  static const defaultMaxSnapshotAge = Duration(seconds: 90);
  static const defaultStartupCatalogRefreshTimeout = Duration(seconds: 6);
  static const defaultStartupCatalogRefreshInterval = Duration(
    milliseconds: 500,
  );
  static const _startupCatalogMaxRefreshes = 14;
  static const _startupCatalogMinRefreshes = 12;

  final SettingsStore settingsStore;
  final DiagnosticsApi diagnosticsApi;
  final DaemonController daemonController;
  final Duration autoRefreshInterval;
  final Duration backgroundRefreshInterval;
  final Duration maxSnapshotAge;
  final bool enableFreshnessTimer;
  final Duration startupCatalogRefreshTimeout;
  final Duration startupCatalogRefreshInterval;

  Timer? _timer;
  Timer? _staleTimer;
  DiagnosticsSnapshot? _snapshot;
  var _healthReachable = false;
  var _routeHealthy = false;
  var _refreshing = false;
  var _daemonBusy = false;
  var _autoRefreshEnabled = false;
  var _appInForeground = true;
  var _snapshotStale = false;
  var _refreshPending = false;
  var _refreshGeneration = 0;
  Future<void>? _refreshFuture;
  String? _lastError;
  String? _lastHealthError;
  String? _lastStatusError;
  String? _lastDaemonMessage;
  String? _lastDaemonManualCommand;
  DateTime? _lastFetchedAt;
  DateTime? _lastSuccessfulStatusAt;
  Duration? _lastRequestDuration;
  var _speedTestRunning = false;
  SpeedTestResult? _lastSpeedTestResult;
  String? _lastSpeedTestError;
  String? _speedTestPeerVirtualIp;
  DateTime? _speedTestStartedAt;
  var _peerTrafficSamples = <String, _PeerTrafficSample>{};
  var _peerTransferRatesBytesPerSecond = <String, int>{};
  late String _lastDiagnosticsUrl;

  DiagnosticsSnapshot? get snapshot => _snapshot;
  bool get healthReachable => _healthReachable;
  bool get daemonReachable => _healthReachable || _snapshot != null;
  bool get routeHealthy => _routeHealthy;
  bool get online => _healthReachable && _snapshot != null;
  bool get statusReachable => _snapshot != null;
  bool get refreshing => _refreshing;
  bool get daemonBusy => _daemonBusy;
  bool get autoRefreshEnabled => _autoRefreshEnabled;
  bool get appInForeground => _appInForeground;
  bool get snapshotStale => _snapshotStale;
  String? get lastError => _lastError;
  String? get lastHealthError => _lastHealthError;
  String? get lastStatusError => _lastStatusError;
  String? get lastDaemonMessage => _lastDaemonMessage;
  String? get lastDaemonManualCommand => _lastDaemonManualCommand;
  DateTime? get lastFetchedAt => _lastFetchedAt;
  DateTime? get lastSuccessfulStatusAt => _lastSuccessfulStatusAt;
  Duration? get lastRequestDuration => _lastRequestDuration;
  bool get speedTestRunning => _speedTestRunning;
  SpeedTestResult? get lastSpeedTestResult => _lastSpeedTestResult;
  String? get lastSpeedTestError => _lastSpeedTestError;
  String? get speedTestPeerVirtualIp => _speedTestPeerVirtualIp;
  DateTime? get speedTestStartedAt => _speedTestStartedAt;

  /// Fresh combined sent + received rates, keyed by peer node ID. A peer is
  /// absent until two successful status samples are available.
  Map<String, int> get peerTransferRatesBytesPerSecond =>
      Map.unmodifiable(_peerTransferRatesBytesPerSecond);

  void startPolling() {
    setAutoRefresh(enabled: true, refreshImmediately: true);
  }

  void setAutoRefresh({
    required bool enabled,
    bool refreshImmediately = false,
  }) {
    if (_autoRefreshEnabled == enabled) {
      if (enabled && refreshImmediately) {
        unawaited(refreshUntilPeerCatalogSettled());
      }
      return;
    }
    _autoRefreshEnabled = enabled;
    _schedulePolling();
    if (enabled && refreshImmediately) {
      unawaited(refreshUntilPeerCatalogSettled());
    }
    notifyListeners();
  }

  void updateAppLifecycleState(AppLifecycleState state) {
    final appInForeground = state == AppLifecycleState.resumed;
    if (_appInForeground == appInForeground) return;
    _appInForeground = appInForeground;
    _schedulePolling();
    if (_autoRefreshEnabled && appInForeground) {
      unawaited(refresh());
    }
    notifyListeners();
  }

  void _schedulePolling() {
    _timer?.cancel();
    _timer = null;
    if (!_autoRefreshEnabled) return;
    final interval = _appInForeground
        ? autoRefreshInterval
        : backgroundRefreshInterval;
    _timer = Timer.periodic(interval, (_) => unawaited(refresh()));
  }

  Future<void> refresh() {
    _refreshPending = true;
    final activeRefresh = _refreshFuture;
    if (activeRefresh != null) return activeRefresh;

    final completer = Completer<void>();
    _refreshFuture = completer.future;
    unawaited(_runRefreshLoop(completer));
    return completer.future;
  }

  Future<void> _runRefreshLoop(Completer<void> completer) async {
    _refreshing = true;
    notifyListeners();
    try {
      do {
        _refreshPending = false;
        final generation = _refreshGeneration;
        final url = settingsStore.settings.diagnosticsUrl;
        await _refreshOnce(url, generation);
      } while (_refreshPending);
      completer.complete();
    } catch (error, stackTrace) {
      completer.completeError(error, stackTrace);
    } finally {
      if (identical(_refreshFuture, completer.future)) {
        _refreshFuture = null;
      }
      _refreshing = false;
      notifyListeners();
    }
  }

  Future<void> _refreshOnce(String url, int generation) async {
    final stopwatch = Stopwatch()..start();
    try {
      final health = await diagnosticsApi.fetchHealth(url);
      if (generation != _refreshGeneration) {
        _refreshPending = true;
        return;
      }

      _lastHealthError = null;
      _lastStatusError = null;
      _healthReachable = health;
      if (!health) {
        _clearSnapshot();
        _routeHealthy = false;
        _lastHealthError = 'GET /health is offline or unreadable';
        _lastStatusError = 'GET /status skipped because /health is offline';
        _lastError = _lastHealthError;
        _lastFetchedAt = DateTime.now();
        return;
      }

      try {
        final snapshot = await diagnosticsApi.fetchStatus(url);
        if (generation != _refreshGeneration) {
          _refreshPending = true;
          return;
        }
        final fetchedAt = DateTime.now();
        _updatePeerTrafficRates(snapshot, fetchedAt);
        _snapshot = snapshot;
        try {
          _routeHealthy = (await diagnosticsApi.verifyRoutes(url)).healthy;
        } catch (_) {
          _routeHealthy = false;
        }
        _lastError = null;
        _lastFetchedAt = fetchedAt;
        _lastSuccessfulStatusAt = _lastFetchedAt;
        _markSnapshotFresh();
      } catch (error) {
        if (generation != _refreshGeneration) {
          _refreshPending = true;
          return;
        }
        _clearSnapshot();
        _lastStatusError = 'GET /status failed: $error';
        _lastError = _lastStatusError;
        _lastFetchedAt = DateTime.now();
      }
    } catch (error) {
      if (generation != _refreshGeneration) {
        _refreshPending = true;
        return;
      }
      _healthReachable = false;
      _clearSnapshot();
      _lastHealthError = 'GET /health failed: $error';
      _lastStatusError = 'GET /status skipped because /health failed';
      _lastError = _lastHealthError;
      _lastFetchedAt = DateTime.now();
    } finally {
      stopwatch.stop();
      if (generation == _refreshGeneration) {
        _lastRequestDuration = stopwatch.elapsed;
      }
    }
  }

  void _clearSnapshot() {
    _snapshot = null;
    _snapshotStale = false;
    _peerTrafficSamples = <String, _PeerTrafficSample>{};
    _peerTransferRatesBytesPerSecond = <String, int>{};
    _staleTimer?.cancel();
    _staleTimer = null;
  }

  void _updatePeerTrafficRates(
    DiagnosticsSnapshot snapshot,
    DateTime fetchedAt,
  ) {
    final nextSamples = <String, _PeerTrafficSample>{};
    final nextRates = <String, int>{};
    for (final peer in snapshot.peers) {
      final nodeId = peer.nodeId.trim();
      if (nodeId.isEmpty) continue;
      final totalBytes = peer.bytesSent + peer.bytesReceived;
      final previous = _peerTrafficSamples[nodeId];
      if (previous != null) {
        final elapsedMicros = fetchedAt
            .difference(previous.fetchedAt)
            .inMicroseconds;
        final deltaBytes = totalBytes - previous.totalBytes;
        if (elapsedMicros > 0 && deltaBytes >= 0) {
          nextRates[nodeId] =
              (deltaBytes * Duration.microsecondsPerSecond / elapsedMicros)
                  .round();
        }
      }
      nextSamples[nodeId] = _PeerTrafficSample(
        totalBytes: totalBytes,
        fetchedAt: fetchedAt,
      );
    }
    _peerTrafficSamples = nextSamples;
    _peerTransferRatesBytesPerSecond = nextRates;
  }

  void _markSnapshotFresh() {
    _snapshotStale = false;
    _staleTimer?.cancel();
    if (!enableFreshnessTimer) return;
    _staleTimer = Timer(maxSnapshotAge, () {
      if (_snapshot == null || _snapshotStale) return;
      _snapshotStale = true;
      notifyListeners();
    });
  }

  Future<void> refreshUntilPeerCatalogSettled({
    bool skipInitialRefresh = false,
  }) async {
    if (!skipInitialRefresh) {
      await refresh();
    }
    if (!_shouldSettlePeerCatalog()) return;

    final deadline = DateTime.now().add(startupCatalogRefreshTimeout);
    var refreshCount = 1;
    var stableCatalogCount = 0;
    var previousSignature = _peerCatalogSignature(_snapshot);
    var bestSnapshot = _snapshot;

    while (refreshCount < _startupCatalogMaxRefreshes &&
        DateTime.now().isBefore(deadline)) {
      if (startupCatalogRefreshInterval > Duration.zero) {
        await Future<void>.delayed(startupCatalogRefreshInterval);
      } else {
        await Future<void>.delayed(Duration.zero);
      }

      await refresh();
      refreshCount += 1;

      final currentSnapshot = _snapshot;
      if (_isPeerCatalogMoreComplete(currentSnapshot, bestSnapshot)) {
        bestSnapshot = currentSnapshot;
      }

      final currentSignature = _peerCatalogSignature(currentSnapshot);
      if (currentSignature == previousSignature) {
        stableCatalogCount += 1;
      } else {
        stableCatalogCount = 0;
      }
      previousSignature = currentSignature;

      if (!_shouldSettlePeerCatalog()) break;
      if (currentSnapshot?.health.controlConnected == true &&
          refreshCount >= _startupCatalogMinRefreshes &&
          stableCatalogCount >= 1) {
        break;
      }
    }

    if (_isPeerCatalogMoreComplete(bestSnapshot, _snapshot)) {
      _snapshot = bestSnapshot;
      notifyListeners();
    }
  }

  Future<DaemonCommandResult> startDaemon() async {
    return _runDaemonCommand(
      () => daemonController.start(settingsStore.settings),
      settlePeerCatalog: true,
    );
  }

  Future<DaemonCommandResult> stopDaemon() async {
    return _runDaemonCommand(
      () => daemonController.stop(settingsStore.settings.diagnosticsUrl),
    );
  }

  Future<void> runSpeedTest(PeerSnapshot peer) async {
    if (_speedTestRunning) return;
    final peerVirtualIp = peer.virtualIp.trim();
    if (peerVirtualIp.isEmpty) return;
    _speedTestRunning = true;
    _speedTestPeerVirtualIp = peerVirtualIp;
    _speedTestStartedAt = DateTime.now();
    _lastSpeedTestResult = null;
    _lastSpeedTestError = null;
    notifyListeners();
    try {
      _lastSpeedTestResult = await diagnosticsApi.runSpeedTest(
        settingsStore.settings.diagnosticsUrl,
        peerVirtualIp: peerVirtualIp,
        duration: const Duration(seconds: 10),
      );
    } catch (error) {
      _lastSpeedTestError = error.toString();
    } finally {
      _speedTestRunning = false;
      notifyListeners();
    }
  }

  bool speedTestMatches(PeerSnapshot peer) {
    final peerVirtualIp = peer.virtualIp.trim();
    return peerVirtualIp.isNotEmpty && peerVirtualIp == _speedTestPeerVirtualIp;
  }

  SpeedTestResult? speedTestResultFor(PeerSnapshot peer) =>
      speedTestMatches(peer) ? _lastSpeedTestResult : null;

  String? speedTestErrorFor(PeerSnapshot peer) =>
      speedTestMatches(peer) ? _lastSpeedTestError : null;

  Future<DaemonCommandResult> _runDaemonCommand(
    Future<DaemonCommandResult> Function() command, {
    bool settlePeerCatalog = false,
  }) async {
    if (_daemonBusy) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Another daemon operation is already running.',
      );
    }
    _daemonBusy = true;
    _lastDaemonMessage = null;
    _lastDaemonManualCommand = null;
    notifyListeners();
    try {
      final result = await command();
      _lastDaemonMessage = result.message;
      _lastDaemonManualCommand = result.manualCommand;
      if (!result.ok) {
        _lastError = result.message;
      }
      if (result.ok && settlePeerCatalog) {
        await refreshUntilPeerCatalogSettled();
      } else {
        await refresh();
      }
      return result;
    } catch (error) {
      final result = DaemonCommandResult(
        ok: false,
        message: 'Daemon operation failed: $error',
      );
      _lastDaemonMessage = result.message;
      _lastDaemonManualCommand = result.manualCommand;
      _lastError = result.message;
      return result;
    } finally {
      _daemonBusy = false;
      notifyListeners();
    }
  }

  bool _shouldSettlePeerCatalog() {
    final settings = settingsStore.settings;
    return !settings.manualMode &&
        settings.authToken.trim().isNotEmpty &&
        _healthReachable;
  }

  static String _peerCatalogSignature(DiagnosticsSnapshot? snapshot) {
    if (snapshot == null) return '';
    final peerKeys = [
      for (final peer in snapshot.peers)
        '${peer.nodeId.trim()}|${peer.virtualIp.trim()}',
    ]..sort();
    return peerKeys.join('\n');
  }

  static bool _isPeerCatalogMoreComplete(
    DiagnosticsSnapshot? candidate,
    DiagnosticsSnapshot? current,
  ) {
    if (candidate == null) return false;
    if (current == null) return true;
    if (candidate.health.controlConnected != current.health.controlConnected) {
      return candidate.health.controlConnected;
    }
    if (candidate.peers.length != current.peers.length) {
      return candidate.peers.length > current.peers.length;
    }
    final candidateLastSuccess = candidate.health.lastControlSuccessSecsAgo;
    final currentLastSuccess = current.health.lastControlSuccessSecsAgo;
    if (candidateLastSuccess != null && currentLastSuccess == null) {
      return true;
    }
    if (candidateLastSuccess == null || currentLastSuccess == null) {
      return false;
    }
    return candidateLastSuccess < currentLastSuccess;
  }

  void _handleSettingsChanged() {
    final nextDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;
    if (nextDiagnosticsUrl == _lastDiagnosticsUrl) return;
    _lastDiagnosticsUrl = nextDiagnosticsUrl;
    _refreshGeneration += 1;
    _refreshPending = true;
    _healthReachable = false;
    _clearSnapshot();
    _lastError = null;
    _lastHealthError = null;
    _lastStatusError = null;
    _lastFetchedAt = null;
    _lastRequestDuration = null;
    _speedTestPeerVirtualIp = null;
    _speedTestStartedAt = null;
    _lastSpeedTestResult = null;
    _lastSpeedTestError = null;
    notifyListeners();
    unawaited(refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    _staleTimer?.cancel();
    settingsStore.removeListener(_handleSettingsChanged);
    diagnosticsApi.close();
    super.dispose();
  }
}

class _PeerTrafficSample {
  const _PeerTrafficSample({required this.totalBytes, required this.fetchedAt});

  final int totalBytes;
  final DateTime fetchedAt;
}
