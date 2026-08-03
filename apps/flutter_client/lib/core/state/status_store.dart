import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/diagnostics_api.dart';
import '../daemon/daemon_controller.dart';
import '../models/diagnostics_models.dart';
import 'settings_store.dart';

class StatusStore extends ChangeNotifier {
  StatusStore({
    required this.settingsStore,
    required this.diagnosticsApi,
    DaemonController? daemonController,
    this.autoRefreshInterval = defaultAutoRefreshInterval,
    this.startupCatalogRefreshTimeout = defaultStartupCatalogRefreshTimeout,
    this.startupCatalogRefreshInterval = defaultStartupCatalogRefreshInterval,
  }) : daemonController =
           daemonController ??
           DaemonController(diagnosticsApi: diagnosticsApi) {
    settingsStore.addListener(_handleSettingsChanged);
  }

  static const defaultAutoRefreshInterval = Duration(seconds: 30);
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
  final Duration startupCatalogRefreshTimeout;
  final Duration startupCatalogRefreshInterval;

  Timer? _timer;
  DiagnosticsSnapshot? _snapshot;
  var _healthReachable = false;
  var _refreshing = false;
  var _daemonBusy = false;
  var _autoRefreshEnabled = false;
  String? _lastError;
  String? _lastHealthError;
  String? _lastStatusError;
  String? _lastDaemonMessage;
  String? _lastDaemonManualCommand;
  DateTime? _lastFetchedAt;
  Duration? _lastRequestDuration;
  var _speedTestRunning = false;
  SpeedTestResult? _lastSpeedTestResult;
  String? _lastSpeedTestError;
  String? _speedTestPeerVirtualIp;
  late String _lastDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;

  DiagnosticsSnapshot? get snapshot => _snapshot;
  bool get healthReachable => _healthReachable;
  bool get daemonReachable => _healthReachable || _snapshot != null;
  bool get online => _healthReachable && _snapshot != null;
  bool get statusReachable => _snapshot != null;
  bool get refreshing => _refreshing;
  bool get daemonBusy => _daemonBusy;
  bool get autoRefreshEnabled => _autoRefreshEnabled;
  String? get lastError => _lastError;
  String? get lastHealthError => _lastHealthError;
  String? get lastStatusError => _lastStatusError;
  String? get lastDaemonMessage => _lastDaemonMessage;
  String? get lastDaemonManualCommand => _lastDaemonManualCommand;
  DateTime? get lastFetchedAt => _lastFetchedAt;
  Duration? get lastRequestDuration => _lastRequestDuration;
  bool get speedTestRunning => _speedTestRunning;
  SpeedTestResult? get lastSpeedTestResult => _lastSpeedTestResult;
  String? get lastSpeedTestError => _lastSpeedTestError;
  String? get speedTestPeerVirtualIp => _speedTestPeerVirtualIp;

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
    _timer?.cancel();
    _timer = null;
    if (enabled) {
      _timer = Timer.periodic(autoRefreshInterval, (_) => unawaited(refresh()));
      if (refreshImmediately) unawaited(refreshUntilPeerCatalogSettled());
    }
    notifyListeners();
  }

  Future<void> refresh() async {
    if (_refreshing) return;
    _refreshing = true;
    notifyListeners();
    final url = settingsStore.settings.diagnosticsUrl;
    final stopwatch = Stopwatch()..start();
    try {
      _lastHealthError = null;
      _lastStatusError = null;
      final health = await diagnosticsApi.fetchHealth(url);
      _healthReachable = health;
      if (!health) {
        _snapshot = null;
        _lastHealthError = 'GET /health is offline or unreadable';
        _lastStatusError = 'GET /status skipped because /health is offline';
        _lastError = _lastHealthError;
      } else {
        try {
          _snapshot = await diagnosticsApi.fetchStatus(url);
          _lastError = null;
        } catch (error) {
          _snapshot = null;
          _lastStatusError = 'GET /status failed: $error';
          _lastError = _lastStatusError;
        }
      }
      _lastFetchedAt = DateTime.now();
    } catch (error) {
      _healthReachable = false;
      _snapshot = null;
      _lastHealthError = 'GET /health failed: $error';
      _lastStatusError = 'GET /status skipped because /health failed';
      _lastError = _lastHealthError;
      _lastFetchedAt = DateTime.now();
    } finally {
      stopwatch.stop();
      _lastRequestDuration = stopwatch.elapsed;
      _refreshing = false;
      notifyListeners();
    }
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
    _speedTestPeerVirtualIp = null;
    _lastSpeedTestResult = null;
    _lastSpeedTestError = null;
    unawaited(refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    settingsStore.removeListener(_handleSettingsChanged);
    diagnosticsApi.close();
    super.dispose();
  }
}
