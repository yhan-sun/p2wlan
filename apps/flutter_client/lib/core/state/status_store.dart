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
  }) : daemonController =
           daemonController ??
           DaemonController(diagnosticsApi: diagnosticsApi) {
    settingsStore.addListener(_handleSettingsChanged);
  }

  static const defaultAutoRefreshInterval = Duration(seconds: 30);

  final SettingsStore settingsStore;
  final DiagnosticsApi diagnosticsApi;
  final DaemonController daemonController;
  final Duration autoRefreshInterval;

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
  late String _lastDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;

  DiagnosticsSnapshot? get snapshot => _snapshot;
  bool get healthReachable => _healthReachable;
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

  void startPolling() {
    setAutoRefresh(enabled: true, refreshImmediately: true);
  }

  void setAutoRefresh({
    required bool enabled,
    bool refreshImmediately = false,
  }) {
    if (_autoRefreshEnabled == enabled) {
      if (enabled && refreshImmediately) unawaited(refresh());
      return;
    }
    _autoRefreshEnabled = enabled;
    _timer?.cancel();
    _timer = null;
    if (enabled) {
      _timer = Timer.periodic(autoRefreshInterval, (_) => unawaited(refresh()));
      if (refreshImmediately) unawaited(refresh());
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

  Future<DaemonCommandResult> startDaemon() async {
    return _runDaemonCommand(
      () => daemonController.start(settingsStore.settings),
    );
  }

  Future<DaemonCommandResult> stopDaemon() async {
    return _runDaemonCommand(
      () => daemonController.stop(settingsStore.settings.diagnosticsUrl),
    );
  }

  Future<DaemonCommandResult> _runDaemonCommand(
    Future<DaemonCommandResult> Function() command,
  ) async {
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
      await refresh();
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

  void _handleSettingsChanged() {
    final nextDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;
    if (nextDiagnosticsUrl == _lastDiagnosticsUrl) return;
    _lastDiagnosticsUrl = nextDiagnosticsUrl;
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
