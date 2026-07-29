import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/daemon_api.dart';
import '../models/daemon_models.dart';
import 'settings_store.dart';

class StatusStore extends ChangeNotifier {
  StatusStore({
    required this.settingsStore,
    required this.daemonApi,
    this.autoRefreshInterval = defaultAutoRefreshInterval,
  }) {
    settingsStore.addListener(_handleSettingsChanged);
  }

  static const defaultAutoRefreshInterval = Duration(seconds: 30);

  final SettingsStore settingsStore;
  final DaemonApi daemonApi;
  final Duration autoRefreshInterval;

  Timer? _timer;
  DaemonSnapshot? _snapshot;
  var _healthReachable = false;
  var _refreshing = false;
  var _autoRefreshEnabled = false;
  String? _lastError;
  String? _lastHealthError;
  String? _lastStatusError;
  DateTime? _lastFetchedAt;
  Duration? _lastRequestDuration;

  DaemonSnapshot? get snapshot => _snapshot;
  bool get healthReachable => _healthReachable;
  bool get online => _healthReachable && _snapshot != null;
  bool get statusReachable => _snapshot != null;
  bool get refreshing => _refreshing;
  bool get autoRefreshEnabled => _autoRefreshEnabled;
  String? get lastError => _lastError;
  String? get lastHealthError => _lastHealthError;
  String? get lastStatusError => _lastStatusError;
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
      final health = await daemonApi.fetchHealth(url);
      _healthReachable = health;
      if (!health) {
        _snapshot = null;
        _lastHealthError = 'GET /health is offline or unreadable';
        _lastStatusError = 'GET /status skipped because /health is offline';
        _lastError = _lastHealthError;
      } else {
        try {
          _snapshot = await daemonApi.fetchStatus(url);
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

  void _handleSettingsChanged() {
    unawaited(refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    settingsStore.removeListener(_handleSettingsChanged);
    daemonApi.close();
    super.dispose();
  }
}
