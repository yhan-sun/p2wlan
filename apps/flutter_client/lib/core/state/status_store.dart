import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/daemon_api.dart';
import '../models/daemon_models.dart';
import 'settings_store.dart';

class StatusStore extends ChangeNotifier {
  StatusStore({required this.settingsStore, required this.daemonApi}) {
    settingsStore.addListener(_handleSettingsChanged);
  }

  static const pollInterval = Duration(seconds: 2);

  final SettingsStore settingsStore;
  final DaemonApi daemonApi;

  Timer? _timer;
  DaemonSnapshot? _snapshot;
  var _healthReachable = false;
  var _refreshing = false;
  String? _lastError;
  DateTime? _lastFetchedAt;

  DaemonSnapshot? get snapshot => _snapshot;
  bool get healthReachable => _healthReachable;
  bool get online => _healthReachable && _snapshot != null;
  bool get refreshing => _refreshing;
  String? get lastError => _lastError;
  DateTime? get lastFetchedAt => _lastFetchedAt;

  void startPolling() {
    _timer?.cancel();
    unawaited(refresh());
    _timer = Timer.periodic(pollInterval, (_) => refresh());
  }

  Future<void> refresh() async {
    if (_refreshing) return;
    _refreshing = true;
    notifyListeners();
    final url = settingsStore.settings.diagnosticsUrl;
    try {
      final health = await daemonApi.fetchHealth(url);
      _healthReachable = health;
      if (!health) {
        _snapshot = null;
        _lastError = 'Daemon health endpoint is offline';
      } else {
        _snapshot = await daemonApi.fetchStatus(url);
        _lastError = null;
      }
      _lastFetchedAt = DateTime.now();
    } catch (error) {
      _snapshot = null;
      _lastError = error.toString();
      _lastFetchedAt = DateTime.now();
    } finally {
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
