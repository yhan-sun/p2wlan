import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:window_manager/window_manager.dart';

import '../core/models/diagnostics_models.dart';
import '../core/state/status_store.dart';
import '../shared/formatters.dart';
import 'app_constants.dart';
import 'desktop_window_operations.dart';

class DesktopWindowStatusController {
  DesktopWindowStatusController({required this.statusStore});

  final StatusStore statusStore;

  bool _initialized = false;
  bool _updateRequested = false;
  Future<void>? _updateInFlight;
  String? _lastTitle;
  bool _macosDockBadgeCleared = false;

  static bool get isSupported {
    return !kIsWeb &&
        (defaultTargetPlatform == TargetPlatform.macOS ||
            defaultTargetPlatform == TargetPlatform.linux ||
            defaultTargetPlatform == TargetPlatform.windows);
  }

  Future<void> initialize() async {
    if (_initialized || !isSupported) return;
    _initialized = true;
    statusStore.addListener(_scheduleUpdate);
    await _queueUpdate();
  }

  void dispose() {
    if (!_initialized) return;
    statusStore.removeListener(_scheduleUpdate);
    _initialized = false;
  }

  void _scheduleUpdate() {
    unawaited(_queueUpdate());
  }

  Future<void> _queueUpdate() {
    if (!_initialized) return Future<void>.value();
    _updateRequested = true;
    final inFlight = _updateInFlight;
    if (inFlight != null) return inFlight;

    final future = _drainUpdates();
    _updateInFlight = future;
    return future;
  }

  Future<void> _drainUpdates() async {
    try {
      while (_initialized && _updateRequested) {
        _updateRequested = false;
        try {
          await _update();
        } catch (error) {
          debugPrint('Failed to update P2WLAN desktop indicators: $error');
        }
      }
    } finally {
      _updateInFlight = null;
      if (_initialized && _updateRequested) {
        unawaited(_queueUpdate());
      }
    }
  }

  Future<void> _update() async {
    final title = taskbarTitleForTesting();
    final shouldUpdateTitle = _lastTitle != title;
    final shouldClearMacosDockBadge =
        defaultTargetPlatform == TargetPlatform.macOS &&
        !_macosDockBadgeCleared;
    if (!shouldUpdateTitle && !shouldClearMacosDockBadge) return;

    try {
      await DesktopWindowOperations.run(() async {
        if (shouldUpdateTitle) {
          await windowManager.setTitle(title);
          _lastTitle = title;
        }
        if (shouldClearMacosDockBadge) {
          // Keep the macOS Dock icon free of live metric badges. This also
          // removes a badge persisted by a previous client version.
          await windowManager.setBadgeLabel();
          _macosDockBadgeCleared = true;
        }
      });
    } catch (error) {
      if (shouldUpdateTitle) {
        debugPrint('Failed to update P2WLAN desktop title: $error');
      }
      if (shouldClearMacosDockBadge) {
        debugPrint('Failed to update P2WLAN Dock badge: $error');
      }
    }
  }

  @visibleForTesting
  String taskbarTitleForTesting() {
    final snapshot = _metricsSnapshot;
    if (snapshot == null) return p2wlanAppName;
    return '$p2wlanAppName · ${formatLatency(_averageLatency(snapshot))} · ${formatTransferRate(_aggregateSpeed(snapshot))}';
  }

  DiagnosticsSnapshot? get _metricsSnapshot {
    if (!statusStore.daemonReachable || statusStore.snapshotStale) return null;
    return statusStore.snapshot;
  }

  int? _averageLatency(DiagnosticsSnapshot? snapshot) {
    if (snapshot == null) return null;
    final latencies = [
      for (final peer in snapshot.peers)
        if (peer.online && peer.latencyMs != null) peer.latencyMs!,
    ];
    if (latencies.isEmpty) return null;
    final total = latencies.fold<int>(0, (sum, value) => sum + value);
    return (total / latencies.length).round();
  }

  int? _aggregateSpeed(DiagnosticsSnapshot? snapshot) {
    if (snapshot == null) return null;
    var total = 0;
    var hasSample = false;
    for (final peer in snapshot.peers) {
      if (!peer.online) continue;
      final rate = statusStore.peerTransferRatesBytesPerSecond[peer.nodeId];
      if (rate == null) continue;
      total += rate;
      hasSample = true;
    }
    return hasSample ? total : null;
  }
}
