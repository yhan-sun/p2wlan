import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:window_manager/window_manager.dart';

import '../core/models/diagnostics_models.dart';
import '../core/state/status_store.dart';
import '../shared/formatters.dart';
import 'app_constants.dart';

class DesktopWindowStatusController {
  DesktopWindowStatusController({required this.statusStore});

  final StatusStore statusStore;

  bool _initialized = false;
  bool _updateQueued = false;
  String? _lastTitle;
  String? _lastDockBadge;

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
    await _update();
  }

  void dispose() {
    if (!_initialized) return;
    statusStore.removeListener(_scheduleUpdate);
    _initialized = false;
  }

  void _scheduleUpdate() {
    if (_updateQueued) return;
    _updateQueued = true;
    scheduleMicrotask(() {
      _updateQueued = false;
      if (_initialized) unawaited(_update());
    });
  }

  Future<void> _update() async {
    final title = taskbarTitleForTesting();
    if (_lastTitle != title) {
      try {
        await windowManager.setTitle(title);
        _lastTitle = title;
      } catch (error) {
        debugPrint('Failed to update P2WLAN desktop title: $error');
      }
    }

    if (defaultTargetPlatform != TargetPlatform.macOS) return;
    final badge = dockBadgeForTesting();
    if (_lastDockBadge == badge) return;
    try {
      await windowManager.setBadgeLabel(badge.isEmpty ? null : badge);
      _lastDockBadge = badge;
    } catch (error) {
      debugPrint('Failed to update P2WLAN Dock badge: $error');
    }
  }

  @visibleForTesting
  String taskbarTitleForTesting() {
    final snapshot = _metricsSnapshot;
    if (snapshot == null) return p2wlanAppName;
    return '$p2wlanAppName · ${formatLatency(_averageLatency(snapshot))} · ${formatTransferRate(_aggregateSpeed(snapshot))}';
  }

  @visibleForTesting
  String dockBadgeForTesting() {
    final snapshot = _metricsSnapshot;
    if (snapshot == null) return '';
    final latency = _averageLatency(snapshot);
    final speed = _aggregateSpeed(snapshot);
    if (latency == null && speed == null) return '';
    final latencyLabel = latency == null ? '—' : '${latency}ms';
    final speedLabel = speed == null
        ? '—'
        : formatTransferRate(speed).replaceAll(' ', '');
    return '$latencyLabel/$speedLabel';
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
