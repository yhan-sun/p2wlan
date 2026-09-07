import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart' show AppLifecycleState;

import '../api/diagnostics_api.dart';
import '../daemon/daemon_controller.dart';
import '../lifecycle/mobile_lifecycle_coordinator.dart';
import '../models/diagnostics_models.dart';
import 'settings_store.dart';

class StatusStore extends ChangeNotifier {
  StatusStore({
    required this.settingsStore,
    required this.diagnosticsApi,
    DaemonController? daemonController,
    MobileLifecycleCoordinator? lifecycleCoordinator,
    this.autoRefreshInterval = defaultActivePollingInterval,
    this.backgroundRefreshInterval = defaultBackgroundPollingInterval,
    this.maxSnapshotAge = defaultMaxSnapshotAge,
    this.enableFreshnessTimer = false,
    this.enableEventPolling = true,
    this.startupCatalogRefreshTimeout = defaultStartupCatalogRefreshTimeout,
    this.startupCatalogRefreshInterval = defaultStartupCatalogRefreshInterval,
    this.routeVerificationInterval = Duration.zero,
    this.metricsUpdateInterval = defaultMetricsUpdateInterval,
  }) : lifecycleCoordinator =
           lifecycleCoordinator ?? MobileLifecycleCoordinator(),
       daemonController =
           daemonController ??
           DaemonController(
             diagnosticsApi: diagnosticsApi,
             readMacosAdminPassword: () =>
                 settingsStore.settings.macosAdminPassword,
             saveMacosAdminPassword: settingsStore.updateMacosAdminPassword,
             clearMacosAdminPassword: settingsStore.clearMacosAdminPassword,
           ) {
    _lastDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;
    settingsStore.addListener(_handleSettingsChanged);
  }

  static const defaultActivePollingInterval = Duration(seconds: 1);
  static const defaultBackgroundPollingInterval = Duration(seconds: 10);
  static const defaultMetricsUpdateInterval = Duration(seconds: 1);
  static const defaultRouteVerificationInterval = Duration(seconds: 10);
  static const defaultMaxSnapshotAge = Duration(seconds: 90);
  static const defaultStartupCatalogRefreshTimeout = Duration(seconds: 6);
  static const defaultStartupCatalogRefreshInterval = Duration(
    milliseconds: 500,
  );
  static const defaultWindowsRouteVerificationInterval = Duration(seconds: 30);
  static const defaultWindowsStartupCatalogRefreshTimeout = Duration(
    seconds: 3,
  );
  static const defaultWindowsStartupCatalogRefreshInterval = Duration(
    milliseconds: 750,
  );
  static const _startupCatalogMaxRefreshes = 14;
  static const _startupCatalogMinRefreshes = 12;
  static const _automaticHealthFailureThreshold = 3;

  final SettingsStore settingsStore;
  final DiagnosticsApi diagnosticsApi;
  final MobileLifecycleCoordinator lifecycleCoordinator;
  final DaemonController daemonController;
  final Duration autoRefreshInterval;
  final Duration backgroundRefreshInterval;
  final Duration maxSnapshotAge;
  final bool enableFreshnessTimer;
  final bool enableEventPolling;
  final Duration startupCatalogRefreshTimeout;
  final Duration startupCatalogRefreshInterval;
  final Duration routeVerificationInterval;
  final Duration metricsUpdateInterval;

  Timer? _timer;
  Timer? _staleTimer;
  Future<void>? _eventLoopFuture;
  var _disposed = false;
  DiagnosticsSnapshot? _snapshot;
  var _healthReachable = false;
  var _routeHealthy = false;
  var _refreshing = false;
  var _showRefreshActivity = false;
  var _daemonBusy = false;
  var _daemonStarting = false;
  var _autoRefreshEnabled = false;
  var _appInForeground = true;
  var _snapshotStale = false;
  var _statusSnapshotTimedOut = false;
  var _startupCatalogSettleDepth = 0;
  var _refreshPending = false;
  var _refreshGeneration = 0;
  var _consecutiveHealthFailures = 0;
  Future<void>? _refreshFuture;
  Future<void>? _automaticRefreshFuture;
  String? _lastError;
  String? _lastHealthError;
  String? _lastStatusError;
  String? _lastDaemonMessage;
  String? _lastDaemonManualCommand;
  DaemonStartupFailureCode? _lastDaemonFailureCode;
  DateTime? _lastFetchedAt;
  DateTime? _lastSuccessfulStatusAt;
  DateTime? _lastAutomaticRefreshAt;
  DateTime? _lastPeerTrafficSampleAt;
  DateTime? _lastRouteVerificationAt;
  Duration? _lastRequestDuration;
  var _speedTestRunning = false;
  var _speedTestRunId = 0;
  final _speedTestClock = Stopwatch();
  SpeedTestResult? _lastSpeedTestResult;
  String? _lastSpeedTestError;
  String? _speedTestPeerVirtualIp;
  DateTime? _speedTestStartedAt;
  var _peerTrafficSamples = <String, _PeerTrafficSample>{};
  var _peerTransferRatesBytesPerSecond = <String, int>{};
  var _peerDirectionalTransferRates = <String, PeerTransferRate>{};
  final _peerOrder = <String, int>{};
  var _nextPeerOrder = 0;
  final _peerOnlineState = <String, bool>{};
  final _peerOnlineOrder = <String, int>{};
  var _nextPeerOnlineOrder = 0;
  late String _lastDiagnosticsUrl;

  DiagnosticsSnapshot? get snapshot => _snapshot;
  bool get healthReachable => _healthReachable;
  bool get daemonReachable => _healthReachable || _snapshot != null;
  bool get routeHealthy => _routeHealthy;
  bool get online => _healthReachable && _snapshot != null;
  bool get statusReachable => _snapshot != null;
  bool get refreshing => _refreshing;
  bool get refreshActivityVisible => _refreshing && _showRefreshActivity;
  bool get daemonBusy => _daemonBusy;
  bool get daemonStarting => _daemonStarting;
  bool get autoRefreshEnabled => _autoRefreshEnabled;
  bool get appInForeground => _appInForeground;
  int get eventLoopGeneration => lifecycleCoordinator.eventLoopGeneration;
  bool get snapshotStale => _snapshotStale;
  bool get statusSnapshotTimedOut => _statusSnapshotTimedOut;
  bool get startupCatalogSettling => _startupCatalogSettleDepth > 0;
  String? get lastError => _lastError;
  String? get lastHealthError => _lastHealthError;
  String? get lastStatusError => _lastStatusError;
  String? get lastDaemonMessage => _lastDaemonMessage;
  String? get lastDaemonManualCommand => _lastDaemonManualCommand;
  DaemonStartupFailureCode? get lastDaemonFailureCode => _lastDaemonFailureCode;
  DateTime? get lastFetchedAt => _lastFetchedAt;
  DateTime? get lastSuccessfulStatusAt => _lastSuccessfulStatusAt;
  Duration? get lastRequestDuration => _lastRequestDuration;
  bool get speedTestRunning => _speedTestRunning;
  int get speedTestRunId => _speedTestRunId;
  Duration get speedTestElapsed => _speedTestClock.elapsed;
  SpeedTestResult? get lastSpeedTestResult => _lastSpeedTestResult;
  String? get lastSpeedTestError => _lastSpeedTestError;
  String? get speedTestPeerVirtualIp => _speedTestPeerVirtualIp;
  DateTime? get speedTestStartedAt => _speedTestStartedAt;
  Map<String, int> get peerTransferRatesBytesPerSecond =>
      Map.unmodifiable(_peerTransferRatesBytesPerSecond);
  Map<String, PeerTransferRate> get peerDirectionalTransferRates =>
      Map.unmodifiable(_peerDirectionalTransferRates);

  List<PeerSnapshot> stablePeerOrder(Iterable<PeerSnapshot> peers) {
    final byKey = <String, PeerSnapshot>{};
    for (final peer in peers) {
      final key = _peerOrderKey(peer);
      _peerOrder.putIfAbsent(key, () => _nextPeerOrder++);
      byKey[key] = peer;
    }
    _recordPeerPresence(byKey.values);
    final ordered = byKey.values.toList();
    ordered.sort(_comparePeerPresentationOrder);
    return ordered;
  }

  void recordPeerPresence(Iterable<PeerSnapshot> peers) {
    final byKey = <String, PeerSnapshot>{};
    for (final peer in peers) {
      byKey[_peerOrderKey(peer)] = peer;
    }
    _recordPeerPresence(byKey.values, markMissingOffline: true);
  }

  void _recordPeerPresence(
    Iterable<PeerSnapshot> peers, {
    bool markMissingOffline = false,
  }) {
    final currentKeys = <String>{};
    for (final peer in peers) {
      final key = _peerOrderKey(peer);
      currentKeys.add(key);
      _peerOrder.putIfAbsent(key, () => _nextPeerOrder++);
      final online = _peerIsOnline(peer);
      final wasOnline = _peerOnlineState[key];
      if (online && wasOnline != true) {
        _peerOnlineOrder[key] = _nextPeerOnlineOrder++;
      } else if (online && !_peerOnlineOrder.containsKey(key)) {
        _peerOnlineOrder[key] = _nextPeerOnlineOrder++;
      }
      _peerOnlineState[key] = online;
    }
    if (markMissingOffline) {
      for (final key in _peerOnlineState.keys.toList()) {
        if (!currentKeys.contains(key)) _peerOnlineState[key] = false;
      }
    }
  }

  int _comparePeerPresentationOrder(PeerSnapshot left, PeerSnapshot right) {
    final leftOnline = _peerIsOnline(left);
    final rightOnline = _peerIsOnline(right);
    if (leftOnline != rightOnline) return leftOnline ? -1 : 1;
    if (leftOnline) {
      final byOnlineOrder =
          (_peerOnlineOrder[_peerOrderKey(left)] ?? _nextPeerOnlineOrder)
              .compareTo(
                _peerOnlineOrder[_peerOrderKey(right)] ?? _nextPeerOnlineOrder,
              );
      if (byOnlineOrder != 0) return byOnlineOrder;
    }
    return _peerOrder[_peerOrderKey(left)]!.compareTo(
      _peerOrder[_peerOrderKey(right)]!,
    );
  }

  static bool _peerIsOnline(PeerSnapshot peer) =>
      peer.online && peer.path != 'offline';

  static String _peerOrderKey(PeerSnapshot peer) {
    final nodeId = peer.nodeId.trim();
    if (nodeId.isNotEmpty) return 'node:$nodeId';
    final virtualIp = peer.virtualIp.trim();
    if (virtualIp.isNotEmpty) return 'ip:$virtualIp';
    return 'name:${peer.displayName}';
  }

  void startPolling() {
    setAutoRefresh(enabled: true, refreshImmediately: true);
  }

  void setAutoRefresh({
    required bool enabled,
    bool refreshImmediately = false,
  }) {
    if (_disposed) return;
    if (_autoRefreshEnabled == enabled) {
      if (enabled && refreshImmediately) {
        unawaited(refreshUntilPeerCatalogSettled(silent: true));
      }
      if (enabled) _ensureEventLoop();
      return;
    }
    _autoRefreshEnabled = enabled;
    if (!enabled) _lastAutomaticRefreshAt = null;
    _schedulePolling();
    if (enabled) {
      _ensureEventLoop();
    } else {
      lifecycleCoordinator.invalidateEventLoop();
      _eventLoopFuture = null;
    }
    if (enabled && refreshImmediately) {
      unawaited(refreshUntilPeerCatalogSettled(silent: true));
    }
    notifyListeners();
  }

  void updateAppLifecycleState(AppLifecycleState state) {
    if (_disposed) return;
    final appInForeground = state == AppLifecycleState.resumed;
    final transition = appInForeground
        ? lifecycleCoordinator.onAppResumed()
        : lifecycleCoordinator.onAppBackgrounded();
    if (transition.outcome != MobileLifecycleOutcome.applied) return;
    _appInForeground = appInForeground;
    if (!appInForeground) {
      _eventLoopFuture = null;
    }
    _schedulePolling();
    if (_autoRefreshEnabled && appInForeground) {
      unawaited(_refreshAfterResume());
    }
    notifyListeners();
  }

  Future<void> _refreshAfterResume() async {
    var appEpoch = lifecycleCoordinator.appEpoch;
    try {
      final androidStatus = await daemonController.androidStatus();
      if (!lifecycleCoordinator.acceptsAppEpoch(appEpoch) ||
          !_appInForeground) {
        return;
      }
      final bridgeIncarnation = androidStatus?.bridgeIncarnation;
      if (bridgeIncarnation != null) {
        final transition = lifecycleCoordinator.observeBridge(
          bridgeIncarnation,
        );
        if (transition.outcome == MobileLifecycleOutcome.staleRejected) {
          return;
        }
        appEpoch = lifecycleCoordinator.appEpoch;
      }
    } catch (_) {}
    if (!lifecycleCoordinator.acceptsAppEpoch(appEpoch) || !_appInForeground) {
      return;
    }
    await refresh(silent: true);
    if (!lifecycleCoordinator.acceptsAppEpoch(appEpoch) ||
        !_autoRefreshEnabled ||
        !_appInForeground) {
      return;
    }
    _ensureEventLoop();
  }

  void _schedulePolling() {
    _timer?.cancel();
    _timer = null;
    if (!_autoRefreshEnabled || _disposed) return;
    final interval = _appInForeground
        ? autoRefreshInterval
        : backgroundRefreshInterval;
    _timer = Timer.periodic(
      interval,
      (_) => unawaited(_refreshAutomatically()),
    );
  }

  void _ensureEventLoop() {
    if (!enableEventPolling ||
        !_autoRefreshEnabled ||
        !_appInForeground ||
        _disposed ||
        _snapshot == null ||
        _eventLoopFuture != null) {
      return;
    }
    final generation = lifecycleCoordinator.eventLoopGeneration;
    final url = settingsStore.settings.diagnosticsUrl;
    late final Future<void> loop;
    loop = _runEventLoop(url, generation, lifecycleCoordinator.appEpoch);
    _eventLoopFuture = loop;
    unawaited(
      loop.whenComplete(() {
        if (identical(_eventLoopFuture, loop)) _eventLoopFuture = null;
      }),
    );
  }

  Future<void> _runEventLoop(String url, int generation, int appEpoch) async {
    var cursor = _snapshot?.revision ?? 0;
    var processId = _snapshot?.processId;
    while (!_disposed &&
        _autoRefreshEnabled &&
        _appInForeground &&
        generation == lifecycleCoordinator.eventLoopGeneration &&
        lifecycleCoordinator.acceptsEventLoop(
          appEpoch: appEpoch,
          generation: generation,
        ) &&
        url == settingsStore.settings.diagnosticsUrl &&
        _snapshot != null) {
      EventsResponse response;
      try {
        response = await diagnosticsApi.fetchEvents(
          url,
          since: cursor,
          processId: processId,
        );
      } catch (_) {
        if (_disposed ||
            generation != lifecycleCoordinator.eventLoopGeneration ||
            !lifecycleCoordinator.acceptsEventLoop(
              appEpoch: appEpoch,
              generation: generation,
            )) {
          return;
        }
        await Future<void>.delayed(const Duration(seconds: 1));
        continue;
      }
      if (_disposed ||
          !_autoRefreshEnabled ||
          generation != lifecycleCoordinator.eventLoopGeneration ||
          !lifecycleCoordinator.acceptsEventLoop(
            appEpoch: appEpoch,
            generation: generation,
          ) ||
          url != settingsStore.settings.diagnosticsUrl) {
        return;
      }
      final current = _snapshot;
      if (current == null) return;
      if (current.processId != processId) {
        processId = current.processId;
        cursor = current.revision;
        continue;
      }
      final ringGap = response.oldestSeq > 0 && response.oldestSeq > cursor + 1;
      final revisionReset = response.revision < cursor;
      final eventProcessChanged =
          response.processId != null &&
          processId != null &&
          response.processId != processId;
      final hasChange =
          response.revision > cursor ||
          response.events.any((event) => event.seq > cursor);
      if (response.resetRequired ||
          ringGap ||
          revisionReset ||
          eventProcessChanged ||
          hasChange) {
        final beforeRevision = current.revision;
        await _refreshAutomatically();
        if (_disposed ||
            generation != lifecycleCoordinator.eventLoopGeneration ||
            !lifecycleCoordinator.acceptsEventLoop(
              appEpoch: appEpoch,
              generation: generation,
            )) {
          return;
        }
        final refreshed = _snapshot;
        if (refreshed == null) return;
        processId = refreshed.processId;
        cursor = refreshed.revision;
        if (refreshed.processId == current.processId &&
            cursor <= beforeRevision &&
            response.revision > cursor) {
          await Future<void>.delayed(const Duration(milliseconds: 250));
        }
      } else {
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
    }
  }

  Future<void> _refreshAutomatically() {
    final existing = _automaticRefreshFuture;
    if (existing != null) return existing;
    final future = _runAutomaticRefresh();
    _automaticRefreshFuture = future;
    unawaited(
      future.then<void>(
        (_) {
          if (identical(_automaticRefreshFuture, future)) {
            _automaticRefreshFuture = null;
          }
        },
        onError: (Object error, StackTrace stackTrace) {
          if (identical(_automaticRefreshFuture, future)) {
            _automaticRefreshFuture = null;
          }
        },
      ),
    );
    return future;
  }

  Future<void> _runAutomaticRefresh() async {
    final interval = _appInForeground
        ? autoRefreshInterval
        : backgroundRefreshInterval;
    final last = _lastAutomaticRefreshAt;
    if (last != null) {
      final remaining = interval - DateTime.now().difference(last);
      if (remaining > Duration.zero) await Future<void>.delayed(remaining);
    }
    if (_disposed || !_autoRefreshEnabled) return;
    _lastAutomaticRefreshAt = DateTime.now();
    await refresh(silent: true);
  }

  Future<void> refresh({bool silent = false}) {
    if (_disposed) return Future<void>.value();
    _refreshPending = true;
    final activeRefresh = _refreshFuture;
    if (activeRefresh != null) {
      if (!silent && !_showRefreshActivity) {
        _showRefreshActivity = true;
        notifyListeners();
      }
      return activeRefresh;
    }
    _showRefreshActivity = !silent;
    final completer = Completer<void>();
    _refreshFuture = completer.future;
    unawaited(_runRefreshLoop(completer));
    return completer.future;
  }

  Future<void> _runRefreshLoop(Completer<void> completer) async {
    _refreshing = true;
    if (!_disposed) notifyListeners();
    try {
      do {
        _refreshPending = false;
        final generation = _refreshGeneration;
        final url = settingsStore.settings.diagnosticsUrl;
        await _refreshOnce(
          url,
          generation,
          throttleMetrics: !_showRefreshActivity,
        );
      } while (_refreshPending && !_disposed);
      completer.complete();
    } catch (error, stackTrace) {
      completer.completeError(error, stackTrace);
    } finally {
      if (identical(_refreshFuture, completer.future)) _refreshFuture = null;
      _refreshing = false;
      _showRefreshActivity = false;
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> _refreshOnce(
    String url,
    int generation, {
    required bool throttleMetrics,
  }) async {
    final stopwatch = Stopwatch()..start();
    final appEpoch = lifecycleCoordinator.appEpoch;
    bool acceptsLifecycle() =>
        !_disposed && lifecycleCoordinator.acceptsAppEpoch(appEpoch);
    try {
      final health = await diagnosticsApi.fetchHealth(url);
      if (generation != _refreshGeneration) {
        _refreshPending = true;
        return;
      }
      if (!acceptsLifecycle()) return;
      _lastHealthError = null;
      _lastStatusError = null;
      _statusSnapshotTimedOut = false;
      _healthReachable = health;
      if (!health) {
        _consecutiveHealthFailures += 1;
        if (throttleMetrics &&
            _snapshot != null &&
            _consecutiveHealthFailures < _automaticHealthFailureThreshold) {
          _snapshotStale = true;
          _peerTransferRatesBytesPerSecond.clear();
          _peerDirectionalTransferRates.clear();
        } else {
          _clearSnapshot();
        }
        _routeHealthy = false;
        _lastHealthError =
            diagnosticsApi.healthFailureFor(url)?.toString() ??
            'GET /health is offline or unreadable';
        _lastStatusError = 'GET /status skipped because /health is offline';
        _lastError = _lastHealthError;
        _lastFetchedAt = DateTime.now();
        return;
      }
      _consecutiveHealthFailures = 0;
      try {
        final snapshot = await diagnosticsApi.fetchStatus(url);
        if (generation != _refreshGeneration) {
          _refreshPending = true;
          return;
        }
        if (!acceptsLifecycle()) return;
        final fetchedAt = DateTime.now();
        _statusSnapshotTimedOut = false;
        if (!_snapshotCanReplace(snapshot, _snapshot)) {
          _lastError = null;
          _lastFetchedAt = fetchedAt;
          return;
        }
        var routeHealthy = _routeHealthy;
        DateTime? routeVerifiedAt;
        if (_shouldVerifyRoutes(fetchedAt)) {
          try {
            final routes = await diagnosticsApi.verifyRoutes(url);
            if (!acceptsLifecycle() || generation != _refreshGeneration) return;
            routeHealthy = routes.healthy;
          } catch (_) {
            if (!acceptsLifecycle()) return;
            routeHealthy = false;
          } finally {
            if (acceptsLifecycle()) routeVerifiedAt = DateTime.now();
          }
        }
        if (!acceptsLifecycle() || generation != _refreshGeneration) return;
        final daemonTransition = lifecycleCoordinator.observeDaemon(
          processId: snapshot.processId,
          runtimeIncarnation: snapshot.runtimeIncarnation,
          revision: snapshot.revision,
        );
        if (daemonTransition.outcome == MobileLifecycleOutcome.staleRejected ||
            daemonTransition.outcome == MobileLifecycleOutcome.failed) {
          _lastError = null;
          _lastFetchedAt = fetchedAt;
          return;
        }
        if (daemonTransition.outcome == MobileLifecycleOutcome.applied) {
          if (daemonTransition.oldIdentity.daemonProcessId !=
                  snapshot.processId ||
              daemonTransition.oldIdentity.daemonRuntimeIncarnation !=
                  snapshot.runtimeIncarnation) {
            _eventLoopFuture = null;
            if (_snapshot != null) cancelSpeedTest();
          }
        }
        _updatePeerTrafficRates(snapshot, fetchedAt, throttle: throttleMetrics);
        recordPeerPresence(snapshot.peers);
        _snapshot = snapshot;
        _routeHealthy = routeHealthy;
        if (routeVerifiedAt != null) _lastRouteVerificationAt = routeVerifiedAt;
        _lastError = null;
        _lastFetchedAt = fetchedAt;
        _lastSuccessfulStatusAt = _lastFetchedAt;
        if (!snapshot.peerSnapshotStale &&
            snapshot.capturedRevision == snapshot.revision) {
          _markSnapshotFresh();
        } else {
          _snapshotStale = true;
          _staleTimer?.cancel();
          _staleTimer = null;
        }
        _ensureEventLoop();
      } catch (error) {
        if (generation != _refreshGeneration) {
          _refreshPending = true;
          return;
        }
        if (!acceptsLifecycle()) return;
        final snapshotTimedOut =
            error is DiagnosticsApiException &&
            error.reasonCode == 'status_snapshot_timeout';
        _statusSnapshotTimedOut = snapshotTimedOut;
        if (!snapshotTimedOut) {
          _clearSnapshot();
          _lastStatusError = 'GET /status failed: $error';
          _lastError = _lastStatusError;
        } else {
          _lastStatusError = null;
          _lastError = null;
        }
        _lastFetchedAt = DateTime.now();
      }
    } catch (error) {
      if (generation != _refreshGeneration) {
        _refreshPending = true;
        return;
      }
      if (!acceptsLifecycle()) return;
      _healthReachable = false;
      _statusSnapshotTimedOut = false;
      _clearSnapshot();
      _lastHealthError = 'GET /health failed: $error';
      _lastStatusError = 'GET /status skipped because /health failed';
      _lastError = _lastHealthError;
      _lastFetchedAt = DateTime.now();
    } finally {
      stopwatch.stop();
      if (generation == _refreshGeneration && acceptsLifecycle()) {
        _lastRequestDuration = stopwatch.elapsed;
      }
    }
  }

  void _clearSnapshot() {
    _snapshot = null;
    _snapshotStale = false;
    _peerTrafficSamples = <String, _PeerTrafficSample>{};
    _peerTransferRatesBytesPerSecond = <String, int>{};
    _peerDirectionalTransferRates = <String, PeerTransferRate>{};
    _lastPeerTrafficSampleAt = null;
    _staleTimer?.cancel();
    _staleTimer = null;
    _lastRouteVerificationAt = null;
  }

  bool _shouldVerifyRoutes(DateTime now) {
    if (routeVerificationInterval <= Duration.zero) return true;
    final last = _lastRouteVerificationAt;
    return last == null || now.difference(last) >= routeVerificationInterval;
  }

  void _updatePeerTrafficRates(
    DiagnosticsSnapshot snapshot,
    DateTime fetchedAt, {
    required bool throttle,
  }) {
    final lastSampleAt = _lastPeerTrafficSampleAt;
    if (throttle &&
        lastSampleAt != null &&
        fetchedAt.difference(lastSampleAt) < metricsUpdateInterval) {
      return;
    }
    final nextSamples = <String, _PeerTrafficSample>{};
    final nextRates = <String, int>{};
    final nextDirectionalRates = <String, PeerTransferRate>{};
    for (final peer in snapshot.peers) {
      final nodeId = peer.nodeId.trim();
      if (nodeId.isEmpty) continue;
      final previous = _peerTrafficSamples[nodeId];
      if (previous != null) {
        final elapsedMicros = fetchedAt
            .difference(previous.fetchedAt)
            .inMicroseconds;
        final sentDelta = peer.bytesSent - previous.bytesSent;
        final receivedDelta = peer.bytesReceived - previous.bytesReceived;
        if (elapsedMicros > 0 && sentDelta >= 0 && receivedDelta >= 0) {
          final uploadBytesPerSecond =
              (sentDelta * Duration.microsecondsPerSecond / elapsedMicros)
                  .round();
          final downloadBytesPerSecond =
              (receivedDelta * Duration.microsecondsPerSecond / elapsedMicros)
                  .round();
          nextDirectionalRates[nodeId] = PeerTransferRate(
            uploadBytesPerSecond: uploadBytesPerSecond,
            downloadBytesPerSecond: downloadBytesPerSecond,
          );
          nextRates[nodeId] = uploadBytesPerSecond + downloadBytesPerSecond;
        }
      }
      nextSamples[nodeId] = _PeerTrafficSample(
        bytesSent: peer.bytesSent,
        bytesReceived: peer.bytesReceived,
        fetchedAt: fetchedAt,
      );
    }
    _peerTrafficSamples = nextSamples;
    _peerTransferRatesBytesPerSecond = nextRates;
    _peerDirectionalTransferRates = nextDirectionalRates;
    _lastPeerTrafficSampleAt = fetchedAt;
  }

  void _markSnapshotFresh() {
    _snapshotStale = false;
    _staleTimer?.cancel();
    if (!enableFreshnessTimer) return;
    _staleTimer = Timer(maxSnapshotAge, () {
      if (_disposed || _snapshot == null || _snapshotStale) return;
      _snapshotStale = true;
      notifyListeners();
    });
  }

  static bool _snapshotCanReplace(
    DiagnosticsSnapshot candidate,
    DiagnosticsSnapshot? current,
  ) {
    if (current == null) return true;
    final candidateProcess = candidate.processId;
    final currentProcess = current.processId;
    if (candidateProcess != null &&
        currentProcess != null &&
        candidateProcess != currentProcess) {
      return true;
    }
    final candidateRuntime = candidate.runtimeIncarnation;
    final currentRuntime = current.runtimeIncarnation;
    if (candidateRuntime != null && currentRuntime != null) {
      if (candidateRuntime > currentRuntime) return true;
      if (candidateRuntime < currentRuntime) return false;
    } else if (currentRuntime != null && candidateRuntime == null) {
      return false;
    }
    final restarted =
        candidate.uptimeMs > 0 &&
        current.uptimeMs > 0 &&
        candidate.uptimeMs < current.uptimeMs;
    if (restarted) return true;
    if (candidate.revision < current.revision) return false;
    if (candidate.revision == current.revision &&
        candidate.networkGeneration < current.networkGeneration) {
      return false;
    }
    return true;
  }

  Future<void> refreshUntilPeerCatalogSettled({
    bool skipInitialRefresh = false,
    bool silent = false,
  }) async {
    if (_disposed) return;
    final generation = _refreshGeneration;
    final maskStartupErrors = _snapshot == null;
    if (maskStartupErrors) _beginStartupCatalogSettling();
    try {
      if (!skipInitialRefresh) await refresh(silent: silent);
      if (generation != _refreshGeneration || !_shouldSettlePeerCatalog()) {
        return;
      }
      final clock = Stopwatch()..start();
      var refreshCount = 1;
      var stableCatalogCount = 0;
      var previousSignature = _peerCatalogSignature(_snapshot);
      while (refreshCount < _startupCatalogMaxRefreshes &&
          clock.elapsed < startupCatalogRefreshTimeout &&
          !_disposed &&
          generation == _refreshGeneration) {
        final remaining = startupCatalogRefreshTimeout - clock.elapsed;
        final delay = startupCatalogRefreshInterval > remaining
            ? remaining
            : startupCatalogRefreshInterval;
        await Future<void>.delayed(
          delay > Duration.zero ? delay : Duration.zero,
        );
        if (_disposed || generation != _refreshGeneration) return;
        await refresh(silent: silent);
        refreshCount += 1;
        if (_disposed || generation != _refreshGeneration) return;
        final currentSnapshot = _snapshot;
        final currentSignature = _peerCatalogSignature(currentSnapshot);
        if (currentSignature == previousSignature) {
          stableCatalogCount += 1;
        } else {
          stableCatalogCount = 0;
        }
        previousSignature = currentSignature;
        if (!_shouldSettlePeerCatalog()) break;
        if (currentSnapshot != null && settingsStore.settings.manualMode) break;
        if (currentSnapshot?.health.controlConnected == true &&
            refreshCount >= _startupCatalogMinRefreshes &&
            stableCatalogCount >= 1) {
          break;
        }
      }
    } finally {
      if (maskStartupErrors) _endStartupCatalogSettling();
    }
  }

  void _beginStartupCatalogSettling() {
    _startupCatalogSettleDepth += 1;
    if (_startupCatalogSettleDepth == 1 && !_disposed) notifyListeners();
  }

  void _endStartupCatalogSettling() {
    if (_startupCatalogSettleDepth == 0) return;
    _startupCatalogSettleDepth -= 1;
    if (_startupCatalogSettleDepth == 0 && !_disposed) notifyListeners();
  }

  Future<DaemonCommandResult> startDaemon() async {
    return _runDaemonCommand(
      () => daemonController.start(settingsStore.settings),
      settlePeerCatalog: true,
    );
  }

  Future<DaemonCommandResult> stopDaemon() async {
    cancelSpeedTest();
    return _runDaemonCommand(
      () => daemonController.stop(settingsStore.settings.diagnosticsUrl),
    );
  }

  Future<void> runSpeedTest(PeerSnapshot peer) async {
    if (_disposed || _speedTestRunning) return;
    final peerVirtualIp = peer.virtualIp.trim();
    if (peerVirtualIp.isEmpty) return;
    final runId = ++_speedTestRunId;
    final url = settingsStore.settings.diagnosticsUrl;
    _speedTestRunning = true;
    _speedTestPeerVirtualIp = peerVirtualIp;
    _speedTestStartedAt = DateTime.now();
    _speedTestClock
      ..reset()
      ..start();
    _lastSpeedTestResult = null;
    _lastSpeedTestError = null;
    notifyListeners();
    bool acceptsSession() =>
        !_disposed &&
        runId == _speedTestRunId &&
        url == settingsStore.settings.diagnosticsUrl;
    try {
      final result = await diagnosticsApi.runSpeedTest(
        url,
        peerVirtualIp: peerVirtualIp,
        duration: const Duration(seconds: 10),
      );
      if (acceptsSession()) _lastSpeedTestResult = result;
    } catch (error) {
      if (acceptsSession()) _lastSpeedTestError = error.toString();
    } finally {
      if (acceptsSession()) {
        _speedTestClock.stop();
        _speedTestRunning = false;
        _speedTestStartedAt = null;
        notifyListeners();
      }
    }
  }

  void cancelSpeedTest() {
    final changed = _speedTestRunning || _speedTestPeerVirtualIp != null;
    _speedTestRunId += 1;
    diagnosticsApi.cancelSpeedTest();
    _speedTestClock
      ..stop()
      ..reset();
    _speedTestRunning = false;
    _speedTestPeerVirtualIp = null;
    _speedTestStartedAt = null;
    _lastSpeedTestResult = null;
    _lastSpeedTestError = null;
    if (changed && !_disposed) notifyListeners();
  }

  Future<PeerSnapshot?> fetchSpeedTestPeerSnapshot(PeerSnapshot peer) async {
    if (_disposed) return null;
    final nodeId = peer.nodeId.trim();
    final virtualIp = peer.virtualIp.trim();
    if (nodeId.isEmpty && virtualIp.isEmpty) return null;
    final generation = _refreshGeneration;
    final runId = _speedTestRunId;
    final current = _snapshot;
    try {
      final snapshot = await diagnosticsApi.fetchStatus(
        settingsStore.settings.diagnosticsUrl,
      );
      if (_disposed ||
          generation != _refreshGeneration ||
          runId != _speedTestRunId ||
          !_snapshotCanReplace(snapshot, current) ||
          (current?.processId != null &&
              snapshot.processId != current?.processId) ||
          snapshot.peerSnapshotStale) {
        return null;
      }
      for (final candidate in snapshot.peers) {
        if (nodeId.isNotEmpty && candidate.nodeId.trim() == nodeId) {
          return candidate;
        }
        if (nodeId.isEmpty &&
            virtualIp.isNotEmpty &&
            candidate.virtualIp.trim() == virtualIp) {
          return candidate;
        }
      }
    } catch (_) {}
    return null;
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
    if (_disposed || _daemonBusy) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Another daemon operation is already running.',
      );
    }
    _daemonBusy = true;
    _daemonStarting = settlePeerCatalog;
    _lastDaemonMessage = null;
    _lastDaemonManualCommand = null;
    _lastDaemonFailureCode = null;
    notifyListeners();
    try {
      final result = await command();
      if (_disposed) return result;
      _lastDaemonMessage = result.message;
      _lastDaemonManualCommand = result.manualCommand;
      _lastDaemonFailureCode = result.failureCode;
      if (!result.ok) _lastError = 'daemon_operation_failed';
      if (result.ok && settlePeerCatalog) {
        await refreshUntilPeerCatalogSettled();
      } else {
        await refresh();
      }
      if (_disposed) return result;
      if (!result.ok) _lastError = 'daemon_operation_failed';
      if (result.ok && Platform.isAndroid) {
        final assignedVirtualIp = _snapshot?.virtualIp.trim() ?? '';
        if (settingsStore.settings.virtualIp.trim().isEmpty &&
            assignedVirtualIp.isNotEmpty) {
          await settingsStore.updateSettings(
            settingsStore.settings.copyWith(virtualIp: assignedVirtualIp),
          );
        }
      }
      return result;
    } catch (_) {
      const result = DaemonCommandResult(
        ok: false,
        message: 'daemon_operation_failed',
      );
      if (!_disposed) {
        _lastDaemonMessage = result.message;
        _lastDaemonManualCommand = result.manualCommand;
        _lastDaemonFailureCode = result.failureCode;
        _lastError = result.message;
      }
      return result;
    } finally {
      _daemonBusy = false;
      _daemonStarting = false;
      if (!_disposed) notifyListeners();
    }
  }

  bool _shouldSettlePeerCatalog() {
    final settings = settingsStore.settings;
    return (_daemonStarting && _snapshot == null) ||
        (!settings.manualMode && settings.authToken.trim().isNotEmpty);
  }

  static String _peerCatalogSignature(DiagnosticsSnapshot? snapshot) {
    if (snapshot == null) return '';
    final peerKeys = [
      for (final peer in snapshot.peers)
        '${peer.nodeId.trim()}|${peer.virtualIp.trim()}',
    ]..sort();
    return peerKeys.join('\n');
  }

  void _handleSettingsChanged() {
    final nextDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;
    if (nextDiagnosticsUrl == _lastDiagnosticsUrl) return;
    _lastDiagnosticsUrl = nextDiagnosticsUrl;
    _refreshGeneration += 1;
    cancelSpeedTest();
    lifecycleCoordinator.invalidateEventLoop();
    _eventLoopFuture = null;
    _refreshPending = true;
    _healthReachable = false;
    _consecutiveHealthFailures = 0;
    _clearSnapshot();
    _lastError = null;
    _lastHealthError = null;
    _lastStatusError = null;
    _lastFetchedAt = null;
    _lastRequestDuration = null;
    notifyListeners();
    unawaited(refresh(silent: true));
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    cancelSpeedTest();
    lifecycleCoordinator.dispose();
    _eventLoopFuture = null;
    _timer?.cancel();
    _staleTimer?.cancel();
    _automaticRefreshFuture = null;
    settingsStore.removeListener(_handleSettingsChanged);
    diagnosticsApi.close();
    super.dispose();
  }
}

class PeerTransferRate {
  const PeerTransferRate({
    required this.uploadBytesPerSecond,
    required this.downloadBytesPerSecond,
  });

  final int uploadBytesPerSecond;
  final int downloadBytesPerSecond;
}

class _PeerTrafficSample {
  const _PeerTrafficSample({
    required this.bytesSent,
    required this.bytesReceived,
    required this.fetchedAt,
  });

  final int bytesSent;
  final int bytesReceived;
  final DateTime fetchedAt;
}
