import 'dart:async';
import 'dart:io';

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
    this.enableEventPolling = true,
    this.startupCatalogRefreshTimeout = defaultStartupCatalogRefreshTimeout,
    this.startupCatalogRefreshInterval = defaultStartupCatalogRefreshInterval,
    this.routeVerificationInterval = Duration.zero,
    this.metricsUpdateInterval = defaultMetricsUpdateInterval,
  }) : daemonController =
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

  /// A near-real-time view while the app is visible, without a push protocol.
  static const defaultActivePollingInterval = Duration(seconds: 1);
  static const defaultBackgroundPollingInterval = Duration(seconds: 10);

  /// Presentation metrics (RTT and transfer rate) are deliberately sampled
  /// at this cadence even when the daemon event stream is more chatty. This
  /// keeps the list readable and prevents a burst of peer events from
  /// turning the UI into a high-frequency telemetry view.
  static const defaultMetricsUpdateInterval = Duration(seconds: 1);
  static const defaultRouteVerificationInterval = Duration(seconds: 10);
  static const defaultMaxSnapshotAge = Duration(seconds: 90);
  static const defaultStartupCatalogRefreshTimeout = Duration(seconds: 6);
  static const defaultStartupCatalogRefreshInterval = Duration(
    milliseconds: 500,
  );

  /// Windows route inspection starts a PowerShell process inside the daemon.
  /// Keep the normal snapshot cadence, but do not repeat this expensive read
  /// on every foreground refresh.
  static const defaultWindowsRouteVerificationInterval = Duration(seconds: 30);
  static const defaultWindowsStartupCatalogRefreshTimeout = Duration(
    seconds: 3,
  );
  static const defaultWindowsStartupCatalogRefreshInterval = Duration(
    milliseconds: 750,
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
  final bool enableEventPolling;
  final Duration startupCatalogRefreshTimeout;
  final Duration startupCatalogRefreshInterval;
  final Duration routeVerificationInterval;
  final Duration metricsUpdateInterval;

  Timer? _timer;
  Timer? _staleTimer;
  Future<void>? _eventLoopFuture;
  var _eventLoopGeneration = 0;
  var _disposed = false;
  DiagnosticsSnapshot? _snapshot;
  var _healthReachable = false;
  var _routeHealthy = false;
  var _refreshing = false;
  var _showRefreshActivity = false;
  var _daemonBusy = false;
  var _autoRefreshEnabled = false;
  var _appInForeground = true;
  var _snapshotStale = false;
  var _statusSnapshotTimedOut = false;
  var _refreshPending = false;
  var _refreshGeneration = 0;
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
  SpeedTestResult? _lastSpeedTestResult;
  String? _lastSpeedTestError;
  String? _speedTestPeerVirtualIp;
  DateTime? _speedTestStartedAt;
  var _peerTrafficSamples = <String, _PeerTrafficSample>{};
  var _peerTransferRatesBytesPerSecond = <String, int>{};
  // Keep catalog order separate from the live peer snapshot. The daemon may
  // return peers in a different order as paths, latency, or last-seen values
  // change; those are presentation fields and must not make rows jump.
  final _peerOrder = <String, int>{};
  var _nextPeerOrder = 0;
  // Online order is a separate monotonic sequence. A peer receives a new
  // online position only when it transitions from offline/missing to online;
  // this moves a reconnected peer behind peers that stayed online, while
  // preserving first-seen order for the offline section.
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
  bool get autoRefreshEnabled => _autoRefreshEnabled;
  bool get appInForeground => _appInForeground;
  bool get snapshotStale => _snapshotStale;
  bool get statusSnapshotTimedOut => _statusSnapshotTimedOut;
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
  SpeedTestResult? get lastSpeedTestResult => _lastSpeedTestResult;
  String? get lastSpeedTestError => _lastSpeedTestError;
  String? get speedTestPeerVirtualIp => _speedTestPeerVirtualIp;
  DateTime? get speedTestStartedAt => _speedTestStartedAt;

  /// Fresh combined sent + received rates, keyed by peer node ID. A peer is
  /// absent until two successful status samples are available.
  Map<String, int> get peerTransferRatesBytesPerSecond =>
      Map.unmodifiable(_peerTransferRatesBytesPerSecond);

  /// Returns peers with online devices first, ordered by the time they became
  /// online during this app session. Offline devices follow in first-seen
  /// catalog order. A peer that goes offline and later returns receives a new
  /// online sequence and moves to the end of the online group.
  ///
  /// The returned list is a fresh list and is safe for a view to filter or
  /// sort explicitly. Repeated status/metrics refreshes only replace the
  /// [PeerSnapshot] values, so a path or latency change cannot reorder the
  /// default device list. The catalog intentionally survives a temporary
  /// snapshot outage and a peer disappearing/reappearing during this app run.
  List<PeerSnapshot> stablePeerOrder(Iterable<PeerSnapshot> peers) {
    final byKey = <String, PeerSnapshot>{};
    for (final peer in peers) {
      final key = _peerOrderKey(peer);
      _peerOrder.putIfAbsent(key, () => _nextPeerOrder++);
      // Keep the newest snapshot value if a mixed-version response contains
      // duplicate entries for the same virtual IP/node.
      byKey[key] = peer;
    }
    _recordPeerPresence(byKey.values);
    final ordered = byKey.values.toList();
    ordered.sort(_comparePeerPresentationOrder);
    return ordered;
  }

  /// Records lifecycle transitions from a complete status snapshot. This is
  /// called at refresh time (not only while a page is mounted), so a device
  /// that disappears and reappears is still moved to the end of the online
  /// group even when the Devices page was not visible during the transition.
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
        // Defensive fallback for callers that restore a catalog without its
        // lifecycle map (for example, a hot-reload or an older test seam).
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
    if (_autoRefreshEnabled == enabled) {
      if (enabled && refreshImmediately) {
        unawaited(refreshUntilPeerCatalogSettled(silent: true));
      }
      if (enabled) _ensureEventLoop();
      return;
    }
    _autoRefreshEnabled = enabled;
    if (!enabled) {
      _lastAutomaticRefreshAt = null;
    }
    _schedulePolling();
    if (enabled) {
      _ensureEventLoop();
    } else {
      _eventLoopGeneration += 1;
    }
    if (enabled && refreshImmediately) {
      unawaited(refreshUntilPeerCatalogSettled(silent: true));
    }
    notifyListeners();
  }

  void updateAppLifecycleState(AppLifecycleState state) {
    final appInForeground = state == AppLifecycleState.resumed;
    if (_appInForeground == appInForeground) return;
    _appInForeground = appInForeground;
    _schedulePolling();
    if (_autoRefreshEnabled && appInForeground) {
      unawaited(refresh(silent: true));
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
    _timer = Timer.periodic(
      interval,
      (_) => unawaited(_refreshAutomatically()),
    );
  }

  void _ensureEventLoop() {
    if (!enableEventPolling ||
        !_autoRefreshEnabled ||
        _disposed ||
        _snapshot == null ||
        _eventLoopFuture != null) {
      return;
    }
    final generation = _eventLoopGeneration;
    final url = settingsStore.settings.diagnosticsUrl;
    late final Future<void> loop;
    loop = _runEventLoop(url, generation);
    _eventLoopFuture = loop;
    unawaited(
      loop.whenComplete(() {
        if (identical(_eventLoopFuture, loop)) {
          _eventLoopFuture = null;
          if (!_disposed && _autoRefreshEnabled && _snapshot != null) {
            scheduleMicrotask(_ensureEventLoop);
          }
        }
      }),
    );
  }

  Future<void> _runEventLoop(String url, int generation) async {
    var cursor = _snapshot?.revision ?? 0;
    var processId = _snapshot?.processId;
    while (!_disposed &&
        _autoRefreshEnabled &&
        generation == _eventLoopGeneration &&
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
        if (_disposed || generation != _eventLoopGeneration) return;
        await Future<void>.delayed(const Duration(seconds: 1));
        continue;
      }
      if (_disposed ||
          !_autoRefreshEnabled ||
          generation != _eventLoopGeneration ||
          url != settingsStore.settings.diagnosticsUrl) {
        return;
      }

      final current = _snapshot;
      if (current == null) return;
      if (current.processId != processId) {
        // The long poll completed against a daemon incarnation that has since
        // been replaced. Start the next request at the new process revision.
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
        if (_disposed || generation != _eventLoopGeneration) return;
        final refreshed = _snapshot;
        if (refreshed == null) return;
        processId = refreshed.processId;
        cursor = refreshed.revision;
        if (refreshed.processId == current.processId &&
            cursor <= beforeRevision &&
            response.revision > cursor) {
          // Avoid a tight loop if an event races a temporarily unavailable
          // snapshot; the next long poll/refetch will converge.
          await Future<void>.delayed(const Duration(milliseconds: 250));
        }
      }
    }
  }

  /// Runs an automatic refresh at the configured foreground/background
  /// cadence. The daemon's event stream can complete several times per
  /// second; serialising these refreshes here keeps both the snapshot and its
  /// derived metrics on the same predictable clock.
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
      final elapsed = DateTime.now().difference(last);
      final remaining = interval - elapsed;
      if (remaining > Duration.zero) {
        await Future<void>.delayed(remaining);
      }
    }
    if (_disposed || !_autoRefreshEnabled) return;
    _lastAutomaticRefreshAt = DateTime.now();
    await refresh(silent: true);
  }

  /// Refreshes the daemon snapshot. Automatic polling passes [silent] so the
  /// UI remains stable; an explicit user refresh keeps its progress feedback.
  Future<void> refresh({bool silent = false}) {
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
    notifyListeners();
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
      } while (_refreshPending);
      completer.complete();
    } catch (error, stackTrace) {
      completer.completeError(error, stackTrace);
    } finally {
      if (identical(_refreshFuture, completer.future)) {
        _refreshFuture = null;
      }
      _refreshing = false;
      _showRefreshActivity = false;
      notifyListeners();
    }
  }

  Future<void> _refreshOnce(
    String url,
    int generation, {
    required bool throttleMetrics,
  }) async {
    final stopwatch = Stopwatch()..start();
    try {
      final health = await diagnosticsApi.fetchHealth(url);
      if (generation != _refreshGeneration) {
        _refreshPending = true;
        return;
      }

      _lastHealthError = null;
      _lastStatusError = null;
      _statusSnapshotTimedOut = false;
      _healthReachable = health;
      if (!health) {
        _statusSnapshotTimedOut = false;
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
        _statusSnapshotTimedOut = false;
        if (!_snapshotCanReplace(snapshot, _snapshot)) {
          // An older response from the same daemon process must never roll the
          // UI, latency, or peer catalog backwards. It is still evidence that
          // the HTTP endpoint is alive, but it is not a successful status
          // snapshot and therefore does not refresh the stale deadline.
          _lastError = null;
          _lastFetchedAt = fetchedAt;
          return;
        }
        _updatePeerTrafficRates(snapshot, fetchedAt, throttle: throttleMetrics);
        recordPeerPresence(snapshot.peers);
        _snapshot = snapshot;
        if (_shouldVerifyRoutes(fetchedAt)) {
          try {
            _routeHealthy = (await diagnosticsApi.verifyRoutes(url)).healthy;
          } catch (_) {
            _routeHealthy = false;
          } finally {
            _lastRouteVerificationAt = DateTime.now();
          }
        }
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
        final snapshotTimedOut =
            error is DiagnosticsApiException &&
            error.reasonCode == 'status_snapshot_timeout';
        _statusSnapshotTimedOut = snapshotTimedOut;
        if (!snapshotTimedOut) {
          _clearSnapshot();
          _lastStatusError = 'GET /status failed: $error';
          _lastError = _lastStatusError;
        } else {
          // /health has already succeeded. A snapshot timeout means the
          // daemon is alive but its hot peer locks are busy; keep the last
          // known snapshot and let the next poll retry without presenting a
          // false "network issue" banner.
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
      _healthReachable = false;
      _statusSnapshotTimedOut = false;
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
      // Keep the previous baseline until the next presentation tick. Using a
      // sub-second sample here would make the calculated rate depend on event
      // delivery jitter rather than actual traffic over a stable interval.
      return;
    }
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
    _lastPeerTrafficSampleAt = fetchedAt;
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

    // PID reuse is possible. A lower uptime is affirmative evidence of a new
    // daemon incarnation even when the OS reused the same numeric PID.
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
    if (!skipInitialRefresh) {
      await refresh(silent: silent);
    }
    if (!_shouldSettlePeerCatalog()) return;

    final deadline = DateTime.now().add(startupCatalogRefreshTimeout);
    var refreshCount = 1;
    var stableCatalogCount = 0;
    var previousSignature = _peerCatalogSignature(_snapshot);
    while (refreshCount < _startupCatalogMaxRefreshes &&
        DateTime.now().isBefore(deadline)) {
      if (startupCatalogRefreshInterval > Duration.zero) {
        await Future<void>.delayed(startupCatalogRefreshInterval);
      } else {
        await Future<void>.delayed(Duration.zero);
      }

      await refresh(silent: silent);
      refreshCount += 1;

      final currentSnapshot = _snapshot;
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
    _lastDaemonFailureCode = null;
    notifyListeners();
    try {
      final result = await command();
      _lastDaemonMessage = result.message;
      _lastDaemonManualCommand = result.manualCommand;
      _lastDaemonFailureCode = result.failureCode;
      if (!result.ok) {
        _lastError = result.message;
      }
      if (result.ok && settlePeerCatalog) {
        await refreshUntilPeerCatalogSettled();
      } else {
        await refresh();
      }
      if (result.ok && Platform.isAndroid) {
        final assignedVirtualIp = _snapshot?.virtualIp.trim() ?? '';
        if (settingsStore.settings.virtualIp.trim().isEmpty &&
            assignedVirtualIp.isNotEmpty) {
          // The first managed Android start may receive its VIP only after
          // registration. Persist it so the next VPN establish() uses the
          // same system-interface address without another provisional bind.
          await settingsStore.updateSettings(
            settingsStore.settings.copyWith(virtualIp: assignedVirtualIp),
          );
        }
      }
      return result;
    } catch (error) {
      final result = DaemonCommandResult(
        ok: false,
        message: 'Daemon operation failed: $error',
      );
      _lastDaemonMessage = result.message;
      _lastDaemonManualCommand = result.manualCommand;
      _lastDaemonFailureCode = result.failureCode;
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

  void _handleSettingsChanged() {
    final nextDiagnosticsUrl = settingsStore.settings.diagnosticsUrl;
    if (nextDiagnosticsUrl == _lastDiagnosticsUrl) return;
    _lastDiagnosticsUrl = nextDiagnosticsUrl;
    _refreshGeneration += 1;
    _eventLoopGeneration += 1;
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
    unawaited(refresh(silent: true));
  }

  @override
  void dispose() {
    _disposed = true;
    _eventLoopGeneration += 1;
    _timer?.cancel();
    _staleTimer?.cancel();
    _automaticRefreshFuture = null;
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
