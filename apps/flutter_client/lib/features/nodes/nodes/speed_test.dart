part of '../nodes_page.dart';

class _SpeedTestDialog extends StatefulWidget {
  const _SpeedTestDialog({
    required this.peer,
    required this.statusStore,
    required this.strings,
  });

  final PeerSnapshot peer;
  final StatusStore statusStore;
  final AppStrings strings;

  @override
  State<_SpeedTestDialog> createState() => _SpeedTestDialogState();
}

class _SpeedTestDialogState extends State<_SpeedTestDialog> {
  static const _testDuration = Duration(seconds: 10);
  static const _desktopSampleInterval = Duration(milliseconds: 200);

  Timer? _progressTimer;
  Timer? _desktopSampleTimer;
  var _desktopSampleInFlight = false;
  var _desktopDialog = false;
  var _wasRunning = false;
  SpeedTestResult? _observedResult;
  String? _observedError;
  final _samples = <_SpeedTestPoint>[];
  late final _SpeedTestTelemetry _desktopTelemetry;

  @override
  void initState() {
    super.initState();
    _desktopTelemetry = _SpeedTestTelemetry(
      maxSamples:
          (_testDuration.inMilliseconds / _desktopSampleInterval.inMilliseconds)
              .ceil(),
    );
    widget.statusStore.addListener(_handleStatusChanged);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final desktop = _isDesktopDialog(context);
    if (_desktopDialog == desktop) return;
    _desktopDialog = desktop;
    _syncSamplingTimers();
  }

  @override
  void dispose() {
    _progressTimer?.cancel();
    _desktopSampleTimer?.cancel();
    widget.statusStore.removeListener(_handleStatusChanged);
    _desktopTelemetry.dispose();
    super.dispose();
  }

  void _handleStatusChanged() {
    final running = _runningForPeer;
    final result = widget.statusStore.speedTestResultFor(widget.peer);
    final error = widget.statusStore.speedTestErrorFor(widget.peer);
    if (running) {
      _recordLiveSample();
    } else if (result != null) {
      _recordResultSample();
      if (result != _desktopTelemetry.result) {
        _desktopTelemetry.recordResult(result, widget.peer.latencyMs);
      }
    }
    _syncSamplingTimers();
    if (!mounted) return;
    final changed =
        _wasRunning != running ||
        !identical(_observedResult, result) ||
        _observedError != error;
    if (changed) {
      setState(() {});
    }
    _wasRunning = running;
    _observedResult = result;
    _observedError = error;
  }

  void _syncSamplingTimers() {
    if (_runningForPeer && _desktopDialog) {
      _progressTimer?.cancel();
      _progressTimer = null;
      _desktopSampleTimer ??= Timer.periodic(
        _desktopSampleInterval,
        (_) => unawaited(_captureDesktopSample()),
      );
      return;
    }
    _desktopSampleTimer?.cancel();
    _desktopSampleTimer = null;
    if (_runningForPeer && !_desktopDialog) {
      _progressTimer ??= Timer.periodic(const Duration(milliseconds: 100), (_) {
        if (mounted) setState(() {});
      });
      return;
    }
    _progressTimer?.cancel();
    _progressTimer = null;
  }

  bool _isDesktopDialog(BuildContext context) {
    final desktopPlatform =
        Platform.isMacOS || Platform.isWindows || Platform.isLinux;
    return desktopPlatform &&
        MediaQuery.sizeOf(context).width >=
            AppBreakpoints.desktopSidebarMinWidth;
  }

  Future<void> _captureDesktopSample() async {
    if (!_desktopDialog || !_runningForPeer || _desktopSampleInFlight) return;
    _desktopSampleInFlight = true;
    try {
      final peer = await widget.statusStore.fetchSpeedTestPeerSnapshot(
        widget.peer,
      );
      if (peer != null) {
        _desktopTelemetry.recordPeer(peer, DateTime.now());
      } else {
        _desktopTelemetry.tick(DateTime.now());
      }
    } finally {
      _desktopSampleInFlight = false;
    }
  }

  void _resetDesktopTelemetry() {
    _desktopTelemetry.reset(
      startedAt: widget.statusStore.speedTestStartedAt ?? DateTime.now(),
      peer: widget.peer,
    );
  }

  bool get _runningForPeer =>
      widget.statusStore.speedTestRunning &&
      widget.statusStore.speedTestMatches(widget.peer);

  bool get _runningElsewhere =>
      widget.statusStore.speedTestRunning && !_runningForPeer;

  void _run() {
    if (!_canRunSpeedTest(widget.peer) || widget.statusStore.speedTestRunning) {
      return;
    }
    _samples.clear();
    _resetDesktopTelemetry();
    if (mounted) setState(() {});
    unawaited(widget.statusStore.runSpeedTest(widget.peer));
    _syncSamplingTimers();
  }

  void _recordLiveSample() {
    final startedAt = widget.statusStore.speedTestStartedAt;
    if (startedAt == null) return;
    final elapsedMs = DateTime.now().difference(startedAt).inMilliseconds;
    final rate = widget.statusStore.snapshotStale
        ? null
        : widget.statusStore.peerDirectionalTransferRates[widget.peer.nodeId];
    _appendSample(
      _SpeedTestPoint(
        elapsedMs: elapsedMs.clamp(0, _testDuration.inMilliseconds),
        downloadMbps: _bytesPerSecondToMbps(rate?.downloadBytesPerSecond ?? 0),
        uploadMbps: _bytesPerSecondToMbps(rate?.uploadBytesPerSecond ?? 0),
      ),
    );
  }

  void _recordResultSample() {
    final result = widget.statusStore.speedTestResultFor(widget.peer);
    if (result == null) return;
    _appendSample(
      _SpeedTestPoint(
        elapsedMs: result.durationMs.clamp(0, _testDuration.inMilliseconds),
        downloadMbps: result.downloadMbps,
        uploadMbps: result.uploadMbps,
      ),
    );
  }

  void _appendSample(_SpeedTestPoint sample) {
    final previous = _samples.isEmpty ? null : _samples.last;
    if (previous != null && sample.elapsedMs <= previous.elapsedMs) {
      _samples[_samples.length - 1] = sample;
      return;
    }
    _samples.add(sample);
    if (_samples.length > 80) _samples.removeAt(0);
  }

  static double _bytesPerSecondToMbps(int bytesPerSecond) {
    return bytesPerSecond * 8 / 1000000;
  }

  @override
  Widget build(BuildContext context) {
    if (_desktopDialog) return _buildDesktopDialog(context);
    final strings = widget.strings;
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final result = widget.statusStore.speedTestResultFor(widget.peer);
    final error = widget.statusStore.speedTestErrorFor(widget.peer);
    final eligible = _canRunSpeedTest(widget.peer);
    final startedAt = widget.statusStore.speedTestStartedAt;
    final elapsed = _runningForPeer && startedAt != null
        ? DateTime.now().difference(startedAt)
        : Duration.zero;
    final cappedElapsed = elapsed > _testDuration ? _testDuration : elapsed;
    final progress =
        cappedElapsed.inMilliseconds / _testDuration.inMilliseconds;
    final dialogSize = MediaQuery.sizeOf(context);
    final viewInsets = MediaQuery.viewInsetsOf(context);
    final safePadding = MediaQuery.paddingOf(context);
    final maxWidth = dialogSize.width > 560
        ? 520.0
        : math.max(280.0, dialogSize.width - 32);
    final maxHeight = math.max(
      240.0,
      math.min(
        640.0,
        dialogSize.height - viewInsets.vertical - safePadding.vertical - 48,
      ),
    );
    final List<_SpeedTestPoint> chartSamples = _samples.isEmpty
        ? const <_SpeedTestPoint>[
            _SpeedTestPoint(elapsedMs: 0, downloadMbps: 0, uploadMbps: 0),
          ]
        : List.unmodifiable(_samples);

    return Dialog(
      key: const Key('node-speedtest-dialog'),
      insetPadding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space16,
        vertical: AppTokens.space24,
      ),
      backgroundColor: colorScheme.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
      ),
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: maxWidth, maxHeight: maxHeight),
        child: SingleChildScrollView(
          primary: false,
          padding: const EdgeInsets.fromLTRB(20, 18, 20, 14),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          strings.speedTestTitle,
                          style: TextStyle(
                            color: colorScheme.onSurface,
                            fontSize: 17,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: AppTokens.space4),
                        Text(
                          strings.speedTestPeer(widget.peer.displayName),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: colorScheme.onSurfaceVariant,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: AppTokens.space12),
                  Flexible(
                    child: Text(
                      _rowPathLabel(strings, widget.peer),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      textAlign: TextAlign.end,
                      style: TextStyle(
                        color: colorScheme.onSurfaceVariant,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  IconButton(
                    tooltip: strings.close,
                    onPressed: () => Navigator.of(context).pop(),
                    visualDensity: VisualDensity.compact,
                    icon: const Icon(Icons.close_rounded, size: 20),
                  ),
                ],
              ),
              const SizedBox(height: AppTokens.space16),
              _MobileSpeedTestLinkInfo(
                peer: widget.peer,
                path: _connectionLabel(strings, widget.peer),
                pathColor: _rowStatusColor(context, widget.peer),
                strings: strings,
              ),
              if (_runningForPeer || _samples.isNotEmpty) ...[
                const SizedBox(height: AppTokens.space14),
                _SpeedTestChart(
                  samples: chartSamples,
                  duration: _testDuration,
                  downloadColor: colorScheme.primary,
                  uploadColor: colorScheme.tertiary,
                  strings: strings,
                ),
              ],
              const SizedBox(height: 18),
              if (!eligible)
                _SpeedTestMessage(
                  icon: Icons.info_outline_rounded,
                  message: strings.speedTestUnavailable,
                  color: colorScheme.onSurfaceVariant,
                )
              else if (_runningElsewhere)
                _SpeedTestMessage(
                  icon: Icons.hourglass_top_rounded,
                  message: strings.speedTestRunningOn(
                    widget.statusStore.speedTestPeerVirtualIp ?? '',
                  ),
                  color: colorScheme.onSurfaceVariant,
                )
              else if (_runningForPeer) ...[
                LinearProgressIndicator(value: progress),
                const SizedBox(height: AppTokens.space10),
                Row(
                  children: [
                    const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 9),
                    Text(
                      strings.speedTesting,
                      style: TextStyle(
                        color: colorScheme.onSurface,
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const Spacer(),
                    Text(
                      strings.speedTestProgress(cappedElapsed.inSeconds),
                      style: TextStyle(
                        color: colorScheme.onSurfaceVariant,
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ],
                ),
              ] else if (error != null && error.isNotEmpty)
                _SpeedTestMessage(
                  icon: Icons.error_outline_rounded,
                  message: strings.speedTestFailed(error),
                  color: colorScheme.error,
                )
              else if (result != null)
                _SpeedTestResult(
                  result: result,
                  latencyMs: widget.peer.latencyMs,
                  strings: strings,
                )
              else
                _SpeedTestMessage(
                  icon: Icons.speed_rounded,
                  message: strings.speedTestDuration,
                  color: colorScheme.onSurfaceVariant,
                ),
              const SizedBox(height: AppTokens.space20),
              LayoutBuilder(
                builder: (context, constraints) {
                  final startButton = FilledButton.icon(
                    key: const Key('node-speedtest-start'),
                    onPressed: eligible && !widget.statusStore.speedTestRunning
                        ? _run
                        : null,
                    icon: const Icon(Icons.speed_rounded, size: 18),
                    label: Text(
                      result != null || error != null
                          ? strings.retrySpeedTest
                          : strings.startSpeedTest,
                    ),
                  );
                  if (constraints.maxWidth < 340) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        SizedBox(width: double.infinity, child: startButton),
                        const SizedBox(height: AppTokens.space4),
                        Align(
                          alignment: Alignment.center,
                          child: TextButton(
                            onPressed: () => Navigator.of(context).pop(),
                            child: Text(strings.close),
                          ),
                        ),
                      ],
                    );
                  }
                  return OverflowBar(
                    alignment: MainAxisAlignment.end,
                    spacing: AppTokens.space8,
                    overflowSpacing: AppTokens.space4,
                    overflowAlignment: OverflowBarAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.of(context).pop(),
                        child: Text(strings.close),
                      ),
                      startButton,
                    ],
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDesktopDialog(BuildContext context) {
    final strings = widget.strings;
    final colorScheme = Theme.of(context).colorScheme;
    final colors = P2WlanColors.of(context);
    final result = widget.statusStore.speedTestResultFor(widget.peer);
    final error = widget.statusStore.speedTestErrorFor(widget.peer);
    final eligible = _canRunSpeedTest(widget.peer);
    final size = MediaQuery.sizeOf(context);
    final maxWidth = math.min(900.0, math.max(0.0, size.width - 32));
    final maxDialogHeight = math.min(720.0, math.max(0.0, size.height - 48));
    final chartHeight = _desktopChartHeight(
      maxWidth: maxWidth,
      maxDialogHeight: maxDialogHeight,
    );
    final pathLabel = _rowPathLabel(strings, widget.peer);
    final pathValue = _connectionLabel(strings, widget.peer);
    final pathColor = _rowStatusColor(context, widget.peer);

    return Dialog(
      key: const Key('node-speedtest-dialog'),
      insetPadding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space16,
        vertical: AppTokens.space24,
      ),
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: maxWidth,
          maxHeight: maxDialogHeight,
        ),
        child: SingleChildScrollView(
          primary: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(24, 20, 24, 18),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            strings.speedTestTitle,
                            style: TextStyle(
                              color: colorScheme.onSurface,
                              fontSize: 21,
                              fontWeight: FontWeight.w700,
                              height: 1.1,
                            ),
                          ),
                          const SizedBox(height: 5),
                          Text(
                            strings.speedTestPeer(widget.peer.displayName),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              color: colorScheme.onSurfaceVariant,
                              fontSize: 13,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: AppTokens.space12),
                    _DesktopPathBadge(label: pathLabel, color: pathColor),
                    const SizedBox(width: AppTokens.space4),
                    IconButton(
                      tooltip: strings.close,
                      onPressed: () => Navigator.of(context).pop(),
                      padding: EdgeInsets.zero,
                      visualDensity: VisualDensity.compact,
                      icon: Icon(
                        Icons.close_rounded,
                        size: 24,
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                _DesktopSpeedLinkInfo(
                  peer: widget.peer,
                  path: pathValue,
                  pathColor: pathColor,
                  strings: strings,
                ),
                const SizedBox(height: 12),
                AnimatedBuilder(
                  animation: _desktopTelemetry,
                  builder: (context, _) => _DesktopSpeedRateCards(
                    downloadMbps: _desktopTelemetry.currentDownloadMbps,
                    uploadMbps: _desktopTelemetry.currentUploadMbps,
                    strings: strings,
                    downloadColor: colorScheme.primary,
                    uploadColor: colors.direct,
                  ),
                ),
                const SizedBox(height: 12),
                RepaintBoundary(
                  child: AnimatedBuilder(
                    animation: _desktopTelemetry,
                    builder: (context, _) => _DesktopSpeedTestChart(
                      samples: _desktopTelemetry.samples,
                      maxSpeed: _desktopTelemetry.chartMaxMbps,
                      duration: _testDuration,
                      height: chartHeight,
                      downloadColor: colorScheme.primary,
                      uploadColor: colors.direct,
                      axisColor: colorScheme.onSurfaceVariant,
                      gridColor: colorScheme.outlineVariant,
                      strings: strings,
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                AnimatedBuilder(
                  animation: _desktopTelemetry,
                  builder: (context, _) => _DesktopSpeedSummary(
                    telemetry: _desktopTelemetry,
                    result: result,
                    fallbackRttMs: widget.peer.latencyMs,
                    strings: strings,
                    downloadColor: colorScheme.primary,
                    uploadColor: colors.direct,
                  ),
                ),
                if (_runningElsewhere) ...[
                  const SizedBox(height: 10),
                  _DesktopSpeedNotice(
                    icon: Icons.hourglass_top_rounded,
                    message: strings.speedTestRunningOn(
                      widget.statusStore.speedTestPeerVirtualIp ?? '',
                    ),
                    color: colorScheme.onSurfaceVariant,
                  ),
                ] else if (error != null && error.isNotEmpty) ...[
                  const SizedBox(height: 10),
                  _DesktopSpeedNotice(
                    icon: Icons.error_outline_rounded,
                    message: strings.speedTestFailed(error),
                    color: colorScheme.error,
                  ),
                ] else if (!eligible) ...[
                  const SizedBox(height: 10),
                  _DesktopSpeedNotice(
                    icon: Icons.info_outline_rounded,
                    message: strings.speedTestUnavailable,
                    color: colorScheme.onSurfaceVariant,
                  ),
                ],
                const SizedBox(height: 14),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: Text(strings.close),
                    ),
                    const SizedBox(width: AppTokens.space8),
                    FilledButton.icon(
                      key: const Key('node-speedtest-start'),
                      onPressed:
                          eligible && !widget.statusStore.speedTestRunning
                          ? _run
                          : null,
                      icon: Icon(
                        _runningForPeer
                            ? Icons.hourglass_top_rounded
                            : Icons.speed_rounded,
                        size: 18,
                      ),
                      label: Text(
                        _runningForPeer || _runningElsewhere
                            ? strings.speedTesting
                            : result != null || error != null
                            ? strings.retrySpeedTest
                            : strings.startSpeedTest,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  static double _desktopChartHeight({
    required double maxWidth,
    required double maxDialogHeight,
  }) {
    final preferred = maxWidth < 820 ? 214.0 : 248.0;
    if (maxDialogHeight >= 640) return preferred;
    // The default macOS window can be close to 800×600. Keep the graph
    // readable there while reserving enough room for the summary and actions.
    return math.max(128.0, math.min(preferred, maxDialogHeight - 462));
  }
}

class _SpeedTestPoint {
  const _SpeedTestPoint({
    required this.elapsedMs,
    required this.downloadMbps,
    required this.uploadMbps,
  });

  final int elapsedMs;
  final double downloadMbps;
  final double uploadMbps;
}

/// Short-lived telemetry model owned by the desktop speed-test surface. It
/// keeps the high-frequency sampler and chart rebuilds local to the modal;
/// the rest of the app remains on its calmer one-second presentation cadence.
class _SpeedTestTelemetry extends ChangeNotifier {
  _SpeedTestTelemetry({required this.maxSamples});

  final int maxSamples;
  final _samples = <_SpeedTestPoint>[];
  var _publishedSamples = const <_SpeedTestPoint>[];
  DateTime? _startedAt;
  DateTime? _lastSampleAt;
  PeerSnapshot? _baselinePeer;
  double _currentDownloadMbps = 0;
  double _currentUploadMbps = 0;
  double _chartMaxMbps = 10;
  DateTime? _lastScaleEvaluation;
  int _elapsedMs = 0;
  int _downloadBytes = 0;
  int _uploadBytes = 0;
  int? _rttMs;
  SpeedTestResult? result;

  List<_SpeedTestPoint> get samples => _publishedSamples;
  double get currentDownloadMbps => _currentDownloadMbps;
  double get currentUploadMbps => _currentUploadMbps;
  double get chartMaxMbps => _chartMaxMbps;
  int get elapsedMs => _elapsedMs;
  int get downloadBytes => _downloadBytes;
  int get uploadBytes => _uploadBytes;
  int? get rttMs => _rttMs;

  double get averageDownloadMbps => _averageMbps(_downloadBytes);
  double get averageUploadMbps => _averageMbps(_uploadBytes);

  void reset({required DateTime startedAt, required PeerSnapshot peer}) {
    _samples.clear();
    _publishedSamples = const <_SpeedTestPoint>[];
    _startedAt = startedAt;
    _lastSampleAt = null;
    _baselinePeer = peer;
    _currentDownloadMbps = 0;
    _currentUploadMbps = 0;
    _chartMaxMbps = 10;
    _lastScaleEvaluation = startedAt;
    _elapsedMs = 0;
    _downloadBytes = 0;
    _uploadBytes = 0;
    _rttMs = peer.latencyMs;
    result = null;
    notifyListeners();
  }

  void tick(DateTime now) {
    final elapsed = _elapsedAt(now);
    if (elapsed == _elapsedMs) return;
    _elapsedMs = elapsed;
    notifyListeners();
  }

  void recordPeer(PeerSnapshot peer, DateTime now) {
    final baseline = _baselinePeer;
    final previous = _lastSampleAt == null ? baseline : _lastPeer;
    final elapsed = _elapsedAt(now);
    final elapsedSincePrevious = _lastSampleAt == null
        ? elapsed
        : now.difference(_lastSampleAt!).inMilliseconds;
    final sentDelta = baseline == null
        ? 0
        : peer.bytesSent - (previous?.bytesSent ?? baseline.bytesSent);
    final receivedDelta = baseline == null
        ? 0
        : peer.bytesReceived -
              (previous?.bytesReceived ?? baseline.bytesReceived);

    if (sentDelta >= 0 && receivedDelta >= 0 && elapsedSincePrevious > 0) {
      _currentUploadMbps = _bytesToMbps(sentDelta, elapsedSincePrevious);
      _currentDownloadMbps = _bytesToMbps(receivedDelta, elapsedSincePrevious);
      if (baseline != null) {
        _uploadBytes = math.max(0, peer.bytesSent - baseline.bytesSent);
        _downloadBytes = math.max(
          0,
          peer.bytesReceived - baseline.bytesReceived,
        );
      }
      _append(
        _SpeedTestPoint(
          elapsedMs: elapsed,
          downloadMbps: _currentDownloadMbps,
          uploadMbps: _currentUploadMbps,
        ),
      );
      _maybeExpandScale(now);
    } else if (sentDelta < 0 || receivedDelta < 0) {
      // Counters can reset when the peer connection is recreated. Treat the
      // next snapshot as a fresh baseline instead of drawing a false spike.
      _baselinePeer = peer;
      _currentDownloadMbps = 0;
      _currentUploadMbps = 0;
    }

    _lastPeer = peer;
    _lastSampleAt = now;
    _elapsedMs = elapsed;
    _rttMs = peer.latencyMs ?? _rttMs;
    _publish();
  }

  void recordResult(SpeedTestResult value, int? fallbackRttMs) {
    result = value;
    _elapsedMs = value.durationMs.clamp(0, 10000);
    _currentDownloadMbps = value.downloadMbps;
    _currentUploadMbps = value.uploadMbps;
    _downloadBytes = value.downloadBytes;
    _uploadBytes = value.uploadBytes;
    _rttMs = _rttMs ?? fallbackRttMs;
    _append(
      _SpeedTestPoint(
        elapsedMs: _elapsedMs,
        downloadMbps: value.downloadMbps,
        uploadMbps: value.uploadMbps,
      ),
    );
    _maybeExpandScale(DateTime.now(), force: true);
    _publish();
  }

  PeerSnapshot? _lastPeer;

  int _elapsedAt(DateTime now) {
    final startedAt = _startedAt;
    if (startedAt == null) return 0;
    return now.difference(startedAt).inMilliseconds.clamp(0, 10000);
  }

  double _averageMbps(int bytes) {
    if (_elapsedMs <= 0 || bytes <= 0) return 0;
    return bytes * 8 * 1000 / (_elapsedMs * 1000000);
  }

  static double _bytesToMbps(int bytes, int elapsedMs) {
    if (bytes <= 0 || elapsedMs <= 0) return 0;
    return bytes * 8 * 1000 / (elapsedMs * 1000000);
  }

  void _append(_SpeedTestPoint point) {
    final previous = _samples.isEmpty ? null : _samples.last;
    if (previous != null && point.elapsedMs <= previous.elapsedMs) {
      _samples[_samples.length - 1] = point;
      return;
    }
    _samples.add(point);
    if (_samples.length > maxSamples) _samples.removeAt(0);
  }

  void _maybeExpandScale(DateTime now, {bool force = false}) {
    final peak = _samples.fold<double>(
      0,
      (maximum, sample) =>
          math.max(maximum, math.max(sample.downloadMbps, sample.uploadMbps)),
    );
    if (peak <= 0) return;
    final last = _lastScaleEvaluation;
    if (!force &&
        last != null &&
        now.difference(last) < const Duration(milliseconds: 500) &&
        peak < _chartMaxMbps * 0.85) {
      return;
    }
    final target = _niceScale(peak);
    if (target > _chartMaxMbps) _chartMaxMbps = target;
    _lastScaleEvaluation = now;
  }

  static double _niceScale(double value) {
    if (!value.isFinite || value <= 0) return 10;
    final magnitude = math
        .pow(10, (math.log(value) / math.ln10).floor())
        .toDouble();
    final normalized = value / magnitude;
    final step = normalized <= 1
        ? 1
        : normalized <= 2
        ? 2
        : normalized <= 5
        ? 5
        : 10;
    return math.max(1, step * magnitude);
  }

  void _publish() {
    _publishedSamples = List.unmodifiable(_samples);
    notifyListeners();
  }
}

class _DesktopPathBadge extends StatelessWidget {
  const _DesktopPathBadge({required this.label, required this.color});

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              color: color,
              fontSize: 12,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class _DesktopSpeedLinkInfo extends StatelessWidget {
  const _DesktopSpeedLinkInfo({
    required this.peer,
    required this.path,
    required this.pathColor,
    required this.strings,
  });

  final PeerSnapshot peer;
  final String path;
  final Color pathColor;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      key: const Key('node-speedtest-link-info'),
      height: 68,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Expanded(
            child: _DesktopLinkValue(
              icon: Icons.desktop_windows_outlined,
              label: strings.virtualIp,
              value: dash(peer.virtualIp),
            ),
          ),
          Container(
            width: 1,
            height: 38,
            color: theme.colorScheme.outlineVariant,
          ),
          Expanded(
            child: _DesktopLinkValue(
              icon: Icons.route_outlined,
              label: strings.path,
              value: path,
              valueColor: pathColor,
            ),
          ),
        ],
      ),
    );
  }
}

class _DesktopLinkValue extends StatelessWidget {
  const _DesktopLinkValue({
    required this.icon,
    required this.label,
    required this.value,
    this.valueColor,
  });

  final IconData icon;
  final String label;
  final String value;
  final Color? valueColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      children: [
        const SizedBox(width: 2),
        Icon(icon, size: 23, color: theme.colorScheme.onSurfaceVariant),
        const SizedBox(width: 12),
        Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: valueColor ?? theme.colorScheme.onSurface,
                fontSize: 16,
                fontWeight: FontWeight.w700,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _DesktopSpeedRateCards extends StatelessWidget {
  const _DesktopSpeedRateCards({
    required this.downloadMbps,
    required this.uploadMbps,
    required this.strings,
    required this.downloadColor,
    required this.uploadColor,
  });

  final double downloadMbps;
  final double uploadMbps;
  final AppStrings strings;
  final Color downloadColor;
  final Color uploadColor;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: _DesktopSpeedRateCard(
            icon: Icons.arrow_downward_rounded,
            label: strings.speedTestDownloadRate,
            value: downloadMbps,
            unit: strings.speedTestMbps,
            color: downloadColor,
          ),
        ),
        const SizedBox(width: AppTokens.space12),
        Expanded(
          child: _DesktopSpeedRateCard(
            icon: Icons.arrow_upward_rounded,
            label: strings.speedTestUploadRate,
            value: uploadMbps,
            unit: strings.speedTestMbps,
            color: uploadColor,
          ),
        ),
      ],
    );
  }
}

class _DesktopSpeedRateCard extends StatelessWidget {
  const _DesktopSpeedRateCard({
    required this.icon,
    required this.label,
    required this.value,
    required this.unit,
    required this.color,
  });

  final IconData icon;
  final String label;
  final double value;
  final String unit;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      height: 92,
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.045),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: color.withValues(alpha: 0.24)),
      ),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
            child: Icon(icon, color: Colors.white, size: 25),
          ),
          const SizedBox(width: 13),
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.baseline,
                  textBaseline: TextBaseline.alphabetic,
                  children: [
                    Text(
                      _formatSpeedNumber(value),
                      style: TextStyle(
                        color: theme.colorScheme.onSurface,
                        fontSize: 31,
                        fontWeight: FontWeight.w700,
                        height: 1,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                    const SizedBox(width: 7),
                    Text(
                      unit,
                      style: TextStyle(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 14,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _DesktopSpeedTestChart extends StatefulWidget {
  const _DesktopSpeedTestChart({
    required this.samples,
    required this.maxSpeed,
    required this.duration,
    required this.height,
    required this.downloadColor,
    required this.uploadColor,
    required this.axisColor,
    required this.gridColor,
    required this.strings,
  });

  final List<_SpeedTestPoint> samples;
  final double maxSpeed;
  final Duration duration;
  final double height;
  final Color downloadColor;
  final Color uploadColor;
  final Color axisColor;
  final Color gridColor;
  final AppStrings strings;

  @override
  State<_DesktopSpeedTestChart> createState() => _DesktopSpeedTestChartState();
}

class _DesktopSpeedTestChartState extends State<_DesktopSpeedTestChart>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  List<_SpeedTestPoint> _fromSamples = const [];
  List<_SpeedTestPoint> _targetSamples = const [];
  double _fromMaxSpeed = 10;
  double _targetMaxSpeed = 10;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 160),
      value: 1,
    );
    _fromSamples = widget.samples;
    _targetSamples = widget.samples;
    _fromMaxSpeed = widget.maxSpeed;
    _targetMaxSpeed = widget.maxSpeed;
  }

  @override
  void didUpdateWidget(covariant _DesktopSpeedTestChart oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (identical(oldWidget.samples, widget.samples) &&
        oldWidget.maxSpeed == widget.maxSpeed) {
      return;
    }
    final current = _interpolateSamples(
      _fromSamples,
      _targetSamples,
      _controller.value,
    );
    _fromSamples = current;
    _targetSamples = widget.samples;
    _fromMaxSpeed = _lerp(_fromMaxSpeed, _targetMaxSpeed, _controller.value);
    _targetMaxSpeed = widget.maxSpeed;
    _controller.forward(from: 0);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Text(
              widget.strings.speedTestMbps,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
            const Spacer(),
            _ChartLegendItem(
              color: widget.downloadColor,
              label: widget.strings.speedTestDownload,
            ),
            const SizedBox(width: 16),
            _ChartLegendItem(
              color: widget.uploadColor,
              label: widget.strings.speedTestUpload,
            ),
          ],
        ),
        const SizedBox(height: 6),
        Container(
          key: const Key('node-speedtest-chart'),
          height: widget.height,
          width: double.infinity,
          padding: const EdgeInsets.fromLTRB(4, 4, 4, 0),
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(AppTokens.radiusMd),
            border: Border.all(color: theme.colorScheme.outlineVariant),
          ),
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, _) => CustomPaint(
              painter: _DesktopSpeedTestChartPainter(
                samples: _interpolateSamples(
                  _fromSamples,
                  _targetSamples,
                  _controller.value,
                ),
                maxSpeed: _lerp(
                  _fromMaxSpeed,
                  _targetMaxSpeed,
                  _controller.value,
                ),
                duration: widget.duration,
                downloadColor: widget.downloadColor,
                uploadColor: widget.uploadColor,
                axisColor: widget.axisColor,
                gridColor: widget.gridColor,
              ),
            ),
          ),
        ),
      ],
    );
  }

  static double _lerp(double from, double to, double t) {
    return from + (to - from) * t;
  }

  static List<_SpeedTestPoint> _interpolateSamples(
    List<_SpeedTestPoint> from,
    List<_SpeedTestPoint> to,
    double t,
  ) {
    if (to.isEmpty) return const [];
    if (from.isEmpty) {
      from = [
        _SpeedTestPoint(
          elapsedMs: to.first.elapsedMs,
          downloadMbps: 0,
          uploadMbps: 0,
        ),
      ];
    }
    return [
      for (var index = 0; index < to.length; index++)
        _SpeedTestPoint(
          elapsedMs:
              (from[math.min(index, from.length - 1)].elapsedMs +
                      (to[index].elapsedMs -
                              from[math.min(index, from.length - 1)]
                                  .elapsedMs) *
                          t)
                  .round(),
          downloadMbps: _lerp(
            from[math.min(index, from.length - 1)].downloadMbps,
            to[index].downloadMbps,
            t,
          ),
          uploadMbps: _lerp(
            from[math.min(index, from.length - 1)].uploadMbps,
            to[index].uploadMbps,
            t,
          ),
        ),
    ];
  }
}

class _ChartLegendItem extends StatelessWidget {
  const _ChartLegendItem({required this.color, required this.label});

  final Color color;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 18,
          height: 3,
          decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(2),
          ),
        ),
        const SizedBox(width: 6),
        Text(
          label,
          style: TextStyle(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }
}

class _DesktopSpeedTestChartPainter extends CustomPainter {
  _DesktopSpeedTestChartPainter({
    required this.samples,
    required this.maxSpeed,
    required this.duration,
    required this.downloadColor,
    required this.uploadColor,
    required this.axisColor,
    required this.gridColor,
  });

  final List<_SpeedTestPoint> samples;
  final double maxSpeed;
  final Duration duration;
  final Color downloadColor;
  final Color uploadColor;
  final Color axisColor;
  final Color gridColor;

  @override
  void paint(Canvas canvas, Size size) {
    const left = 48.0;
    const right = 12.0;
    const top = 8.0;
    const bottom = 28.0;
    final chart = Rect.fromLTRB(
      left,
      top,
      math.max(left + 1, size.width - right),
      math.max(top + 1, size.height - bottom),
    );
    final safeMax = maxSpeed.isFinite && maxSpeed > 0 ? maxSpeed : 10.0;
    final gridPaint = Paint()
      ..color = gridColor.withValues(alpha: 0.48)
      ..strokeWidth = 1;
    final axisPaint = Paint()
      ..color = axisColor.withValues(alpha: 0.58)
      ..strokeWidth = 1.1;

    for (var index = 0; index <= 4; index++) {
      final fraction = index / 4;
      final y = chart.bottom - chart.height * fraction;
      canvas.drawLine(Offset(chart.left, y), Offset(chart.right, y), gridPaint);
      _drawText(
        canvas,
        _formatAxisSpeed(safeMax * fraction),
        Offset(0, y - 7),
        width: left - 8,
        align: TextAlign.right,
      );
    }
    canvas.drawLine(
      Offset(chart.left, chart.top),
      Offset(chart.left, chart.bottom),
      axisPaint,
    );
    canvas.drawLine(
      Offset(chart.left, chart.bottom),
      Offset(chart.right, chart.bottom),
      axisPaint,
    );

    final durationMs = math.max(1, duration.inMilliseconds);
    for (var index = 0; index <= 2; index++) {
      final fraction = index / 2;
      final x = chart.left + chart.width * fraction;
      final seconds = durationMs * fraction / 1000;
      _drawText(
        canvas,
        '${seconds.toStringAsFixed(seconds == seconds.roundToDouble() ? 0 : 1)}s',
        Offset(x - 24, chart.bottom + 7),
        width: 48,
        align: index == 0
            ? TextAlign.left
            : index == 2
            ? TextAlign.right
            : TextAlign.center,
      );
    }

    canvas.save();
    canvas.clipRect(chart);
    _drawSeries(
      canvas,
      chart,
      safeMax,
      durationMs,
      downloadColor,
      (sample) => sample.downloadMbps,
    );
    _drawSeries(
      canvas,
      chart,
      safeMax,
      durationMs,
      uploadColor,
      (sample) => sample.uploadMbps,
    );
    canvas.restore();
  }

  void _drawSeries(
    Canvas canvas,
    Rect chart,
    double safeMax,
    int durationMs,
    Color color,
    double Function(_SpeedTestPoint sample) value,
  ) {
    if (samples.isEmpty) return;
    final points = [
      for (final sample in samples)
        _DesktopPlotPoint(
          x: (sample.elapsedMs.clamp(0, durationMs) / durationMs).toDouble(),
          value: value(sample).clamp(0, safeMax).toDouble(),
        ),
    ];
    final tangents = _monotoneTangents(points);
    final path = Path();
    final first = points.first;
    path.moveTo(
      chart.left + first.x * chart.width,
      _screenY(chart, first.value, safeMax),
    );
    for (var index = 0; index < points.length - 1; index++) {
      final current = points[index];
      final next = points[index + 1];
      final dx = (next.x - current.x) * chart.width;
      final firstControlValue =
          current.value + tangents[index] * (next.x - current.x) / 3;
      final secondControlValue =
          next.value - tangents[index + 1] * (next.x - current.x) / 3;
      path.cubicTo(
        chart.left + current.x * chart.width + dx / 3,
        _screenY(chart, firstControlValue.clamp(0, safeMax), safeMax),
        chart.left + next.x * chart.width - dx / 3,
        _screenY(chart, secondControlValue.clamp(0, safeMax), safeMax),
        chart.left + next.x * chart.width,
        _screenY(chart, next.value, safeMax),
      );
    }
    final linePaint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.3
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    canvas.drawPath(path, linePaint);
  }

  double _screenY(Rect chart, double value, double safeMax) {
    return chart.bottom - chart.height * (value / safeMax);
  }

  List<double> _monotoneTangents(List<_DesktopPlotPoint> points) {
    if (points.length < 2) return List.filled(points.length, 0);
    final slopes = <double>[];
    for (var index = 0; index < points.length - 1; index++) {
      final dx = points[index + 1].x - points[index].x;
      slopes.add(
        dx <= 0 ? 0 : (points[index + 1].value - points[index].value) / dx,
      );
    }
    final tangents = List<double>.filled(points.length, 0);
    tangents[0] = _endpointTangent(
      slopes[0],
      slopes.length > 1 ? slopes[1] : slopes[0],
    );
    tangents[tangents.length - 1] = _endpointTangent(
      slopes.last,
      slopes.length > 1 ? slopes[slopes.length - 2] : slopes.last,
    );
    for (var index = 1; index < points.length - 1; index++) {
      final previous = slopes[index - 1];
      final next = slopes[index];
      if (previous == 0 || next == 0 || previous.sign != next.sign) {
        tangents[index] = 0;
      } else {
        tangents[index] = (previous + next) / 2;
        final limit = 3 * math.min(previous.abs(), next.abs());
        tangents[index] = tangents[index].clamp(-limit, limit).toDouble();
      }
    }
    return tangents;
  }

  double _endpointTangent(double slope, double adjacent) {
    if (slope == 0 || slope.sign != adjacent.sign) return 0;
    return slope;
  }

  void _drawText(
    Canvas canvas,
    String text,
    Offset offset, {
    required double width,
    required TextAlign align,
  }) {
    final painter = TextPainter(
      text: TextSpan(
        text: text,
        style: TextStyle(
          color: axisColor,
          fontSize: 10,
          fontWeight: FontWeight.w500,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
      textDirection: TextDirection.ltr,
      textAlign: align,
      maxLines: 1,
    )..layout(maxWidth: width);
    painter.paint(canvas, offset);
  }

  @override
  bool shouldRepaint(covariant _DesktopSpeedTestChartPainter oldDelegate) =>
      true;
}

class _DesktopPlotPoint {
  const _DesktopPlotPoint({required this.x, required this.value});

  final double x;
  final double value;
}

class _DesktopSpeedSummary extends StatelessWidget {
  const _DesktopSpeedSummary({
    required this.telemetry,
    required this.result,
    required this.fallbackRttMs,
    required this.strings,
    required this.downloadColor,
    required this.uploadColor,
  });

  final _SpeedTestTelemetry telemetry;
  final SpeedTestResult? result;
  final int? fallbackRttMs;
  final AppStrings strings;
  final Color downloadColor;
  final Color uploadColor;

  @override
  Widget build(BuildContext context) {
    final download = result?.downloadMbps ?? telemetry.averageDownloadMbps;
    final upload = result?.uploadMbps ?? telemetry.averageUploadMbps;
    final downloadBytes = result?.downloadBytes ?? telemetry.downloadBytes;
    final uploadBytes = result?.uploadBytes ?? telemetry.uploadBytes;
    final elapsedMs = result?.durationMs ?? telemetry.elapsedMs;
    final rtt = telemetry.rttMs ?? fallbackRttMs;
    final theme = Theme.of(context);
    return Container(
      key: const Key('node-speedtest-summary'),
      height: 72,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Expanded(
            child: _DesktopSummaryMetric(
              label: strings.speedTestLocalRtt,
              value: formatLatency(rtt),
            ),
          ),
          _DesktopSummaryDivider(),
          Expanded(
            child: _DesktopSummaryMetric(
              label: strings.speedTestAverageDownload,
              value: '${_formatSpeedNumber(download)} ${strings.speedTestMbps}',
              valueColor: downloadColor,
            ),
          ),
          _DesktopSummaryDivider(),
          Expanded(
            child: _DesktopSummaryMetric(
              label: strings.speedTestAverageUpload,
              value: '${_formatSpeedNumber(upload)} ${strings.speedTestMbps}',
              valueColor: uploadColor,
            ),
          ),
          _DesktopSummaryDivider(),
          Expanded(
            flex: 2,
            child: _DesktopSummaryMetric(
              label: strings.speedTestTransferred,
              value:
                  '${formatBytes(downloadBytes)} / ${formatBytes(uploadBytes)}',
            ),
          ),
          _DesktopSummaryDivider(),
          Expanded(
            child: _DesktopSummaryMetric(
              label: strings.speedTestElapsed,
              value: '${(elapsedMs / 1000).toStringAsFixed(1)} s',
            ),
          ),
        ],
      ),
    );
  }
}

class _DesktopSummaryDivider extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      width: 1,
      height: 38,
      color: Theme.of(context).colorScheme.outlineVariant,
    );
  }
}

class _DesktopSummaryMetric extends StatelessWidget {
  const _DesktopSummaryMetric({
    required this.label,
    required this.value,
    this.valueColor,
  });

  final String label;
  final String value;
  final Color? valueColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 10),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 11,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 3),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: valueColor ?? theme.colorScheme.onSurface,
              fontSize: 13,
              fontWeight: FontWeight.w700,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileSpeedTestLinkInfo extends StatelessWidget {
  const _MobileSpeedTestLinkInfo({
    required this.peer,
    required this.path,
    required this.pathColor,
    required this.strings,
  });

  final PeerSnapshot peer;
  final String path;
  final Color pathColor;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      key: const Key('node-speedtest-link-info'),
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(
          alpha: 0.28,
        ),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Expanded(
            child: _MobileSpeedTestLinkValue(
              icon: Icons.computer_outlined,
              label: strings.virtualIp,
              value: dash(peer.virtualIp),
            ),
          ),
          Container(
            width: 1,
            height: 34,
            margin: const EdgeInsets.symmetric(horizontal: 10),
            color: theme.colorScheme.outlineVariant,
          ),
          Expanded(
            child: _MobileSpeedTestLinkValue(
              icon: Icons.route_outlined,
              label: strings.path,
              value: path,
              valueColor: pathColor,
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileSpeedTestLinkValue extends StatelessWidget {
  const _MobileSpeedTestLinkValue({
    required this.icon,
    required this.label,
    required this.value,
    this.valueColor,
  });

  final IconData icon;
  final String label;
  final String value;
  final Color? valueColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      children: [
        Icon(icon, size: 18, color: theme.colorScheme.onSurfaceVariant),
        const SizedBox(width: 8),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                value,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: valueColor ?? theme.colorScheme.onSurface,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _DesktopSpeedNotice extends StatelessWidget {
  const _DesktopSpeedNotice({
    required this.icon,
    required this.message,
    required this.color,
  });

  final IconData icon;
  final String message;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 17, color: color),
        const SizedBox(width: 7),
        Expanded(
          child: Text(
            message,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(color: color, fontSize: 12, height: 1.25),
          ),
        ),
      ],
    );
  }
}

String _formatSpeedNumber(double value) {
  if (!value.isFinite || value <= 0) return '0.0';
  if (value >= 1000) return value.toStringAsFixed(0);
  return value >= 10 ? value.toStringAsFixed(1) : value.toStringAsFixed(2);
}

class _SpeedTestChart extends StatelessWidget {
  const _SpeedTestChart({
    required this.samples,
    required this.duration,
    required this.downloadColor,
    required this.uploadColor,
    required this.strings,
  });

  final List<_SpeedTestPoint> samples;
  final Duration duration;
  final Color downloadColor;
  final Color uploadColor;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final latest = samples.last;
    final colorScheme = Theme.of(context).colorScheme;
    return LayoutBuilder(
      builder: (context, constraints) {
        final chartHeight = constraints.maxWidth < 320 ? 132.0 : 150.0;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: _SpeedTestLegend(
                    color: downloadColor,
                    label: strings.speedTestDownload,
                    value: latest.downloadMbps,
                  ),
                ),
                const SizedBox(width: AppTokens.space12),
                Expanded(
                  child: _SpeedTestLegend(
                    color: uploadColor,
                    label: strings.speedTestUpload,
                    value: latest.uploadMbps,
                  ),
                ),
              ],
            ),
            const SizedBox(height: AppTokens.space8),
            Container(
              key: const Key('node-speedtest-chart'),
              // Keep the plotting area fixed so the y-axis never makes the
              // dialog jump as the measured speed changes. This compact height
              // also leaves room for the result metrics on phone-sized dialogs.
              height: chartHeight,
              width: double.infinity,
              padding: const EdgeInsets.fromLTRB(4, 4, 4, 0),
              decoration: BoxDecoration(
                color: colorScheme.surfaceContainerHighest.withValues(
                  alpha: 0.32,
                ),
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                border: Border.all(color: colorScheme.outlineVariant),
              ),
              child: CustomPaint(
                painter: _SpeedTestChartPainter(
                  samples: samples,
                  duration: duration,
                  downloadColor: downloadColor,
                  uploadColor: uploadColor,
                  gridColor: colorScheme.outlineVariant,
                  labelColor: colorScheme.onSurfaceVariant,
                ),
              ),
            ),
          ],
        );
      },
    );
  }
}

class _SpeedTestLegend extends StatelessWidget {
  const _SpeedTestLegend({
    required this.color,
    required this.label,
    required this.value,
  });

  final Color color;
  final String label;
  final double value;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 6),
        Flexible(
          child: Text(
            '$label ${_formatSpeed(value)}',
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: colorScheme.onSurface,
              fontSize: 12,
              fontWeight: FontWeight.w700,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
      ],
    );
  }
}

class _SpeedTestChartPainter extends CustomPainter {
  _SpeedTestChartPainter({
    required this.samples,
    required this.duration,
    required this.downloadColor,
    required this.uploadColor,
    required this.gridColor,
    required this.labelColor,
  });

  final List<_SpeedTestPoint> samples;
  final Duration duration;
  final Color downloadColor;
  final Color uploadColor;
  final Color gridColor;
  final Color labelColor;

  @override
  void paint(Canvas canvas, Size size) {
    const left = 42.0;
    const right = 8.0;
    const top = 8.0;
    const bottom = 26.0;
    final chart = Rect.fromLTRB(
      left,
      top,
      math.max(left + 1, size.width - right),
      math.max(top + 1, size.height - bottom),
    );
    final maxSpeed = _niceCeiling(_maxSampleSpeed());
    final gridPaint = Paint()
      ..color = gridColor.withValues(alpha: 0.72)
      ..strokeWidth = 1;
    final axisPaint = Paint()
      ..color = gridColor
      ..strokeWidth = 1.2;

    for (var index = 0; index <= 4; index++) {
      final fraction = index / 4;
      final y = chart.bottom - chart.height * fraction;
      canvas.drawLine(Offset(chart.left, y), Offset(chart.right, y), gridPaint);
      _drawText(
        canvas,
        _formatAxisSpeed(maxSpeed * fraction),
        Offset(0, y - 7),
        width: left - 6,
        align: TextAlign.right,
      );
    }
    canvas.drawLine(
      Offset(chart.left, chart.top),
      Offset(chart.left, chart.bottom),
      axisPaint,
    );
    canvas.drawLine(
      Offset(chart.left, chart.bottom),
      Offset(chart.right, chart.bottom),
      axisPaint,
    );

    final durationMs = math.max(1, duration.inMilliseconds);
    for (var index = 0; index <= 2; index++) {
      final fraction = index / 2;
      final x = chart.left + chart.width * fraction;
      final seconds = durationMs * fraction / 1000;
      _drawText(
        canvas,
        '${seconds.toStringAsFixed(seconds == seconds.roundToDouble() ? 0 : 1)}s',
        Offset(x - 22, chart.bottom + 6),
        width: 44,
        align: index == 0
            ? TextAlign.left
            : index == 2
            ? TextAlign.right
            : TextAlign.center,
      );
    }

    canvas.save();
    canvas.clipRect(chart);
    _drawSeries(
      canvas,
      chart,
      maxSpeed,
      durationMs,
      downloadColor,
      (sample) => sample.downloadMbps,
    );
    _drawSeries(
      canvas,
      chart,
      maxSpeed,
      durationMs,
      uploadColor,
      (sample) => sample.uploadMbps,
    );
    canvas.restore();
  }

  void _drawSeries(
    Canvas canvas,
    Rect chart,
    double maxSpeed,
    int durationMs,
    Color color,
    double Function(_SpeedTestPoint sample) value,
  ) {
    if (samples.isEmpty) return;
    final points = [
      for (final sample in samples)
        _DesktopPlotPoint(
          x: (sample.elapsedMs.clamp(0, durationMs) / durationMs).toDouble(),
          value: value(sample).clamp(0, maxSpeed).toDouble(),
        ),
    ];
    final tangents = _monotoneTangents(points);
    final path = Path();
    final first = points.first;
    path.moveTo(
      chart.left + first.x * chart.width,
      chart.bottom - chart.height * (first.value / maxSpeed),
    );
    for (var index = 0; index < points.length - 1; index++) {
      final current = points[index];
      final next = points[index + 1];
      final dx = (next.x - current.x) * chart.width;
      final firstControlValue =
          current.value + tangents[index] * (next.x - current.x) / 3;
      final secondControlValue =
          next.value - tangents[index + 1] * (next.x - current.x) / 3;
      path.cubicTo(
        chart.left + current.x * chart.width + dx / 3,
        chart.bottom -
            chart.height * (firstControlValue.clamp(0, maxSpeed) / maxSpeed),
        chart.left + next.x * chart.width - dx / 3,
        chart.bottom -
            chart.height * (secondControlValue.clamp(0, maxSpeed) / maxSpeed),
        chart.left + next.x * chart.width,
        chart.bottom - chart.height * (next.value / maxSpeed),
      );
    }
    final linePaint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.3
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    canvas.drawPath(path, linePaint);
  }

  List<double> _monotoneTangents(List<_DesktopPlotPoint> points) {
    if (points.length < 2) return List.filled(points.length, 0);
    final slopes = <double>[];
    for (var index = 0; index < points.length - 1; index++) {
      final dx = points[index + 1].x - points[index].x;
      slopes.add(
        dx <= 0 ? 0 : (points[index + 1].value - points[index].value) / dx,
      );
    }
    final tangents = List<double>.filled(points.length, 0);
    tangents[0] = _endpointTangent(
      slopes[0],
      slopes.length > 1 ? slopes[1] : slopes[0],
    );
    tangents[tangents.length - 1] = _endpointTangent(
      slopes.last,
      slopes.length > 1 ? slopes[slopes.length - 2] : slopes.last,
    );
    for (var index = 1; index < points.length - 1; index++) {
      final previous = slopes[index - 1];
      final next = slopes[index];
      if (previous == 0 || next == 0 || previous.sign != next.sign) {
        tangents[index] = 0;
      } else {
        tangents[index] = (previous + next) / 2;
        final limit = 3 * math.min(previous.abs(), next.abs());
        tangents[index] = tangents[index].clamp(-limit, limit).toDouble();
      }
    }
    return tangents;
  }

  double _endpointTangent(double slope, double adjacent) {
    if (slope == 0 || slope.sign != adjacent.sign) return 0;
    return slope;
  }

  double _maxSampleSpeed() {
    var maximum = 0.0;
    for (final sample in samples) {
      maximum = math.max(maximum, sample.downloadMbps);
      maximum = math.max(maximum, sample.uploadMbps);
    }
    return maximum;
  }

  double _niceCeiling(double value) {
    if (value <= 0 || !value.isFinite) return 1;
    final magnitude = math
        .pow(10, (math.log(value) / math.ln10).floor())
        .toDouble();
    final normalized = value / magnitude;
    final step = normalized <= 1
        ? 1
        : normalized <= 2
        ? 2
        : normalized <= 5
        ? 5
        : 10;
    return step * magnitude;
  }

  void _drawText(
    Canvas canvas,
    String text,
    Offset offset, {
    required double width,
    required TextAlign align,
  }) {
    final painter = TextPainter(
      text: TextSpan(
        text: text,
        style: TextStyle(
          color: labelColor,
          fontSize: 9,
          fontWeight: FontWeight.w600,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
      textDirection: TextDirection.ltr,
      textAlign: align,
      maxLines: 1,
    )..layout(maxWidth: width);
    painter.paint(canvas, offset);
  }

  @override
  bool shouldRepaint(covariant _SpeedTestChartPainter oldDelegate) => true;
}

String _formatSpeed(double value) {
  if (!value.isFinite || value <= 0) return '0 Mbps';
  if (value >= 1000) return '${value.toStringAsFixed(0)} Mbps';
  if (value >= 10) return '${value.toStringAsFixed(1)} Mbps';
  return '${value.toStringAsFixed(2)} Mbps';
}

String _formatAxisSpeed(double value) {
  if (value >= 100) return value.toStringAsFixed(0);
  if (value >= 10) return value.toStringAsFixed(1);
  if (value >= 1) return value.toStringAsFixed(1);
  return value.toStringAsFixed(2);
}

class _SpeedTestMessage extends StatelessWidget {
  const _SpeedTestMessage({
    required this.icon,
    required this.message,
    required this.color,
  });

  final IconData icon;
  final String message;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 19, color: color),
        const SizedBox(width: 9),
        Expanded(
          child: Text(
            message,
            style: TextStyle(color: color, fontSize: 13, height: 1.35),
          ),
        ),
      ],
    );
  }
}

class _SpeedTestResult extends StatelessWidget {
  const _SpeedTestResult({
    required this.result,
    required this.latencyMs,
    required this.strings,
  });

  final SpeedTestResult result;
  final int? latencyMs;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 400) {
          return Column(
            children: [
              Row(
                children: [
                  Expanded(
                    child: _MobileSpeedTestMetric(
                      label: strings.latency,
                      value: formatLatency(latencyMs),
                    ),
                  ),
                  const SizedBox(width: AppTokens.space8),
                  Expanded(
                    child: _MobileSpeedTestMetric(
                      label: strings.speedTestDownload,
                      value: '${result.downloadMbps.toStringAsFixed(1)} Mbps',
                    ),
                  ),
                ],
              ),
              const SizedBox(height: AppTokens.space8),
              Row(
                children: [
                  Expanded(
                    child: _MobileSpeedTestMetric(
                      label: strings.speedTestUpload,
                      value: '${result.uploadMbps.toStringAsFixed(1)} Mbps',
                    ),
                  ),
                  const SizedBox(width: AppTokens.space8),
                  Expanded(
                    child: _MobileSpeedTestMetric(
                      label: strings.speedTestTransferred,
                      value:
                          '${formatBytes(result.downloadBytes)} / ${formatBytes(result.uploadBytes)}',
                      detail:
                          '${strings.speedTestElapsed}: ${formatDuration(Duration(milliseconds: result.durationMs))}',
                    ),
                  ),
                ],
              ),
            ],
          );
        }
        return Wrap(
          spacing: 18,
          runSpacing: 2,
          children: [
            MetricTile(
              label: strings.latency,
              value: formatLatency(latencyMs),
              minWidth: 100,
              maxWidth: 130,
            ),
            MetricTile(
              label: strings.speedTestDownload,
              value: '${result.downloadMbps.toStringAsFixed(1)} Mbps',
              minWidth: 130,
              maxWidth: 180,
            ),
            MetricTile(
              label: strings.speedTestUpload,
              value: '${result.uploadMbps.toStringAsFixed(1)} Mbps',
              minWidth: 130,
              maxWidth: 180,
            ),
            MetricTile(
              label: strings.speedTestTransferred,
              value:
                  '${formatBytes(result.downloadBytes)} / ${formatBytes(result.uploadBytes)}',
              detail:
                  '${strings.speedTestElapsed}: ${formatDuration(Duration(milliseconds: result.durationMs))}',
              minWidth: 200,
              maxWidth: 260,
            ),
          ],
        );
      },
    );
  }
}

class _MobileSpeedTestMetric extends StatelessWidget {
  const _MobileSpeedTestMetric({
    required this.label,
    required this.value,
    this.detail,
  });

  final String label;
  final String value;
  final String? detail;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(right: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: colorScheme.onSurfaceVariant,
              fontSize: 11,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 3),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: colorScheme.onSurface,
              fontSize: 13,
              fontWeight: FontWeight.w700,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
          if (detail != null) ...[
            const SizedBox(height: 2),
            Text(
              detail!,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: colorScheme.onSurfaceVariant,
                fontSize: 10,
                fontWeight: FontWeight.w500,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
