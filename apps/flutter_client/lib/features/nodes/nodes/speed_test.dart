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
  int? _desktopSampleRunId;
  int? _observedRunId;
  var _disposed = false;
  var _desktopDialog = false;
  var _wasRunning = false;
  SpeedTestResult? _observedResult;
  String? _observedError;
  String? _observedPath;
  bool? _observedEligibility;
  final _samples = <SpeedTestPoint>[];
  late final SpeedTestTelemetry _desktopTelemetry;

  @override
  void initState() {
    super.initState();
    _desktopTelemetry = SpeedTestTelemetry(
      maxSamples:
          (_testDuration.inMilliseconds / _desktopSampleInterval.inMilliseconds)
              .ceil(),
    );
    widget.statusStore.addListener(_handleStatusChanged);
    if (_runningForPeer) _resetDesktopTelemetry();
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
    _disposed = true;
    _progressTimer?.cancel();
    _desktopSampleTimer?.cancel();
    widget.statusStore.removeListener(_handleStatusChanged);
    if (_runningForPeer) {
      final store = widget.statusStore;
      final runId = store.speedTestRunId;
      scheduleMicrotask(() {
        if (store.speedTestRunning && store.speedTestRunId == runId) {
          store.cancelSpeedTest();
        }
      });
    }
    _desktopTelemetry.dispose();
    super.dispose();
  }

  void _handleStatusChanged() {
    if (_disposed || !mounted) return;
    final running = _runningForPeer;
    final runChanged =
        running && _observedRunId != widget.statusStore.speedTestRunId;
    if (runChanged) _resetDesktopTelemetry();
    final result = widget.statusStore.speedTestResultFor(widget.peer);
    final error = widget.statusStore.speedTestErrorFor(widget.peer);
    if (running) {
      _recordLiveSample();
    } else if (result != null) {
      _recordResultSample();
      if (result != _desktopTelemetry.result) {
        _desktopTelemetry.recordResult(
          result,
          _currentPeer.latencyMs,
          runId: widget.statusStore.speedTestRunId,
        );
      }
    }
    _syncSamplingTimers();
    if (!mounted) return;
    final eligible = _canRunCurrentPeer;
    final path = _currentPeer.path;
    final changed =
        _observedPath != path ||
        _observedEligibility != eligible ||
        runChanged ||
        _wasRunning != running ||
        !identical(_observedResult, result) ||
        _observedError != error;
    if (changed) {
      setState(() {});
    }
    _observedPath = path;
    _observedEligibility = eligible;
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
    if (_disposed || !_desktopDialog || !_runningForPeer) return;
    final runId = widget.statusStore.speedTestRunId;
    if (_desktopSampleRunId == runId) return;
    _desktopSampleRunId = runId;
    try {
      final peer = await widget.statusStore.fetchSpeedTestPeerSnapshot(
        widget.peer,
      );
      if (_disposed ||
          !mounted ||
          !_runningForPeer ||
          runId != widget.statusStore.speedTestRunId) {
        return;
      }
      final elapsed = widget.statusStore.speedTestElapsed;
      if (peer != null) {
        _desktopTelemetry.recordPeer(peer, elapsed, runId: runId);
      } else {
        _desktopTelemetry.tick(elapsed, runId: runId);
      }
    } finally {
      if (_desktopSampleRunId == runId) _desktopSampleRunId = null;
    }
  }

  PeerSnapshot? get _latestPeer {
    for (final peer in widget.statusStore.snapshot?.peers ?? <PeerSnapshot>[]) {
      if (peer.nodeId == widget.peer.nodeId) return peer;
    }
    return null;
  }

  PeerSnapshot get _currentPeer => _latestPeer ?? widget.peer;

  bool get _canRunCurrentPeer {
    final peer = _latestPeer;
    return peer != null &&
        widget.statusStore.healthReachable &&
        !widget.statusStore.snapshotStale &&
        _canRunSpeedTest(peer);
  }

  void _resetDesktopTelemetry() {
    _observedRunId = widget.statusStore.speedTestRunId;
    _samples.clear();
    _desktopTelemetry.reset(runId: _observedRunId!, peer: _currentPeer);
  }

  bool get _runningForPeer =>
      widget.statusStore.speedTestRunning &&
      widget.statusStore.speedTestMatches(widget.peer);

  bool get _runningElsewhere =>
      widget.statusStore.speedTestRunning && !_runningForPeer;

  void _run() {
    if (!_canRunCurrentPeer ||
        widget.statusStore.speedTestRunning ||
        widget.statusStore.snapshotStale) {
      return;
    }
    unawaited(widget.statusStore.runSpeedTest(_currentPeer));
    _syncSamplingTimers();
  }

  void _recordLiveSample() {
    final elapsedMs = widget.statusStore.speedTestElapsed.inMilliseconds;
    final rate = widget.statusStore.snapshotStale
        ? null
        : widget.statusStore.peerDirectionalTransferRates[widget.peer.nodeId];
    _appendSample(
      SpeedTestPoint(
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
      SpeedTestPoint(
        elapsedMs: result.durationMs.clamp(0, _testDuration.inMilliseconds),
        downloadMbps: result.downloadMbps,
        uploadMbps: result.uploadMbps,
      ),
    );
  }

  void _appendSample(SpeedTestPoint sample) {
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
    final eligible = _canRunCurrentPeer;
    final elapsed = _runningForPeer
        ? widget.statusStore.speedTestElapsed
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
    final List<SpeedTestPoint> chartSamples = _samples.isEmpty
        ? const <SpeedTestPoint>[
            SpeedTestPoint(elapsedMs: 0, downloadMbps: 0, uploadMbps: 0),
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
                  message: _speedTestUnavailableMessage(strings),
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
    final eligible = _canRunCurrentPeer;
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
                    message: _speedTestUnavailableMessage(strings),
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

class SpeedTestPoint {
  const SpeedTestPoint({
    required this.elapsedMs,
    required this.downloadMbps,
    required this.uploadMbps,
  });

  final int elapsedMs;
  final double downloadMbps;
  final double uploadMbps;
}

String _formatSpeedNumber(double value) {
  if (!value.isFinite || value <= 0) return '0.0';
  if (value >= 1000) return value.toStringAsFixed(0);
  return value >= 10 ? value.toStringAsFixed(1) : value.toStringAsFixed(2);
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
