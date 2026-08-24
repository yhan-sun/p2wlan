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

  Timer? _progressTimer;
  final _samples = <_SpeedTestPoint>[];

  @override
  void initState() {
    super.initState();
    widget.statusStore.addListener(_handleStatusChanged);
    _syncProgressTimer();
  }

  @override
  void dispose() {
    _progressTimer?.cancel();
    widget.statusStore.removeListener(_handleStatusChanged);
    super.dispose();
  }

  void _handleStatusChanged() {
    if (_runningForPeer) {
      _recordLiveSample();
    } else if (widget.statusStore.speedTestResultFor(widget.peer) != null) {
      _recordResultSample();
    }
    _syncProgressTimer();
    if (mounted) setState(() {});
  }

  void _syncProgressTimer() {
    if (_runningForPeer) {
      _progressTimer ??= Timer.periodic(const Duration(milliseconds: 100), (_) {
        if (mounted) setState(() {});
      });
      return;
    }
    _progressTimer?.cancel();
    _progressTimer = null;
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
    if (mounted) setState(() {});
    unawaited(widget.statusStore.runSpeedTest(widget.peer));
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
    final maxWidth = dialogSize.width > 560 ? 520.0 : dialogSize.width - 32;

    return Dialog(
      key: const Key('node-speedtest-dialog'),
      insetPadding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space16,
        vertical: AppTokens.space24,
      ),
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: maxWidth, maxHeight: 560),
        child: Padding(
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
                  Text(
                    _rowPathLabel(strings, widget.peer),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: colorScheme.onSurfaceVariant,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  IconButton(
                    tooltip: strings.close,
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close_rounded, size: 20),
                  ),
                ],
              ),
              const SizedBox(height: AppTokens.space16),
              _SpeedTestDetailRow(
                label: strings.virtualIp,
                value: dash(widget.peer.virtualIp),
              ),
              _SpeedTestDetailRow(
                label: strings.path,
                value: _connectionLabel(strings, widget.peer),
              ),
              if (_samples.isNotEmpty) ...[
                const SizedBox(height: AppTokens.space14),
                _SpeedTestChart(
                  samples: List.unmodifiable(_samples),
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
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: Text(strings.close),
                  ),
                  const SizedBox(width: AppTokens.space8),
                  FilledButton.icon(
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
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
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
          // Keep the plotting area fixed so the y-axis never makes the dialog
          // jump as the measured speed changes. This compact height also
          // leaves room for the result metrics on phone-sized dialogs.
          height: 150,
          width: double.infinity,
          padding: const EdgeInsets.fromLTRB(4, 4, 4, 0),
          decoration: BoxDecoration(
            color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.32),
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
        Offset(
          chart.left +
              chart.width *
                  (sample.elapsedMs.clamp(0, durationMs) / durationMs),
          chart.bottom -
              chart.height * (value(sample).clamp(0, maxSpeed) / maxSpeed),
        ),
    ];
    final path = Path()..moveTo(points.first.dx, points.first.dy);
    for (var index = 1; index < points.length; index++) {
      final previous = points[index - 1];
      final current = points[index];
      final middleX = (previous.dx + current.dx) / 2;
      path.quadraticBezierTo(middleX, previous.dy, current.dx, current.dy);
    }
    final linePaint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.3
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    canvas.drawPath(path, linePaint);
    final pointPaint = Paint()..color = color;
    for (final point in points) {
      canvas.drawCircle(point, 2.7, pointPaint);
    }
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

class _SpeedTestDetailRow extends StatelessWidget {
  const _SpeedTestDetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(
            width: 82,
            child: Text(
              label,
              style: TextStyle(
                color: colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: colorScheme.onSurface,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
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
  }
}
