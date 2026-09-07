part of '../nodes_page.dart';

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

class _SpeedTestChart extends StatelessWidget {
  const _SpeedTestChart({
    required this.samples,
    required this.duration,
    required this.downloadColor,
    required this.uploadColor,
    required this.strings,
  });

  final List<SpeedTestPoint> samples;
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

  final List<SpeedTestPoint> samples;
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
    double Function(SpeedTestPoint sample) value,
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
