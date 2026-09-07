part of '../nodes_page.dart';

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

  final List<SpeedTestPoint> samples;
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
  List<SpeedTestPoint> _fromSamples = const [];
  List<SpeedTestPoint> _targetSamples = const [];
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

  static List<SpeedTestPoint> _interpolateSamples(
    List<SpeedTestPoint> from,
    List<SpeedTestPoint> to,
    double t,
  ) {
    if (to.isEmpty) return const [];
    if (from.isEmpty) {
      from = [
        SpeedTestPoint(
          elapsedMs: to.first.elapsedMs,
          downloadMbps: 0,
          uploadMbps: 0,
        ),
      ];
    }
    return [
      for (var index = 0; index < to.length; index++)
        SpeedTestPoint(
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

  final List<SpeedTestPoint> samples;
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
    double Function(SpeedTestPoint sample) value,
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
