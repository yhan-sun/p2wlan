part of '../dashboard_page.dart';

/// Lightweight static connection map: this device in the center, up to 6 peers
/// split evenly on both sides, connected by straight lines. Rendered only on
/// expanded (desktop-width) layouts; no canvas animations or fake data.
class _ConnectionMap extends StatelessWidget {
  const _ConnectionMap({required this.peers});

  static const rowHeight = 80.0;
  static const centerColumnWidth = 120.0;

  /// Exposed so widget tests can assert expanded layouts render the map and
  /// compact layouts do not.
  static const widgetKey = Key('dashboard-connection-map');

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final leftCount = (peers.length + 1) ~/ 2;
    final rightCount = peers.length - leftCount;
    final rows = leftCount > rightCount ? leftCount : rightCount;
    if (rows < 1) return const SizedBox.shrink();

    final lineColor = theme.brightness == Brightness.dark
        ? AppTokens.colorDarkBorder
        : AppTokens.colorBorderSubtle;

    Widget cellAt(int index, bool left) {
      final peer = left
          ? (index < leftCount ? peers[index] : null)
          : (index < rightCount ? peers[leftCount + index] : null);
      if (peer == null) return const SizedBox(height: rowHeight);
      return SizedBox(
        height: rowHeight,
        child: Align(
          alignment: left ? Alignment.centerRight : Alignment.centerLeft,
          child: _MapPeerCell(peer: peer),
        ),
      );
    }

    return Column(
      key: widgetKey,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          height: rows * rowHeight,
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(
                child: Column(
                  children: [
                    for (var index = 0; index < rows; index++)
                      cellAt(index, true),
                  ],
                ),
              ),
              SizedBox(
                width: centerColumnWidth,
                child: CustomPaint(
                  painter: _ConnectionMapPainter(
                    rows: rows,
                    rowHeight: rowHeight,
                    lineColor: lineColor,
                  ),
                  child: Center(child: _MapLocalCell(label: strings.localNode)),
                ),
              ),
              Expanded(
                child: Column(
                  children: [
                    for (var index = 0; index < rows; index++)
                      cellAt(index, false),
                  ],
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _MapPeerCell extends StatelessWidget {
  const _MapPeerCell({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = _peerStatusColor(context, peer);
    return ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 260),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(color: color, shape: BoxShape.circle),
              ),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  peer.displayName,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 12.5,
                    fontWeight: FontWeight.w600,
                    height: 1.2,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 3),
          Padding(
            padding: const EdgeInsets.only(left: 14),
            child: Text(
              dash(peer.virtualIp),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 11,
                height: 1.2,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _MapLocalCell extends StatelessWidget {
  const _MapLocalCell({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final accent = isDark ? AppTokens.colorDarkAccent : AppTokens.colorAccent;
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest,
            shape: BoxShape.circle,
            border: Border.all(color: accent, width: 1.5),
          ),
          child: Icon(Icons.hub_rounded, color: accent, size: 22),
        ),
        const SizedBox(height: 5),
        Text(
          label,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 12,
            fontWeight: FontWeight.w700,
            height: 1.2,
          ),
        ),
      ],
    );
  }
}

class _ConnectionMapPainter extends CustomPainter {
  const _ConnectionMapPainter({
    required this.rows,
    required this.rowHeight,
    required this.lineColor,
  });

  final int rows;
  final double rowHeight;
  final Color lineColor;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = lineColor
      ..strokeWidth = 1.2
      ..strokeCap = StrokeCap.round;
    final midX = size.width / 2;
    final localY = size.height / 2;

    canvas.drawLine(Offset(midX, 0), Offset(midX, size.height), paint);
    canvas.drawLine(Offset(0, localY), Offset(size.width, localY), paint);
    for (var index = 0; index < rows; index++) {
      final y = index * rowHeight + rowHeight / 2;
      if ((y - localY).abs() < 0.5) continue;
      canvas.drawLine(Offset(0, y), Offset(midX, y), paint);
      canvas.drawLine(Offset(midX, y), Offset(size.width, y), paint);
    }
  }

  @override
  bool shouldRepaint(_ConnectionMapPainter oldDelegate) {
    return oldDelegate.rows != rows ||
        oldDelegate.rowHeight != rowHeight ||
        oldDelegate.lineColor != lineColor;
  }
}
