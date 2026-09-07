part of '../nodes_page.dart';

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

class _DesktopSpeedSummary extends StatelessWidget {
  const _DesktopSpeedSummary({
    required this.telemetry,
    required this.result,
    required this.fallbackRttMs,
    required this.strings,
    required this.downloadColor,
    required this.uploadColor,
  });

  final SpeedTestTelemetry telemetry;
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
