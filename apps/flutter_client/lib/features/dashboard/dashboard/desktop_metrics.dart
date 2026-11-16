part of '../dashboard_page.dart';

class _DesktopLiveMetrics extends StatelessWidget {
  const _DesktopLiveMetrics({
    required this.counts,
    required this.peers,
    required this.complete,
    required this.rate,
    this.scopePicker,
  });

  final _PeerCounts counts;
  final List<NetworkPeerSnapshot> peers;
  final bool complete;
  final PeerTransferRate? rate;
  final Widget? scopePicker;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final latency = [for (final item in peers) ?item.peer.latencyMs]..sort();
    final middle = latency.length ~/ 2;
    final rtt = latency.isEmpty
        ? null
        : (latency[(latency.length - 1) ~/ 2] + latency[middle]) / 2;
    final measured = rate;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ConstrainedBox(
          constraints: BoxConstraints(
            minHeight: MediaQuery.sizeOf(context).width >= 900 ? 32 : 0,
          ),
          child: Align(
            alignment: AlignmentDirectional.centerStart,
            child: SizedBox(
              width: double.infinity,
              child: Wrap(
                alignment: WrapAlignment.spaceBetween,
                crossAxisAlignment: WrapCrossAlignment.center,
                spacing: AppTokens.space12,
                runSpacing: AppTokens.space2,
                children: [
                  Semantics(
                    header: true,
                    child: Text(
                      strings.isZh ? '实时指标' : 'Live metrics',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                  ),
                  ?scopePicker,
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: AppTokens.space8),
        LayoutBuilder(
          builder: (context, constraints) {
            const gap = AppTokens.space12;
            final scale = MediaQuery.textScalerOf(context).scale(13) / 13;
            final width = constraints.maxWidth;
            final compact = width / scale < 720;
            final columns = switch (width / scale) {
              >= 520 => 5,
              >= 320 => 3,
              >= 200 => 2,
              _ => 1,
            };
            final cardWidth = (width - gap * (columns - 1)) / columns;
            final fields = [
              _DesktopMetric(
                key: const Key('home-live-online'),
                icon: 'users',
                label: strings.isZh ? '在线设备' : 'Online devices',
                reading: _countLabel(counts.online),
                unit: strings.isZh ? '台' : '',
                detail: strings.isZh ? '当前范围内在线' : 'In the current scope',
                compact: compact,
              ),
              _DesktopMetric(
                key: const Key('home-live-direct'),
                icon: 'link',
                label: strings.isZh ? 'P2P 直连' : 'P2P direct',
                reading: _countLabel(counts.direct),
                unit: strings.isZh ? '台' : '',
                detail: strings.isZh ? '设备间直接通信' : 'Peer-to-peer path',
                color: counts.direct > 0 ? colors.direct : null,
                compact: compact,
              ),
              _DesktopMetric(
                key: const Key('home-live-relay'),
                icon: 'layers',
                label: strings.isZh ? 'Relay 中继' : 'Relay',
                reading: !complete && counts.relay == 0
                    ? '—'
                    : _countLabel(counts.relay),
                unit: strings.isZh ? '台' : '',
                detail: switch ((counts.relay, complete)) {
                  (> 0, _) => strings.isZh ? '通过中继连接' : 'Using a relay path',
                  (0, true) => strings.isZh ? '当前无中继连接' : 'No relay paths',
                  _ => strings.unavailable,
                },
                color: counts.relay > 0 ? colors.relay : null,
                compact: compact,
              ),
              _DesktopMetric(
                key: const Key('home-live-rate'),
                icon: 'activity',
                label: strings.isZh ? '实时流量' : 'Live traffic',
                reading: formatTransferRate(
                  measured == null
                      ? null
                      : measured.uploadBytesPerSecond +
                            measured.downloadBytesPerSecond,
                ),
                detail: strings.isZh ? '暂无速率样本' : 'Awaiting rate samples',
                tooltip: strings.isZh ? '当前范围内已采样的上传与下载合计速率。' : 'Combined sampled upload and download rate for the current scope.',
                compact: compact,
                extra: measured == null
                    ? null
                    : _DesktopTrafficSplit(rate: measured, compact: compact),
              ),
              _DesktopMetric(
                key: const Key('home-live-rtt'),
                icon: 'clock',
                label: strings.isZh ? 'RTT 中位数' : 'Median RTT',
                reading: rtt == null
                    ? '—'
                    : '${rtt.toStringAsFixed(rtt == rtt.round() ? 0 : 1)} ms',
                detail: strings.isZh ? '近期有效延迟样本' : 'Recent verified samples',
                tooltip: strings.isZh
                    ? '${latency.length} 台设备有近期有效 RTT 样本。'
                    : '${latency.length} devices have a recent RTT sample from a verified path.',
                compact: compact,
              ),
            ];
            return Wrap(
              spacing: gap,
              runSpacing: gap,
              children: [
                for (final field in fields)
                  SizedBox(width: cardWidth, child: field),
              ],
            );
          },
        ),
      ],
    );
  }

  String _countLabel(int value) => complete
      ? '$value'
      : value > 0 || counts.online > 0
      ? '≥$value'
      : '—';
}

class _DesktopMetric extends StatelessWidget {
  const _DesktopMetric({
    super.key,
    required this.icon,
    required this.label,
    required this.reading,
    required this.detail,
    required this.compact,
    this.color,
    this.unit = '',
    this.tooltip,
    this.extra,
  });

  final String icon;
  final String label;
  final String reading;
  final String detail;
  final bool compact;
  final Color? color;
  final String unit;
  final String? tooltip;
  final Widget? extra;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final unitAt = reading.indexOf(' ');
    final blank = reading == '—';
    final value = unitAt < 0 ? reading : reading.substring(0, unitAt);
    final suffix = unitAt >= 0
        ? reading.substring(unitAt)
        : blank || unit.isEmpty
        ? ''
        : ' $unit';
    final labelStyle = theme.textTheme.bodySmall?.copyWith(
      color: colors.textSecondary,
    );
    final metric = DesktopCard(
      padding: EdgeInsets.all(compact ? AppTokens.space8 : AppTokens.space14),
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: compact ? 58 : 92),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: labelStyle,
                  ),
                ),
                if (!compact) ...[
                  const SizedBox(width: AppTokens.space4),
                  DesktopIcon(icon, size: 15, color: colors.textMuted),
                ],
              ],
            ),
            const SizedBox(height: AppTokens.space4),
            Text.rich(
              TextSpan(
                text: value,
                children: [
                  if (suffix.isNotEmpty)
                    TextSpan(
                      text: suffix,
                      style: labelStyle?.copyWith(
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                ],
              ),
              style: theme.textTheme.titleLarge?.copyWith(
                fontSize: compact ? 19 : 26,
                height: 1.1,
                color: blank ? colors.textMuted : color ?? colors.textPrimary,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
            if (extra != null || !compact) ...[
              const SizedBox(height: AppTokens.space6),
              extra ??
                  Text(
                    detail,
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontSize: 11,
                      color: colors.textMuted,
                    ),
                  ),
            ],
          ],
        ),
      ),
    );
    return Tooltip(
      message: tooltip ?? (compact ? '$label · $detail' : detail),
      child: metric,
    );
  }
}

class _DesktopTrafficSplit extends StatelessWidget {
  const _DesktopTrafficSplit({required this.rate, required this.compact});

  final PeerTransferRate rate;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final upload = rate.uploadBytesPerSecond;
    final download = rate.downloadBytesPerSecond;
    final total = upload + download;
    final directions = [
      (
        upload,
        colors.successDot,
        strings.isZh
            ? '上传'
            : compact
            ? 'Up'
            : 'Upload',
        strings.isZh ? '上传' : 'Upload',
      ),
      (
        download,
        colors.probing,
        strings.isZh
            ? '下载'
            : compact
            ? 'Down'
            : 'Download',
        strings.isZh ? '下载' : 'Download',
      ),
    ];
    final description = directions
        .map(
          (direction) => '${direction.$4} ${formatTransferRate(direction.$1)}',
        )
        .join(' · ');
    return Tooltip(
      message: description,
      excludeFromSemantics: true,
      child: Semantics(
        label: description,
        excludeSemantics: true,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SizedBox(
              height: 5,
              child: total == 0
                  ? DecoratedBox(
                      decoration: BoxDecoration(
                        color: colors.surfaceMuted,
                        borderRadius: BorderRadius.circular(3),
                      ),
                    )
                  : Row(
                      key: const Key('home-traffic-rate-split'),
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        for (final direction in directions.where(
                          (direction) => direction.$1 > 0,
                        ))
                          Expanded(
                            flex: (direction.$1 / total * 1000).round().clamp(
                              1,
                              1000,
                            ),
                            child: Padding(
                              padding: EdgeInsetsDirectional.only(
                                end:
                                    upload > 0 &&
                                        download > 0 &&
                                        direction.$2 == colors.successDot
                                    ? AppTokens.space2
                                    : 0,
                              ),
                              child: DecoratedBox(
                                decoration: BoxDecoration(
                                  color: direction.$2,
                                  borderRadius: BorderRadius.circular(3),
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
            ),
            if (!compact) ...[
              const SizedBox(height: AppTokens.space4),
              Wrap(
                alignment: WrapAlignment.spaceBetween,
                spacing: AppTokens.space4,
                children: [
                  for (final direction in directions)
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.circle, size: 5, color: direction.$2),
                        const SizedBox(width: AppTokens.space4),
                        Text(
                          direction.$3,
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(fontSize: 10, color: colors.textMuted),
                        ),
                      ],
                    ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _DesktopTrafficSummary extends StatelessWidget {
  const _DesktopTrafficSummary({
    required this.statusStore,
    required this.scopes,
    required this.selectedId,
  });

  final StatusStore statusStore;
  final List<NetworkScopeSnapshot> scopes;
  final String? selectedId;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final history = TrafficHistoryScope.maybeOf(context);
    final saved = history?.store.summary(
      settings: history.settings,
      networkId: _trafficNetworkId(scopes, selectedId, statusStore),
    );
    final historical = scopes.any((scope) => !scope.isRunning);
    final counters = _scopeCounters(scopes);
    final theme = Theme.of(context);
    return DesktopCard(
      key: const Key('home-traffic-panel'),
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space16,
        vertical: AppTokens.space10,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: AppTokens.space16,
            runSpacing: AppTokens.space8,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  DecoratedBox(
                    decoration: BoxDecoration(
                      color: colors.probing.withValues(alpha: 0.10),
                      borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                    ),
                    child: SizedBox.square(
                      dimension: 32,
                      child: Center(
                        child: DesktopIcon(
                          'arrow-up-down',
                          size: 16,
                          color: colors.probing,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: AppTokens.space10),
                  Flexible(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          historical
                              ? (strings.isZh
                                    ? '上次记录的流量'
                                    : 'Last recorded traffic')
                              : (strings.isZh ? '流量统计' : 'Traffic usage'),
                          style: theme.textTheme.titleSmall,
                        ),
                        if (!historical)
                          Text(
                            strings.isZh ? '当前会话累计' : 'Current session total',
                            style: theme.textTheme.bodySmall?.copyWith(
                              fontSize: 11,
                              color: colors.textMuted,
                            ),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
              _DesktopTrafficTotal(
                id: 'upload',
                label: strings.isZh ? '上传' : 'Upload',
                value: counters.uploadBytes,
                icon: 'arrow-up',
                color: colors.successDot,
              ),
              _DesktopTrafficTotal(
                id: 'download',
                label: strings.isZh ? '下载' : 'Download',
                value: counters.downloadBytes,
                icon: 'arrow-down',
                color: colors.probing,
              ),
              _DesktopTrafficTotal(
                id: 'total',
                label: strings.isZh ? '合计' : 'Total',
                value: counters.totalBytes,
              ),
              TextButton.icon(
                key: const Key('home-traffic-details'),
                label: Text(strings.isZh ? '流量详情' : 'Traffic details'),
                icon: DesktopIcon(
                  'chevron-right',
                  size: AppTokens.iconSm,
                  color: theme.colorScheme.primary,
                ),
                iconAlignment: IconAlignment.end,
                onPressed: () => showDialog<void>(
                  context: context,
                  builder: (_) => AppStringsScope(
                    strings: strings,
                    child: _TrafficDetailsDialog(
                      statusStore: statusStore,
                      selectedId: selectedId,
                    ),
                  ),
                ),
              ),
            ],
          ),
          if (history != null)
            Padding(
              padding: const EdgeInsets.only(top: AppTokens.space4),
              child: Text(
                '${strings.isZh ? '历史累计' : 'Saved total'}  ${formatOptionalBytes(saved?.counters.totalBytes)}',
                key: const Key('home-traffic-history-total'),
                style: theme.textTheme.bodySmall?.copyWith(
                  color: history.store.error == null
                      ? colors.textSecondary
                      : colors.warningText,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _DesktopTrafficTotal extends StatelessWidget {
  const _DesktopTrafficTotal({
    required this.id,
    required this.label,
    required this.value,
    this.icon,
    this.color,
  });

  final String id;
  final String label;
  final int? value;
  final String? icon;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Wrap(
      spacing: AppTokens.space6,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        if (icon != null) DesktopIcon(icon!, size: 14, color: color),
        Text(
          label,
          style: theme.textTheme.bodySmall?.copyWith(color: colors.textMuted),
        ),
        Text(
          formatOptionalBytes(value),
          key: ValueKey('home-traffic-current-$id'),
          style: theme.textTheme.bodySmall?.copyWith(
            color: colors.textPrimary,
            fontWeight: FontWeight.w600,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}
