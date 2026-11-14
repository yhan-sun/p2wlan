part of '../dashboard_page.dart';

class _DesktopLiveMetrics extends StatelessWidget {
  const _DesktopLiveMetrics({
    required this.counts,
    required this.peers,
    required this.complete,
    required this.bytesPerSecond,
  });

  final _PeerCounts counts;
  final List<NetworkPeerSnapshot> peers;
  final bool complete;
  final int? bytesPerSecond;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final latency = [for (final item in peers) ?item.peer.latencyMs]..sort();
    final middle = latency.length ~/ 2;
    final rtt = latency.isEmpty
        ? null
        : (latency[(latency.length - 1) ~/ 2] + latency[middle]) / 2;
    final fields = [
      _DesktopMetric(
        key: const Key('home-live-online'),
        label: strings.isZh ? '在线设备' : 'Online devices',
        reading: _countLabel(counts.online),
      ),
      _DesktopMetric(
        key: const Key('home-live-direct'),
        label: strings.isZh ? 'P2P 直连' : 'P2P direct',
        reading: _countLabel(counts.direct),
        color: colors.direct,
      ),
      _DesktopMetric(
        key: const Key('home-live-relay'),
        label: strings.isZh ? 'Relay 中继' : 'Relay',
        reading: _countLabel(counts.relay),
        color: colors.relay,
      ),
      _DesktopMetric(
        key: const Key('home-live-rate'),
        label: strings.isZh ? '实时流量' : 'Live traffic',
        reading: formatTransferRate(bytesPerSecond),
        tooltip: strings.isZh ? '当前范围内已采样的上传与下载合计速率。' : 'Combined sampled upload and download rate for the current scope.',
      ),
      _DesktopMetric(
        key: const Key('home-live-rtt'),
        label: strings.isZh ? 'RTT 中位数' : 'Median RTT',
        reading: rtt == null
            ? '—'
            : '${rtt.toStringAsFixed(rtt == rtt.round() ? 0 : 1)} ms',
        tooltip: strings.isZh
            ? '${latency.length} 台设备有已验证链路的近期 RTT 样本。'
            : '${latency.length} devices have a recent RTT sample from a verified path.',
      ),
    ];
    return DecoratedBox(
      decoration: BoxDecoration(
        border: Border(
          top: BorderSide(color: colors.divider),
          bottom: BorderSide(color: colors.divider),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: AppTokens.space12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            LayoutBuilder(
              builder: (context, constraints) {
                final scale = MediaQuery.textScalerOf(context).scale(13) / 13;
                final width = constraints.maxWidth;
                final columns = switch (width / scale) {
                  >= 520 => 5,
                  >= 320 => 3,
                  >= 200 => 2,
                  _ => 1,
                };
                return Wrap(
                  runSpacing: AppTokens.space12,
                  children: [
                    for (var index = 0; index < fields.length; index++)
                      SizedBox(
                        width: width / columns,
                        child: DecoratedBox(
                          decoration: BoxDecoration(
                            border: index % columns == 0
                                ? null
                                : Border(
                                    left: BorderSide(color: colors.divider),
                                  ),
                          ),
                          child: Padding(
                            padding: EdgeInsets.only(
                              left: index % columns == 0
                                  ? 0
                                  : AppTokens.space12,
                              right: AppTokens.space8,
                            ),
                            child: fields[index],
                          ),
                        ),
                      ),
                  ],
                );
              },
            ),
            if (counts.online > 0) ...[
              const SizedBox(height: AppTokens.space12),
              _DesktopPathBreakdown(counts: counts),
            ],
          ],
        ),
      ),
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
    required this.label,
    required this.reading,
    this.color,
    this.tooltip,
  });

  final String label;
  final String reading;
  final Color? color;
  final String? tooltip;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final unitAt = reading.indexOf(' ');
    final value = unitAt < 0 ? reading : reading.substring(0, unitAt);
    final metric = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: theme.textTheme.bodySmall?.copyWith(
            color: colors.textSecondary,
          ),
        ),
        const SizedBox(height: AppTokens.space4),
        AppEntrance(
          identity: reading,
          child: Text.rich(
            TextSpan(
              text: value,
              children: [
                if (unitAt >= 0)
                  TextSpan(
                    text: reading.substring(unitAt),
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: colors.textSecondary,
                    ),
                  ),
              ],
            ),
            style: theme.textTheme.titleLarge?.copyWith(
              color: reading == '—' ? colors.textMuted : color,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
      ],
    );
    return tooltip == null ? metric : Tooltip(message: tooltip!, child: metric);
  }
}

class _DesktopPathBreakdown extends StatelessWidget {
  const _DesktopPathBreakdown({required this.counts});

  final _PeerCounts counts;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final segments = [
      (counts.direct, colors.direct, strings.direct),
      (counts.relay, colors.relay, strings.relay),
      (counts.probing, colors.probing, strings.probing),
    ];
    final description = [
      for (final (count, _, label) in segments) '$label $count',
    ].join(' · ');
    return Tooltip(
      message: description,
      excludeFromSemantics: true,
      child: Semantics(
        label: description,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          child: SizedBox(
            height: AppTokens.space4,
            child: Row(
              key: const Key('home-path-breakdown'),
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                for (final (count, color, _) in segments)
                  if (count > 0)
                    Expanded(
                      flex: count,
                      child: ColoredBox(color: color),
                    ),
              ],
            ),
          ),
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
    return Container(
      key: const Key('home-traffic-panel'),
      padding: const EdgeInsets.only(top: AppTokens.space8),
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: colors.divider)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text(
                historical
                    ? (strings.isZh ? '上次记录的流量' : 'Last recorded traffic')
                    : (strings.isZh ? '流量统计' : 'Traffic usage'),
                style: Theme.of(context).textTheme.titleSmall,
              ),
              TextButton.icon(
                key: const Key('home-traffic-details'),
                label: Text(strings.isZh ? '流量详情' : 'Traffic details'),
                icon: const Icon(
                  Icons.chevron_right_rounded,
                  size: AppTokens.iconSm,
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
          TrafficTotals(
            counters: _scopeCounters(scopes),
            keyPrefix: 'home-traffic-current',
          ),
          if (history != null)
            Padding(
              padding: const EdgeInsets.only(top: AppTokens.space8),
              child: Text(
                '${strings.isZh ? '历史累计' : 'Saved total'}  ${formatOptionalBytes(saved?.counters.totalBytes)}',
                key: const Key('home-traffic-history-total'),
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: history.store.error == null
                      ? colors.textSecondary
                      : colors.warningText,
                ),
              ),
            ),
        ],
      ),
    );
  }
}
