part of '../dashboard_page.dart';

class _DashboardMetrics extends StatelessWidget {
  const _DashboardMetrics({
    required this.snapshot,
    required this.lastFetchedAt,
    required this.requestDuration,
  });

  final DiagnosticsSnapshot? snapshot;
  final DateTime? lastFetchedAt;
  final Duration? requestDuration;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final stats = snapshot?.stats;
    final relay = snapshot?.relaySelection;
    final totalPeers = snapshot?.peers.length ?? stats?.totalPeers;
    final onlinePeers = snapshot?.peers.where((peer) => peer.online).length;
    final offlinePeers = snapshot?.peers.where((peer) => !peer.online).length;
    final probingPeers = snapshot?.peers
        .where((peer) => peer.path == 'probing' || peer.path == 'direct_trial')
        .length;
    final items = [
      _MetricItem(
        label: strings.onlineDevices,
        value: onlinePeers == null
            ? '—'
            : '${formatInt(onlinePeers)}/${formatInt(totalPeers ?? 0)}',
        detail: offlinePeers == null
            ? null
            : '${strings.offlineDevices}: ${formatInt(offlinePeers)}',
      ),
      _MetricItem(
        label: strings.pathOverview,
        value: stats == null
            ? '—'
            : '${formatInt(stats.directConnections)} / ${formatInt(stats.relayConnections)}',
        detail: stats == null
            ? null
            : '${strings.directPaths} · ${strings.relayPaths}${probingPeers == null || probingPeers == 0 ? '' : ' · ${strings.probing}: ${formatInt(probingPeers)}'}',
      ),
      _MetricItem(
        label: strings.relay,
        value: snapshot == null
            ? '—'
            : snapshot!.relayConnected
            ? strings.connected
            : strings.notConnected,
        detail: dash(relay?.selectedRegion ?? relay?.selectedEndpoint),
      ),
      _MetricItem(
        label: strings.lastRefresh,
        value: formatDateTime(lastFetchedAt),
        detail: formatDuration(requestDuration),
      ),
    ];

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            children: [
              for (var index = 0; index < items.length; index++) ...[
                _CompactMetricRow(item: items[index]),
                if (index != items.length - 1) const _MetricDivider(),
              ],
            ],
          );
        }

        final columns = constraints.maxWidth < 760 ? 2 : 4;
        final spacing = columns == 2 ? 18.0 : 24.0;
        final width =
            (constraints.maxWidth - (spacing * (columns - 1))) / columns;
        return Wrap(
          spacing: spacing,
          runSpacing: 16,
          children: [
            for (final item in items) _MetricBlock(width: width, item: item),
          ],
        );
      },
    );
  }
}

class _MetricItem {
  const _MetricItem({required this.label, required this.value, this.detail});

  final String label;
  final String value;
  final String? detail;
}

class _MetricBlock extends StatelessWidget {
  const _MetricBlock({required this.width, required this.item});

  final double width;
  final _MetricItem item;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SizedBox(
      width: width,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _MetricLabel(item.label),
          const SizedBox(height: 6),
          Text(
            item.value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 16,
              fontWeight: FontWeight.w700,
              height: 1.15,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
          if (item.detail != null) ...[
            const SizedBox(height: 4),
            _MetricDetail(item.detail!),
          ],
        ],
      ),
    );
  }
}

class _CompactMetricRow extends StatelessWidget {
  const _CompactMetricRow({required this.item});

  final _MetricItem item;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 9),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: _MetricLabel(item.label)),
          const SizedBox(width: 16),
          Flexible(
            flex: 2,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  item.value,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.right,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                    height: 1.2,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
                if (item.detail != null) ...[
                  const SizedBox(height: 3),
                  _MetricDetail(item.detail!, textAlign: TextAlign.right),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _MetricLabel extends StatelessWidget {
  const _MetricLabel(this.value);

  final String value;

  @override
  Widget build(BuildContext context) {
    return Text(
      value,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        color: Theme.of(context).colorScheme.onSurfaceVariant,
        fontSize: 12,
        fontWeight: FontWeight.w600,
        height: 1.2,
      ),
    );
  }
}

class _MetricDetail extends StatelessWidget {
  const _MetricDetail(this.value, {this.textAlign = TextAlign.left});

  final String value;
  final TextAlign textAlign;

  @override
  Widget build(BuildContext context) {
    return Text(
      value,
      maxLines: 2,
      overflow: TextOverflow.ellipsis,
      textAlign: textAlign,
      style: TextStyle(
        color: Theme.of(context).colorScheme.onSurfaceVariant,
        fontSize: 12,
        fontWeight: FontWeight.w400,
        height: 1.25,
        fontFeatures: AppTokens.tabularFontFeatures,
      ),
    );
  }
}

class _MetricDivider extends StatelessWidget {
  const _MetricDivider();

  @override
  Widget build(BuildContext context) {
    return Divider(color: Theme.of(context).colorScheme.outlineVariant);
  }
}

class _StatusNote extends StatelessWidget {
  const _StatusNote({
    required this.label,
    required this.message,
    required this.tone,
  });

  final String label;
  final String message;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final colors = _tonePanelColors(context, tone);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border, width: 1),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.only(top: 7),
              child: Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(
                  color: colors.text,
                  shape: BoxShape.circle,
                ),
              ),
            ),
            const SizedBox(width: 9),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: TextStyle(
                      color: colors.text,
                      fontSize: 12,
                      height: 1.25,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    message,
                    style: TextStyle(
                      color: colors.text,
                      fontSize: 12,
                      height: 1.35,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

({Color bg, Color border, Color text}) _tonePanelColors(
  BuildContext context,
  StatusTone tone,
) {
  final theme = Theme.of(context);
  final isDark = theme.brightness == Brightness.dark;
  if (isDark) {
    return switch (tone) {
      StatusTone.good => (
        bg: AppTokens.colorDarkGoodBg,
        border: AppTokens.colorDarkGoodBorder,
        text: AppTokens.colorDarkGoodText,
      ),
      StatusTone.warn => (
        bg: AppTokens.colorDarkWarnBg,
        border: AppTokens.colorDarkWarnBorder,
        text: AppTokens.colorDarkWarnText,
      ),
      StatusTone.bad => (
        bg: AppTokens.colorDarkBadBg,
        border: AppTokens.colorDarkBadBorder,
        text: AppTokens.colorDarkBadText,
      ),
      StatusTone.neutral => (
        bg: AppTokens.colorDarkNeutralBg,
        border: AppTokens.colorDarkNeutralBorder,
        text: AppTokens.colorDarkNeutralText,
      ),
    };
  }

  return switch (tone) {
    StatusTone.good => (
      bg: AppTokens.colorGoodBg,
      border: AppTokens.colorGoodBorder,
      text: AppTokens.colorGoodText,
    ),
    StatusTone.warn => (
      bg: AppTokens.colorWarnBg,
      border: AppTokens.colorWarnBorder,
      text: AppTokens.colorWarnText,
    ),
    StatusTone.bad => (
      bg: AppTokens.colorBadBg,
      border: AppTokens.colorBadBorder,
      text: AppTokens.colorBadText,
    ),
    StatusTone.neutral => (
      bg: theme.colorScheme.surfaceContainerHighest,
      border: theme.colorScheme.outline,
      text: theme.colorScheme.onSurfaceVariant,
    ),
  };
}
