part of '../dashboard_page.dart';

class _NetworkHero extends StatelessWidget {
  const _NetworkHero({
    required this.snapshot,
    required this.status,
    required this.counts,
    required this.daemonAvailable,
    required this.canControlLocalDaemon,
    required this.daemonBusy,
    required this.refreshing,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
  });

  final DiagnosticsSnapshot? snapshot;
  final _NetworkStatus status;
  final _PeerCounts counts;

  /// Whether any daemon endpoint is reachable (health or status). When only
  /// health is up (e.g. GET /status failing), the daemon is running but its
  /// state is unavailable.
  final bool daemonAvailable;
  final bool canControlLocalDaemon;
  final bool daemonBusy;
  final bool refreshing;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final hasSnapshot = snapshot != null;

    final header = Row(
      children: [
        Expanded(
          child: Text(
            strings.networkTitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 15,
              fontWeight: FontWeight.w800,
              letterSpacing: 0,
            ),
          ),
        ),
        const SizedBox(width: 12),
        StatusBadge(
          label: _networkStatusLabel(strings, status, canControlLocalDaemon),
          tone: _networkStatusTone(status),
        ),
      ],
    );

    // Full stop guidance only when the network is truly stopped and this device
    // can start the daemon; unavailable (health up / status down) and mobile
    // get the "unavailable" message instead.
    final showStartGuide =
        status == _NetworkStatus.stopped && canControlLocalDaemon;
    final infoBlock = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (hasSnapshot) ...[
          _HeroLabel(strings.virtualIp),
          const SizedBox(height: 4),
          Text(
            dash(snapshot!.virtualIp),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 28,
              fontWeight: FontWeight.w800,
              height: 1.05,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
          if (counts.total > 0) ...[
            const SizedBox(height: 14),
            _HeroCounts(counts: counts),
          ],
        ] else ...[
          Text(
            showStartGuide
                ? strings.dashboardStoppedTitle
                : strings.dashboardUnavailableTitle,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 20,
              fontWeight: FontWeight.w800,
              height: 1.15,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            showStartGuide
                ? strings.dashboardStoppedDetail
                : strings.dashboardUnavailableDetail,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
              height: 1.4,
            ),
          ),
        ],
      ],
    );

    final actions = _DashboardActions(
      daemonAvailable: daemonAvailable,
      daemonBusy: daemonBusy,
      canControlLocalDaemon: canControlLocalDaemon,
      refreshing: refreshing,
      onStartDaemon: () => _handleStart(context),
      onStopDaemon: onStopDaemon,
      onRefresh: onRefresh,
    );

    return _DashboardSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          header,
          const SizedBox(height: 14),
          infoBlock,
          const SizedBox(height: 16),
          const Divider(height: 1),
          const SizedBox(height: 16),
          LayoutBuilder(
            builder: (context, constraints) {
              if (constraints.maxWidth < 560) {
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _NetworkIdLine(snapshot: snapshot),
                    const SizedBox(height: 12),
                    actions,
                  ],
                );
              }
              return Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(child: _NetworkIdLine(snapshot: snapshot)),
                  const SizedBox(width: 16),
                  actions,
                ],
              );
            },
          ),
        ],
      ),
    );
  }

  Future<void> _handleStart(BuildContext context) async {
    if (defaultTargetPlatform == TargetPlatform.macOS) {
      final strings = AppStringsScope.of(context);
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (dialogContext) {
          return AlertDialog(
            title: Text(strings.macosAuthorizationTitle),
            content: Text(strings.macosAuthorizationBody),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(false),
                child: Text(strings.cancel),
              ),
              FilledButton(
                onPressed: () => Navigator.of(dialogContext).pop(true),
                child: Text(strings.continueAction),
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;
    }
    await onStartDaemon();
  }
}

class _HeroCounts extends StatelessWidget {
  const _HeroCounts({required this.counts});

  final _PeerCounts counts;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final good = isDark ? AppTokens.colorDarkGoodText : AppTokens.colorGoodText;
    final warn = isDark ? AppTokens.colorDarkWarnText : AppTokens.colorWarnText;
    final relay = isDark ? AppTokens.colorDarkAccent : AppTokens.colorAccent;
    return Wrap(
      spacing: 20,
      runSpacing: 10,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        _HeroCount(
          key: const Key('dashboard-count-online'),
          label: strings.onlineDevices,
          value: counts.online,
          color: good,
        ),
        _HeroCount(
          key: const Key('dashboard-count-direct'),
          label: strings.direct,
          value: counts.direct,
          color: good,
        ),
        _HeroCount(
          key: const Key('dashboard-count-relay'),
          label: strings.relay,
          value: counts.relay,
          color: relay,
        ),
        if (counts.probing > 0)
          _HeroCount(
            key: const Key('dashboard-count-probing'),
            label: strings.probing,
            value: counts.probing,
            color: warn,
          ),
      ],
    );
  }
}

class _HeroCount extends StatelessWidget {
  const _HeroCount({
    super.key,
    required this.label,
    required this.value,
    required this.color,
  });

  final String label;
  final int value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 7),
        Text(
          '$value',
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 15,
            fontWeight: FontWeight.w800,
            height: 1.1,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
        const SizedBox(width: 5),
        Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 12,
            fontWeight: FontWeight.w600,
            height: 1.2,
          ),
        ),
      ],
    );
  }
}

class _HeroLabel extends StatelessWidget {
  const _HeroLabel(this.value);

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
        fontWeight: FontWeight.w700,
        height: 1.2,
      ),
    );
  }
}

class _NetworkIdLine extends StatelessWidget {
  const _NetworkIdLine({required this.snapshot});

  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Flexible(
          child: Text(
            '${strings.networkId}  ${dash(snapshot?.networkId)}',
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 12,
              fontWeight: FontWeight.w500,
              height: 1.2,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
      ],
    );
  }
}
