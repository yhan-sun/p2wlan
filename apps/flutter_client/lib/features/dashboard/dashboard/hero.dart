part of '../dashboard_page.dart';

/// Home hero: quiet status, Virtual IP, identity line, key metrics, and the
/// daemon recovery actions. One surface — the only strong container on Home.
class _NetworkHero extends StatelessWidget {
  const _NetworkHero({
    required this.snapshot,
    required this.status,
    required this.loading,
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

  /// First load / recovery in flight: the daemon state is not known yet.
  final bool loading;
  final _PeerCounts counts;
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
            strings.homeNetworkTitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 15,
              fontWeight: FontWeight.w700,
              letterSpacing: 0,
            ),
          ),
        ),
        const SizedBox(width: AppTokens.space12),
        StatusBadge(
          label: _networkStatusLabel(strings, status, canControlLocalDaemon),
          tone: _networkStatusTone(status),
        ),
      ],
    );

    final showStartGuide =
        status == _NetworkStatus.stopped && canControlLocalDaemon;

    final infoBlock = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (loading) ...[
          Text(
            strings.homeLoading,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
              height: 1.4,
            ),
          ),
        ] else if (hasSnapshot) ...[
          Text(
            strings.homeJoinedSubtitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
              height: 1.3,
            ),
          ),
          const SizedBox(height: AppTokens.space14),
          _VirtualIpBlock(
            virtualIp: snapshot!.virtualIp,
            networkId: snapshot!.networkId,
          ),
          if (status == _NetworkStatus.stale) ...[
            const SizedBox(height: AppTokens.space14),
            _StaleNote(refreshing: refreshing, onRefresh: onRefresh),
          ],
          if (status != _NetworkStatus.stale) ...[
            const SizedBox(height: AppTokens.space16),
            const Divider(height: 1),
            const SizedBox(height: AppTokens.space14),
            _HomeMetrics(counts: counts),
          ],
        ] else ...[
          Text(
            showStartGuide
                ? strings.homeStoppedTitle
                : strings.homeUnavailableTitle,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 20,
              fontWeight: FontWeight.w700,
              height: 1.15,
            ),
          ),
          const SizedBox(height: AppTokens.space6),
          Text(
            showStartGuide
                ? strings.homeStoppedDetail
                : strings.homeUnavailableDetail,
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

    final actions = _HomeActions(
      status: status,
      loading: loading,
      daemonAvailable: daemonAvailable,
      daemonBusy: daemonBusy,
      canControlLocalDaemon: canControlLocalDaemon,
      refreshing: refreshing,
      onStartDaemon: () => _handleStart(context),
      onStopDaemon: onStopDaemon,
      onRefresh: onRefresh,
    );

    final showActions =
        !loading &&
        (status == _NetworkStatus.stopped ||
            status == _NetworkStatus.unavailable ||
            hasSnapshot);

    return _HeroSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          header,
          const SizedBox(height: AppTokens.space14),
          infoBlock,
          if (showActions) ...[
            if (hasSnapshot) ...[
              const SizedBox(height: AppTokens.space14),
              Align(alignment: Alignment.centerRight, child: actions),
            ] else ...[
              const SizedBox(height: AppTokens.space16),
              actions,
            ],
          ],
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

/// The one prominent surface on Home: light border, no shadow, radius 12.
class _HeroSurface extends StatelessWidget {
  const _HeroSurface({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: theme.colorScheme.outline, width: 1),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space16),
        child: child,
      ),
    );
  }
}

/// Virtual IP with tap-to-copy (tooltip + lightweight snackbar).
class _VirtualIpBlock extends StatelessWidget {
  const _VirtualIpBlock({required this.virtualIp, required this.networkId});

  final String virtualIp;
  final String networkId;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          strings.virtualIpLabel,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 12,
            fontWeight: FontWeight.w700,
            height: 1.2,
          ),
        ),
        const SizedBox(height: AppTokens.space4),
        Tooltip(
          message: strings.copyVirtualIp,
          child: InkWell(
            key: const Key('home-virtual-ip'),
            onTap: () => _copy(context, strings),
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    dash(virtualIp),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: theme.colorScheme.onSurface,
                      fontSize: 28,
                      fontWeight: FontWeight.w700,
                      height: 1.1,
                      fontFeatures: AppTokens.tabularFontFeatures,
                    ),
                  ),
                  const SizedBox(width: AppTokens.space8),
                  Icon(
                    Icons.copy_rounded,
                    size: 15,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: AppTokens.space6),
        Text(
          '${strings.networkId}  ${dash(networkId)}',
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 11.5,
            fontWeight: FontWeight.w500,
            height: 1.2,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }

  Future<void> _copy(BuildContext context, AppStrings strings) async {
    await Clipboard.setData(ClipboardData(text: virtualIp));
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(strings.copied)));
  }
}

/// Last-known data kept, with an explicit stale note and refresh.
class _StaleNote extends StatelessWidget {
  const _StaleNote({required this.refreshing, required this.onRefresh});

  final bool refreshing;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final c = P2WlanColors.of(context);
    return Row(
      children: [
        Container(
          width: 7,
          height: 7,
          decoration: BoxDecoration(
            color: c.warningDot,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 7),
        Text(
          strings.homeStaleNote,
          style: TextStyle(
            color: c.warningText,
            fontSize: 12,
            fontWeight: FontWeight.w600,
            height: 1.2,
          ),
        ),
        const SizedBox(width: AppTokens.space8),
        TextButton.icon(
          key: const Key('home-stale-refresh'),
          onPressed: refreshing ? null : onRefresh,
          icon: refreshing
              ? const SizedBox.square(
                  dimension: 14,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.refresh_rounded, size: 16),
          label: Text(strings.refresh),
          style: TextButton.styleFrom(
            visualDensity: VisualDensity.compact,
            padding: const EdgeInsets.symmetric(horizontal: 8),
          ),
        ),
      ],
    );
  }
}

/// Online / Direct / Relay — one quiet row, subtle dividers, no metric cards.
class _HomeMetrics extends StatelessWidget {
  const _HomeMetrics({required this.counts});

  final _PeerCounts counts;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Row(
      children: [
        _MetricCell(
          key: const Key('dashboard-count-online'),
          value: counts.online,
          label: strings.onlineDevices,
        ),
        _MetricDivider(),
        _MetricCell(
          key: const Key('dashboard-count-direct'),
          value: counts.direct,
          label: strings.direct,
        ),
        _MetricDivider(),
        _MetricCell(
          key: const Key('dashboard-count-relay'),
          value: counts.relay,
          label: strings.relay,
        ),
      ],
    );
  }
}

class _MetricCell extends StatelessWidget {
  const _MetricCell({super.key, required this.value, required this.label});

  final int value;
  final String label;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Expanded(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '$value',
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 20,
              fontWeight: FontWeight.w700,
              height: 1.1,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
          const SizedBox(height: 2),
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
      ),
    );
  }
}

class _MetricDivider extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      width: 1,
      height: 30,
      color: P2WlanColors.of(context).divider,
    );
  }
}
