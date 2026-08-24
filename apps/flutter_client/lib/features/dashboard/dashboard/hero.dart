part of '../dashboard_page.dart';

/// Mobile/web home state. These builds are remote-management clients and do
/// not own a local desktop daemon or diagnostics endpoint. Keep that boundary
/// explicit instead of rendering the desktop "service unavailable" recovery
/// state against a localhost URL that can never exist on the phone.
class _RemoteOnlyHero extends StatelessWidget {
  const _RemoteOnlyHero({this.onOpenDevices});

  final VoidCallback? onOpenDevices;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return _HeroSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  strings.mobileModeTitle,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(width: AppTokens.space12),
              StatusBadge(
                label: strings.mobileModeBadge,
                tone: StatusTone.neutral,
              ),
            ],
          ),
          const SizedBox(height: AppTokens.space12),
          Text(
            strings.mobileModeDetail,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
              height: 1.45,
            ),
          ),
          if (onOpenDevices != null) ...[
            const SizedBox(height: AppTokens.space14),
            Align(
              alignment: Alignment.centerRight,
              child: OutlinedButton.icon(
                key: const Key('mobile-home-open-devices'),
                onPressed: onOpenDevices,
                icon: const Icon(Icons.devices_other_rounded, size: 17),
                label: Text(strings.mobileModeOpenDevices),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

/// Home hero: quiet status, Virtual IP, key metrics, and daemon recovery
/// actions. One surface — the only strong container on Home.
class _NetworkHero extends StatelessWidget {
  const _NetworkHero({
    required this.snapshot,
    required this.status,
    required this.counts,
    required this.canControlLocalDaemon,
    required this.daemonBusy,
    required this.initialProbePending,
    required this.onStartDaemon,
    required this.onStopDaemon,
  });

  final DiagnosticsSnapshot? snapshot;
  final _NetworkStatus status;
  final _PeerCounts counts;
  final bool canControlLocalDaemon;
  final bool daemonBusy;
  final bool initialProbePending;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final hasSnapshot = snapshot != null;

    final showStop =
        canControlLocalDaemon &&
        switch (status) {
          _NetworkStatus.healthy ||
          _NetworkStatus.degraded ||
          _NetworkStatus.stale => true,
          _ => false,
        };

    final header = LayoutBuilder(
      builder: (context, _) {
        final colors = P2WlanColors.of(context);
        return Row(
          children: [
            Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: colors.selectedSurface,
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              ),
              child: Icon(
                Icons.hub_rounded,
                size: 19,
                color: theme.colorScheme.primary,
              ),
            ),
            const SizedBox(width: AppTokens.space12),
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
            const SizedBox(width: AppTokens.space8),
            StatusBadge(
              label: _networkStatusLabel(
                strings,
                status,
                canControlLocalDaemon,
              ),
              tone: _networkStatusTone(status),
            ),
          ],
        );
      },
    );

    final showStartGuide =
        status == _NetworkStatus.stopped && canControlLocalDaemon;

    final infoBlock = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (hasSnapshot) ...[
          LayoutBuilder(
            builder: (context, constraints) {
              final virtualIp = _VirtualIpBlock(
                virtualIp: snapshot!.virtualIp,
                showStop: showStop,
                daemonBusy: daemonBusy,
                onStopDaemon: onStopDaemon,
              );

              // On desktop the two pieces of primary information share one
              // baseline. Narrow windows keep the same order but stack them
              // so neither the IP nor the counts becomes cramped.
              if (status != _NetworkStatus.stale &&
                  constraints.maxWidth >= 720) {
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Expanded(child: virtualIp),
                    const SizedBox(width: AppTokens.space24),
                    SizedBox(
                      width: 360,
                      child: _HomeMetrics(
                        counts: counts,
                        natProfile: snapshot!.natProfile,
                      ),
                    ),
                  ],
                );
              }

              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  virtualIp,
                  if (status == _NetworkStatus.stale) ...[
                    const SizedBox(height: AppTokens.space14),
                    const _StaleNote(),
                  ] else ...[
                    const SizedBox(height: AppTokens.space16),
                    _HomeMetrics(
                      counts: counts,
                      natProfile: snapshot!.natProfile,
                    ),
                  ],
                ],
              );
            },
          ),
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
      daemonBusy: daemonBusy,
      initialProbePending: initialProbePending,
      canControlLocalDaemon: canControlLocalDaemon,
      onStartDaemon: () => _handleStart(context),
    );

    final showActions =
        canControlLocalDaemon && status == _NetworkStatus.stopped;

    return _HeroSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          header,
          const SizedBox(height: AppTokens.space16),
          infoBlock,
          if (showActions) ...[
            const SizedBox(height: AppTokens.space16),
            actions,
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

/// The primary Home surface: quiet elevation, product color, and generous
/// spacing without the heavy default Material Card treatment.
class _HeroSurface extends StatelessWidget {
  const _HeroSurface({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Container(
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border, width: 1),
        boxShadow: theme.brightness == Brightness.dark
            ? const []
            : AppTokens.shadowBorder,
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space20),
        child: child,
      ),
    );
  }
}

/// Virtual IP with tap-to-copy (tooltip + lightweight snackbar).
class _VirtualIpBlock extends StatelessWidget {
  const _VirtualIpBlock({
    required this.virtualIp,
    this.showStop = false,
    this.daemonBusy = false,
    this.onStopDaemon,
  });

  final String virtualIp;
  final bool showStop;
  final bool daemonBusy;
  final Future<void> Function()? onStopDaemon;

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
        Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Expanded(
              child: Tooltip(
                message: strings.copyVirtualIp,
                child: InkWell(
                  key: const Key('home-virtual-ip'),
                  onTap: () => _copy(context, strings),
                  borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Row(
                      children: [
                        Flexible(
                          child: Text(
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
            ),
            if (showStop && onStopDaemon != null) ...[
              const SizedBox(width: AppTokens.space8),
              _StopDaemonButton(
                daemonBusy: daemonBusy,
                onStopDaemon: onStopDaemon!,
              ),
            ],
          ],
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

/// Full-label stop action kept next to the Virtual IP. It intentionally stays
/// a text button on phones: the destructive action must remain discoverable
/// and must not collapse into an unlabeled icon at compact widths.
class _StopDaemonButton extends StatelessWidget {
  const _StopDaemonButton({
    required this.daemonBusy,
    required this.onStopDaemon,
  });

  final bool daemonBusy;
  final Future<void> Function() onStopDaemon;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    return OutlinedButton.icon(
      key: const Key('dashboard-stop-button'),
      onPressed: daemonBusy ? null : onStopDaemon,
      style: OutlinedButton.styleFrom(
        foregroundColor: colors.dangerText,
        backgroundColor: colors.dangerSurface,
        side: BorderSide(color: colors.dangerBorder),
        minimumSize: const Size(0, 40),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
        visualDensity: VisualDensity.compact,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        ),
        textStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
      ),
      icon: daemonBusy
          ? _ButtonSpinner(color: colors.dangerText)
          : const Icon(Icons.stop_rounded, size: 17),
      label: Text(daemonBusy ? strings.daemonWorking : strings.stopP2wlan),
    );
  }
}

/// Last-known data kept with an explicit stale note; polling stays automatic.
class _StaleNote extends StatelessWidget {
  const _StaleNote();

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final c = P2WlanColors.of(context);
    return Wrap(
      crossAxisAlignment: WrapCrossAlignment.center,
      spacing: 7,
      runSpacing: 4,
      children: [
        Container(
          width: 7,
          height: 7,
          decoration: BoxDecoration(
            color: c.warningDot,
            shape: BoxShape.circle,
          ),
        ),
        Text(
          strings.homeStaleNote,
          style: TextStyle(
            color: c.warningText,
            fontSize: 12,
            fontWeight: FontWeight.w600,
            height: 1.2,
          ),
        ),
      ],
    );
  }
}

/// Online / Direct / Relay / NAT in one compact statistics surface.
class _HomeMetrics extends StatelessWidget {
  const _HomeMetrics({required this.counts, required this.natProfile});

  final _PeerCounts counts;
  final NatProfileSnapshot? natProfile;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final natType = natProfile?.traversalType;
    final natValue = natProfile == null
        ? '—'
        : strings.natTraversalTypeCompactLabel(natType!);
    final natTooltip = natProfile == null
        ? strings.natDetectionUnavailable
        : natType == NatTraversalType.unknown
        ? strings.natTypeDetectionInProgressDetail
        : strings.natTraversalTypeLabel(natType!);
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space8,
        vertical: AppTokens.space12,
      ),
      decoration: BoxDecoration(
        color: colors.surfaceMuted,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          _MetricCell(
            key: const Key('dashboard-count-online'),
            value: '${counts.online}',
            label: strings.onlineDevices,
          ),
          _MetricDivider(color: colors.border),
          _MetricCell(
            key: const Key('dashboard-nat-type'),
            value: natValue,
            label: strings.natType,
            tooltip: natTooltip,
          ),
          _MetricDivider(color: colors.border),
          _MetricCell(
            key: const Key('dashboard-count-direct'),
            value: '${counts.direct}',
            label: strings.direct,
          ),
          _MetricDivider(color: colors.border),
          _MetricCell(
            key: const Key('dashboard-count-relay'),
            value: '${counts.relay}',
            label: strings.relay,
          ),
        ],
      ),
    );
  }
}

class _MetricDivider extends StatelessWidget {
  const _MetricDivider({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(width: 1, height: 34, color: color);
  }
}

class _MetricCell extends StatelessWidget {
  const _MetricCell({
    super.key,
    required this.value,
    required this.label,
    this.tooltip,
  });

  final String value;
  final String label;
  final String? tooltip;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final content = Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          height: 22,
          child: FittedBox(
            fit: BoxFit.scaleDown,
            child: Text(
              value,
              maxLines: 1,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 20,
                fontWeight: FontWeight.w700,
                height: 1.1,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ),
        const SizedBox(height: 2),
        Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          textAlign: TextAlign.center,
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 12,
            fontWeight: FontWeight.w600,
            height: 1.2,
          ),
        ),
      ],
    );
    return Expanded(
      child: tooltip == null
          ? content
          : Tooltip(message: tooltip!, child: content),
    );
  }
}
