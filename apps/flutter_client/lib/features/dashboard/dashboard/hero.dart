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
    required this.configuredRoom,
    required this.onStartDaemon,
    required this.onStopDaemon,
    this.onOpenRooms,
    this.issueBanner,
  });

  final DiagnosticsSnapshot? snapshot;
  final _NetworkStatus status;
  final _PeerCounts counts;
  final bool canControlLocalDaemon;
  final bool daemonBusy;
  final bool initialProbePending;
  final bool configuredRoom;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final VoidCallback? onOpenRooms;
  final Widget? issueBanner;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final hasSnapshot = snapshot != null;
    final startupPending =
        initialProbePending &&
        (daemonBusy || status == _NetworkStatus.unavailable);

    final showStop =
        canControlLocalDaemon &&
        switch (status) {
          _NetworkStatus.healthy ||
          _NetworkStatus.degraded ||
          _NetworkStatus.stale => true,
          _ => false,
        };

    final header = hasSnapshot
        ? Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: AppTokens.space16,
            runSpacing: AppTokens.space8,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    status == _NetworkStatus.healthy
                        ? Icons.check_circle_outline_rounded
                        : Icons.info_outline_rounded,
                    size: 20,
                    color: status == _NetworkStatus.healthy
                        ? P2WlanColors.of(context).successText
                        : P2WlanColors.of(context).warningText,
                  ),
                  const SizedBox(width: AppTokens.space8),
                  Flexible(
                    child: Text(
                      status == _NetworkStatus.healthy
                          ? (strings.isZh
                                ? '本机网络已连接'
                                : 'Local network connected')
                          : status == _NetworkStatus.stale
                          ? (strings.isZh ? '上次连接信息' : 'Last known connection')
                          : _networkStatusLabel(
                              strings,
                              status,
                              canControlLocalDaemon,
                            ),
                      key: const Key('home-connection-heading'),
                      style: TextStyle(
                        color: theme.colorScheme.onSurface,
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                        height: 1.35,
                      ),
                    ),
                  ),
                ],
              ),
              if (showStop)
                _StopDaemonButton(
                  daemonBusy: daemonBusy,
                  onStopDaemon: onStopDaemon,
                ),
            ],
          )
        : Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: AppTokens.space12,
            runSpacing: AppTokens.space10,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.hub_outlined,
                    size: 19,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(width: AppTokens.space8),
                  Flexible(
                    child: Text(
                      strings.homeNetworkTitle,
                      style: TextStyle(
                        color: theme.colorScheme.onSurface,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        height: 1.4,
                      ),
                    ),
                  ),
                ],
              ),
              StatusBadge(
                label: startupPending
                    ? (strings.isZh ? '连接中' : 'Connecting')
                    : _networkStatusLabel(
                        strings,
                        status,
                        canControlLocalDaemon,
                      ),
                tone: _networkStatusTone(status),
              ),
            ],
          );

    final showStartGuide =
        status == _NetworkStatus.stopped && canControlLocalDaemon;
    final showRoomGuide = showStartGuide && onOpenRooms != null;

    final infoBlock = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (hasSnapshot) ...[
          _VirtualIpBlock(virtualIp: snapshot!.virtualIp),
          if (status == _NetworkStatus.stale) ...[
            const SizedBox(height: AppTokens.space6),
            const _StaleNote(),
          ] else ...[
            const SizedBox(height: AppTokens.space4),
            _HomeMetrics(counts: counts),
          ],
        ] else ...[
          Text(
            startupPending
                ? (strings.isZh ? '正在连接 P2WLAN' : 'Connecting to P2WLAN')
                : showRoomGuide
                ? (strings.isZh ? '连接这台设备' : 'Connect this device')
                : showStartGuide
                ? strings.homeStoppedTitle
                : status == _NetworkStatus.unavailable
                ? strings.issueStatusUnavailableTitle
                : strings.homeUnavailableTitle,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 24,
              fontWeight: FontWeight.w700,
              height: 1.35,
            ),
          ),
          const SizedBox(height: AppTokens.space6),
          Text(
            startupPending
                ? (strings.isZh
                      ? '正在等待本地网络服务就绪；如出现系统授权，请完成授权。'
                      : 'Waiting for the local network service. Complete the system permission prompt if shown.')
                : showRoomGuide
                ? (strings.isZh
                      ? '在房间页面选择要连接的房间，也可加入或创建房间。'
                      : 'Choose a room to connect to. You can also join or create a room.')
                : showStartGuide
                ? strings.homeStoppedDetail
                : status == _NetworkStatus.unavailable
                ? strings.issueStatusUnavailableDetail
                : strings.homeUnavailableDetail,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
              height: 1.6,
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
      configuredRoom: configuredRoom,
      onOpenRooms: onOpenRooms,
      onStartDaemon: () => _handleStart(context),
    );

    final showActions =
        canControlLocalDaemon &&
        status == _NetworkStatus.stopped &&
        issueBanner == null;

    return _HeroSurface(
      emphasized: !hasSnapshot,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          header,
          if (issueBanner != null) ...[
            const SizedBox(height: AppTokens.space8),
            issueBanner!,
          ],
          const SizedBox(height: AppTokens.space8),
          infoBlock,
          if (showActions) ...[
            const SizedBox(height: AppTokens.space16),
            Align(alignment: Alignment.centerLeft, child: actions),
          ],
        ],
      ),
    );
  }

  Future<void> _handleStart(BuildContext context) async {
    // macOS shows its password field only when the encrypted local
    // administrator credential is missing or no longer valid. Do not add a
    // second explanatory dialog here: after the first successful entry,
    // starting the daemon should be a single click with no repeated prompt.
    await onStartDaemon();
  }
}

/// The primary Home surface: quiet elevation, product color, and generous
/// spacing without the heavy default Material Card treatment.
class _HeroSurface extends StatelessWidget {
  const _HeroSurface({required this.child, this.emphasized = false});

  final Widget child;
  final bool emphasized;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Container(
      decoration: BoxDecoration(
        color: colors.surface,
        gradient: emphasized
            ? LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [colors.surface, colors.selectedSurface],
              )
            : null,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(
          color: emphasized
              ? theme.colorScheme.primary.withValues(alpha: 0.18)
              : colors.border,
        ),
        boxShadow: theme.brightness == Brightness.dark
            ? const []
            : AppTokens.shadowBorder,
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space16),
        child: child,
      ),
    );
  }
}

/// Virtual IP with a stable copy target and bounded inline confirmation.
class _VirtualIpBlock extends StatefulWidget {
  const _VirtualIpBlock({
    required this.virtualIp,
    this.compact = false,
    this.stale = false,
  });

  final String virtualIp;
  final bool compact;
  final bool stale;

  @override
  State<_VirtualIpBlock> createState() => _VirtualIpBlockState();
}

class _VirtualIpBlockState extends State<_VirtualIpBlock> {
  Timer? _resetCopy;
  var _copied = false;
  var _copyRevision = 0;

  @override
  void didUpdateWidget(covariant _VirtualIpBlock oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.virtualIp != widget.virtualIp) {
      _copyRevision++;
      _resetCopy?.cancel();
      _copied = false;
    }
  }

  @override
  void dispose() {
    _copyRevision++;
    _resetCopy?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          widget.stale
              ? (strings.isZh ? '上次记录的虚拟 IP' : 'Last recorded virtual IP')
              : strings.virtualIpLabel,
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 12,
            fontWeight: FontWeight.w500,
          ),
        ),
        SizedBox(height: widget.compact ? AppTokens.space2 : AppTokens.space6),
        Semantics(
          key: const Key('home-virtual-ip-feedback'),
          button: true,
          liveRegion: _copied,
          label: strings.copyVirtualIp,
          value: _copied ? strings.copied : null,
          child: Tooltip(
            excludeFromSemantics: true,
            message: _copied ? strings.copied : strings.copyVirtualIp,
            child: Material(
              type: MaterialType.transparency,
              child: InkWell(
                key: const Key('home-virtual-ip'),
                onTap: _copy,
                borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                child: ConstrainedBox(
                  constraints: BoxConstraints(
                    minHeight: widget.compact
                        ? AppTokens.space24
                        : AppTokens.minTouchTarget,
                  ),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Flexible(
                          child: Text(
                            dash(widget.virtualIp),
                            softWrap: true,
                            style: TextStyle(
                              color: theme.colorScheme.onSurface,
                              fontSize: widget.compact ? 16 : 24,
                              fontWeight: FontWeight.w600,
                              height: 1.1,
                              fontFeatures: AppTokens.tabularFontFeatures,
                            ),
                          ),
                        ),
                        SizedBox(
                          width: widget.compact
                              ? AppTokens.space8
                              : AppTokens.space12,
                        ),
                        AnimatedSwitcher(
                          duration: AppMotion.feedbackDurationOf(context),
                          child: Icon(
                            _copied ? Icons.check_rounded : Icons.copy_rounded,
                            key: ValueKey(_copied),
                            size: 17,
                            color: _copied
                                ? P2WlanColors.of(context).successText
                                : theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _copy() async {
    final revision = ++_copyRevision;
    try {
      await Clipboard.setData(ClipboardData(text: widget.virtualIp));
    } on PlatformException {
      if (!mounted || revision != _copyRevision) return;
      _resetCopy?.cancel();
      setState(() => _copied = false);
      final strings = AppStringsScope.of(context);
      showAppNotice(
        context,
        content: Text(strings.isZh ? '复制失败，请重试' : 'Copy failed. Try again.'),
      );
      return;
    }
    if (!mounted || revision != _copyRevision) return;
    _resetCopy?.cancel();
    setState(() => _copied = true);
    _resetCopy = Timer(const Duration(milliseconds: 1600), () {
      if (mounted) setState(() => _copied = false);
    });
  }
}

/// Full-label stop action grouped with the local connection status. It intentionally stays
/// a text button on phones: the destructive action must remain discoverable
/// and must not collapse into an unlabeled icon at compact widths.
class _StopDaemonButton extends StatelessWidget {
  const _StopDaemonButton({
    required this.daemonBusy,
    required this.onStopDaemon,
    this.compact = false,
  });

  final bool daemonBusy;
  final Future<void> Function() onStopDaemon;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    return OutlinedButton.icon(
      key: const Key('dashboard-stop-button'),
      onPressed: daemonBusy ? null : onStopDaemon,
      style: compact
          ? null
          : OutlinedButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
              side: BorderSide(color: colors.border),
              minimumSize: const Size(
                AppTokens.minTouchTarget,
                AppTokens.minTouchTarget,
              ),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
              visualDensity: VisualDensity.standard,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              ),
              textStyle: Theme.of(context).textTheme.labelMedium
                  ?.copyWith(fontSize: 12, fontWeight: FontWeight.w600),
            ),
      icon: daemonBusy
          ? _ButtonSpinner(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            )
          : const Icon(Icons.stop_rounded, size: 17),
      label: Text(
        daemonBusy
            ? strings.daemonWorking
            : compact
            ? (strings.isZh ? '断开' : 'Disconnect')
            : strings.stopP2wlan,
      ),
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

/// Presence and confirmed paths use distinct labels in the primary summary.
class _HomeMetrics extends StatelessWidget {
  const _HomeMetrics({required this.counts});

  final _PeerCounts counts;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Wrap(
      spacing: AppTokens.space16,
      runSpacing: AppTokens.space6,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        _MetricCell(
          key: const Key('dashboard-count-online'),
          value: '${counts.online}',
          label: strings.onlineDevices,
        ),
        _MetricCell(
          key: const Key('dashboard-count-available'),
          value: '${counts.direct + counts.relay}',
          label: strings.isZh ? '确认链路' : 'Confirmed paths',
          tooltip: strings.isZh ? '本机已确认的直连或中继路径；在线设备不一定已有可用路径。' : 'Direct or relay paths confirmed by this device. An online device may still be establishing a path.',
        ),
        _PathBreakdown(
          key: const Key('dashboard-count-direct'),
          value: counts.direct,
          label: strings.direct,
        ),
        _PathBreakdown(
          key: const Key('dashboard-count-relay'),
          value: counts.relay,
          label: strings.relay,
        ),
      ],
    );
  }
}

class _PathBreakdown extends StatelessWidget {
  const _PathBreakdown({super.key, required this.value, required this.label});
  final int value;
  final String label;

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Text(
        '$value',
        style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
      const SizedBox(width: 4),
      Text(
        label,
        style: TextStyle(
          fontSize: 12,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
    ],
  );
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
    final content = Wrap(
      spacing: AppTokens.space4,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        Text(
          value,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 14,
            fontWeight: FontWeight.w600,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 13,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
    return tooltip == null
        ? content
        : Tooltip(message: tooltip!, child: content);
  }
}
