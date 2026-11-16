part of '../dashboard_page.dart';

/// Desktop Home presents runtime status, current measurements and recent
/// peers in reading order. The scope selector changes presentation only.
class _DesktopHome extends StatefulWidget {
  const _DesktopHome({
    required this.page,
    required this.capabilities,
    required this.scrollController,
    required this.scopeId,
    required this.onScopeChanged,
  });

  final DashboardPage page;
  final PlatformCapabilities capabilities;
  final ScrollController scrollController;
  final String? scopeId;
  final ValueChanged<String?> onScopeChanged;

  @override
  State<_DesktopHome> createState() => _DesktopHomeState();
}

class _DesktopHomeState extends State<_DesktopHome> {
  final _diagnostics = ExpansibleController();
  final _diagnosticsAnchor = GlobalKey();
  final _diagnosticPeer = ValueNotifier<String?>(null);

  DashboardPage get page => widget.page;

  @override
  void dispose() {
    _diagnostics.dispose();
    _diagnosticPeer.dispose();
    super.dispose();
  }

  void _openDiagnostics(NetworkPeerSnapshot item) {
    final context = _diagnosticsAnchor.currentContext;
    if (context == null) return;
    _diagnosticPeer.value = item.identity;
    _diagnostics.expand();
    Scrollable.ensureVisible(
      context,
      duration: AppMotion.durationOf(context),
      curve: AppMotion.curve,
    );
  }

  @override
  Widget build(BuildContext context) {
    final store = page.statusStore;
    final strings = AppStringsScope.of(context);
    return ListenableBuilder(
      listenable: Listenable.merge([
        store,
        page.settingsStore,
        store.parallelRooms,
      ]),
      builder: (context, _) {
        final overview = NetworkOverview.read(store);
        final selectedId = overview.selected(widget.scopeId).isEmpty
            ? null
            : widget.scopeId;
        final scopes = overview.selected(selectedId);
        final running = scopes.where((scope) => scope.isRunning).toList();
        final peers = [
          for (final scope in scopes)
            ...scope.peers.where((item) => item.online),
        ];
        final counts = _countPeers(peers.map((item) => item.peer).toList());
        final focus = scopes.length == 1 ? scopes.single : null;
        final representative =
            focus ??
            running.where((scope) => scope.isPrimary).firstOrNull ??
            (running.length == 1 ? running.single : null);
        final trafficScopes = _trafficScopes(overview, selectedId);
        // The primary runtime is the only source of sampled live rates.
        final rate = trafficScopes.length == 1
            ? _scopeRate(trafficScopes.single, store)
            : null;
        final devicePreview = _DesktopOnlineDevices(
          peers: peers.take(5).toList(growable: false),
          onOpenDevices: page.onOpenDevices,
          onOpenPeer: _peerAction,
          onDiagnostics: _openDiagnostics,
          scopeLabels: focus == null,
          hasCurrentData: running.isNotEmpty,
        );
        final components = representative?.isRunning == true
            ? _DesktopNetworkComponents(scope: representative!)
            : null;
        return PageScaffold(
          scrollController: widget.scrollController,
          title: strings.isZh ? '网络概览' : 'Network overview',
          subtitle: strings.isZh ? '查看虚拟局域网的连接状态、设备与传输活动。' : 'See your virtual network, connected devices and transfer activity.',
          showHeader: page.showHeader,
          maxWidth: AppTokens.desktopPageMaxWidth,
          children: [
            _DesktopConnection(
              page: page,
              capabilities: widget.capabilities,
              overview: overview,
              scopes: scopes,
              focus: focus,
              representative: representative,
            ),
            SizedBox(
              height: MediaQuery.sizeOf(context).width < 900
                  ? AppTokens.space12
                  : AppTokens.space20,
            ),
            _DesktopLiveMetrics(
              counts: counts,
              peers: peers,
              complete:
                  running.isNotEmpty &&
                  trafficScopes.every((scope) => scope.isRunning),
              rate: rate,
              scopePicker: overview.hasRooms
                  ? NetworkScopePicker(
                      overview: overview,
                      selectedId: selectedId,
                      onChanged: widget.onScopeChanged,
                    )
                  : null,
            ),
            SizedBox(
              height: MediaQuery.sizeOf(context).width < 900
                  ? AppTokens.space8
                  : AppTokens.space16,
            ),
            if (components == null)
              devicePreview
            else
              LayoutBuilder(
                builder: (context, constraints) {
                  final scale = MediaQuery.textScalerOf(context).scale(13) / 13;
                  if (constraints.maxWidth < 720 * scale) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        devicePreview,
                        const SizedBox(height: AppTokens.space16),
                        components,
                      ],
                    );
                  }
                  return Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(child: devicePreview),
                      const SizedBox(width: AppTokens.space14),
                      SizedBox(
                        width: (constraints.maxWidth / 3)
                            .clamp(250, 346)
                            .toDouble(),
                        child: components,
                      ),
                    ],
                  );
                },
              ),
            const SizedBox(height: AppTokens.space16),
            if (trafficScopes.any((scope) => scope.snapshot != null))
              _DesktopTrafficSummary(
                statusStore: store,
                scopes: trafficScopes,
                selectedId: selectedId,
              )
            else
              _TrafficHistoryEntry(statusStore: store, selectedId: selectedId),
            const SizedBox(height: AppTokens.space16),
            _DesktopHomeDiagnostics(
              key: _diagnosticsAnchor,
              controller: _diagnostics,
              diagnosticPeer: _diagnosticPeer,
              scopes: scopes,
              peers: peers,
              representative: representative,
              onOpenTroubleshooting: page.onOpenTroubleshooting,
              onOpenRoom: page.onOpenRoom,
              onOpenDevices: page.onOpenDevices,
            ),
          ],
        );
      },
    );
  }

  VoidCallback? _peerAction(NetworkPeerSnapshot item) {
    if (item.roomId case final roomId? when !item.isPrimary) {
      if (page.onOpenRoomDevice case final openDevice?) {
        return () => openDevice(roomId, item.peer.nodeId);
      }
      if (page.onOpenRoom case final openRoom?) {
        return () => openRoom(roomId);
      }
      return page.onOpenRooms;
    }
    if (page.onOpenPeer case final open?) return () => open(item.peer);
    return page.onOpenDevices;
  }
}

class _DesktopConnection extends StatelessWidget {
  const _DesktopConnection({
    required this.page,
    required this.capabilities,
    required this.overview,
    required this.scopes,
    required this.focus,
    required this.representative,
  });

  final DashboardPage page;
  final PlatformCapabilities capabilities;
  final NetworkOverview overview;
  final List<NetworkScopeSnapshot> scopes;
  final NetworkScopeSnapshot? focus;
  final NetworkScopeSnapshot? representative;

  StatusStore get store => page.statusStore;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final primaryOnly = focus?.isPrimary == true;
    final state = focus?.state;
    final busy = primaryOnly && store.daemonBusy;
    final initialProbe =
        primaryOnly &&
        (store.daemonStarting ||
            (store.snapshot == null && store.startupCatalogSettling) ||
            (store.lastFetchedAt == null && store.refreshing));
    final transitioning =
        busy ||
        state == NetworkDisplayState.starting ||
        state == NetworkDisplayState.stopping ||
        (state == null && !overview.hasRunningNetwork && overview.isStarting);
    final (tone, title, detail) = _connectionCopy(
      strings,
      transitioning: transitioning,
      primaryOnly: primaryOnly,
    );
    final colors = P2WlanColors.of(context);
    final accent = transitioning
        ? colors.progress
        : _tonePanelColors(context, tone).text;
    final issue = primaryOnly
        ? _primaryIssue(strings, state)
        : _roomIssue(strings);
    final canControl = capabilities.canControlLocalDaemon;
    final canStopPrimary =
        primaryOnly &&
        canControl &&
        (state == NetworkDisplayState.running ||
            state == NetworkDisplayState.attention ||
            state == NetworkDisplayState.stale);
    final canStopRoom =
        canControl &&
        focus != null &&
        !primaryOnly &&
        state != NetworkDisplayState.stopping &&
        state != NetworkDisplayState.starting &&
        state != NetworkDisplayState.stopped;
    final room = focus?.roomId;
    final roomAction = room == null || page.onOpenRoom == null
        ? page.onOpenRooms
        : () => page.onOpenRoom!(room);
    final cancelled =
        store.lastDaemonFailureCode ==
        DaemonStartupFailureCode.administratorAuthorizationCancelled;
    final canChooseRoom =
        !primaryOnly ||
        (state == NetworkDisplayState.unavailable && page.onOpenRooms != null);
    final canStartPrimary =
        primaryOnly &&
        canControl &&
        (state == NetworkDisplayState.stopped ||
            state == NetworkDisplayState.starting);
    final actions = [
      if (canStopPrimary)
        _StopDaemonButton(
          daemonBusy: busy,
          onStopDaemon: store.stopPrimaryDaemon,
          compact: true,
        ),
      if (canStopRoom && room != null)
        _DesktopGhostDanger(
          key: const Key('home-disconnect-room'),
          onPressed: () => _disconnectRoom(context, focus!),
          label: strings.isZh ? '断开房间' : 'Disconnect room',
        ),
      if (canChooseRoom && roomAction != null && issue == null)
        FilledButton(
          key: Key(primaryOnly ? 'home-open-rooms' : 'home-room-action'),
          onPressed: roomAction,
          child: Text(switch ((
            primaryOnly,
            focus?.isRunning ?? overview.hasRunningNetwork,
            room,
          )) {
            (true, _, _) => strings.isZh ? '加入或创建房间' : 'Join or create a room',
            (false, false, _) => strings.isZh ? '连接房间' : 'Connect a room',
            (false, true, null) =>
              strings.isZh ? '选择房间邀请' : 'Choose a room to invite',
            (false, true, _) => strings.isZh ? '邀请设备' : 'Invite a device',
          }),
        ),
      if (canStartPrimary && (issue == null || cancelled))
        _HomeActions(
          status: _NetworkStatus.stopped,
          daemonBusy: busy,
          initialProbePending: initialProbe,
          canControlLocalDaemon: canControl,
          configuredRoom: isRoomNetwork(page.settingsStore.settings.networkId),
          onStartDaemon: store.startDaemon,
          onOpenRooms: page.onOpenRooms,
        ),
    ];
    final virtualIp = representative?.snapshot?.virtualIp.trim() ?? '';
    final showLastIp = state == NetworkDisplayState.stale;
    final ip =
        virtualIp.isNotEmpty &&
            (representative?.isRunning == true || showLastIp)
        ? _VirtualIpBlock(
            virtualIp: virtualIp,
            compact: true,
            stale: showLastIp,
            inline: true,
          )
        : null;
    final manualCommand = page.settingsStore.settings.authToken.trim().isEmpty
        ? store.lastDaemonManualCommand
        : null;
    final online = tone == StatusTone.good && !transitioning;
    final scopeLabel = !online || focus == null
        ? null
        : focus!.isPrimary && focus!.roomId == null
        ? (strings.isZh ? '主网络' : 'Main network')
        : networkScopeLabel(strings, focus!);
    final deviceName = representative?.isPrimary == true
        ? page.settingsStore.settings.deviceName.trim()
        : '';
    final connection = Semantics(
      liveRegion: true,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          _ConnectionMark(
            tone: tone,
            accent: accent,
            transitioning: transitioning,
          ),
          const SizedBox(width: AppTokens.space12),
          Expanded(
            child: AppEntrance(
              identity: title,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Wrap(
                    spacing: AppTokens.space8,
                    runSpacing: AppTokens.space2,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Text(
                        title,
                        key: const Key('home-connection-heading'),
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(
                              color: online
                                  ? Theme.of(context).colorScheme.primary
                                  : null,
                              fontSize: 18,
                              fontWeight: FontWeight.w700,
                            ),
                      ),
                      if (scopeLabel != null && focus!.isPrimary)
                        _ConnectionScopeLabel(label: scopeLabel),
                    ],
                  ),
                  if (!online || ip == null)
                    Padding(
                      padding: const EdgeInsets.only(top: AppTokens.space4),
                      child: Text(
                        detail,
                        style: Theme.of(context).textTheme.bodySmall
                            ?.copyWith(color: colors.textSecondary),
                      ),
                    ),
                  if (ip != null)
                    Wrap(
                      spacing: AppTokens.space8,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        ip,
                        if (online && deviceName.isNotEmpty)
                          Text(
                            '·  $deviceName',
                            style: Theme.of(context).textTheme.bodySmall
                                ?.copyWith(color: colors.textSecondary),
                          ),
                      ],
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
    final commands = Wrap(
      spacing: AppTokens.space8,
      runSpacing: AppTokens.space8,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: actions,
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        DesktopCard(
          borderColor: online ? colors.successBorder : null,
          padding: const EdgeInsets.all(AppTokens.space16),
          child: ConstrainedBox(
            constraints: BoxConstraints(
              minHeight: MediaQuery.sizeOf(context).width < 900 ? 0 : 60,
            ),
            child: LayoutBuilder(
              builder: (context, constraints) {
                final scale = MediaQuery.textScalerOf(context).scale(13) / 13;
                if (actions.isEmpty) return connection;
                if (constraints.maxWidth >= 465 * scale &&
                    actions.length == 1 &&
                    !canStartPrimary) {
                  return Row(
                    children: [
                      Expanded(child: connection),
                      const SizedBox(width: AppTokens.space12),
                      commands,
                    ],
                  );
                }
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    connection,
                    const SizedBox(height: AppTokens.space8),
                    commands,
                  ],
                );
              },
            ),
          ),
        ),
        if (issue != null) ...[const SizedBox(height: AppTokens.space8), issue],
        if (primaryOnly && manualCommand != null) ...[
          const SizedBox(height: AppTokens.space8),
          _ManualCommandCard(command: manualCommand),
        ],
      ],
    );
  }

  (StatusTone, String, String) _connectionCopy(
    AppStrings strings, {
    required bool transitioning,
    required bool primaryOnly,
  }) {
    if (transitioning && primaryOnly) {
      final starting = store.daemonStarting;
      return (
        StatusTone.neutral,
        starting
            ? (strings.isZh ? '正在连接 P2WLAN' : 'Connecting to P2WLAN')
            : (strings.isZh ? '正在断开 P2WLAN' : 'Disconnecting P2WLAN'),
        starting ? strings.homeLoading : strings.daemonWorking,
      );
    }
    final scope = focus;
    if (scope == null) return networkOverviewStatus(strings, overview);
    if (!primaryOnly) {
      return (
        networkDisplayStateTone(scope.state),
        networkDisplayStateLabel(strings, scope.state),
        networkScopeLabel(strings, scope),
      );
    }
    return switch (scope.state) {
      NetworkDisplayState.running => (
        StatusTone.good,
        strings.isZh ? '本机网络已连接' : 'Local network connected',
        strings.homeJoinedSubtitle,
      ),
      NetworkDisplayState.attention => (
        StatusTone.warn,
        strings.needsAttention,
        strings.issueServiceStatusDetail,
      ),
      NetworkDisplayState.stale => (
        StatusTone.warn,
        strings.isZh ? '上次连接信息' : 'Last known connection',
        strings.homeStaleNote,
      ),
      NetworkDisplayState.unavailable => (
        StatusTone.warn,
        strings.issueStatusUnavailableTitle,
        strings.issueStatusUnavailableDetail,
      ),
      _ => (
        StatusTone.bad,
        strings.isZh ? 'P2WLAN 未运行' : 'P2WLAN is stopped',
        strings.homeStoppedDetail,
      ),
    };
  }

  Widget? _primaryIssue(AppStrings strings, NetworkDisplayState? state) {
    final failureCode = store.lastDaemonFailureCode;
    final failure = store.daemonBusy
        ? null
        : failureCode != null
        ? daemonStartupFailurePresentation(
            strings,
            DaemonCommandResult(
              ok: false,
              message: '',
              failureCode: failureCode,
            ),
          )
        : store.lastError == 'daemon_operation_failed'
        ? strings.daemonOperationFailed
        : null;
    final message =
        failure ??
        _dashboardIssueMessage(
          strings: strings,
          daemonAvailable: store.daemonReachable || store.statusReachable,
          snapshotStale: state == NetworkDisplayState.stale,
          statusReachable: store.statusReachable,
          statusError: store.lastStatusError,
          healthReachable: store.healthReachable,
          healthError: store.lastHealthError,
          error: store.lastError,
          snapshot: store.snapshot,
          startupCatalogSettling:
              store.startupCatalogSettling || store.daemonStarting,
        );
    if (message == null) return null;
    return _HomeIssueBanner(
      message: message,
      tone: failure == null ? StatusTone.warn : StatusTone.bad,
      onOpenTroubleshooting: page.onOpenTroubleshooting,
      onReauthenticate: store.snapshot?.health.reauthRequired == true
          ? page.onReauthenticate
          : null,
      primaryAction:
          failureCode !=
          DaemonStartupFailureCode.administratorAuthorizationCancelled,
    );
  }

  Widget? _roomIssue(AppStrings strings) {
    final issues = scopes.where(networkScopeNeedsAttention).toList();
    if (issues.isEmpty) return null;
    final issue = issues.first;
    final room = issue.roomId;
    final needsLogin = issue.snapshot?.health.reauthRequired == true;
    final message = room == null
        ? null
        : store.parallelRooms.session(room)?.message;
    final explanation = needsLogin
        ? strings.issueReauthRequired
        : message != null && message.trim().isNotEmpty
        ? RoomStrings(strings.isZh).runtimeText(message)
        : issue.state == NetworkDisplayState.stale
        ? strings.homeStaleNote
        : strings.issueServiceStatusDetail;
    return _HomeIssueBanner(
      key: const Key('home-room-issue'),
      title: networkScopeLabel(strings, issue),
      message: explanation,
      tone: StatusTone.warn,
      onReauthenticate: needsLogin ? page.onReauthenticate : null,
      onOpenTroubleshooting: room != null && page.onOpenRoom != null
          ? () => page.onOpenRoom!(room)
          : page.onOpenTroubleshooting,
      actionLabel: needsLogin && page.onReauthenticate != null
          ? null
          : room != null && page.onOpenRoom != null
          ? (strings.isZh ? '处理此房间' : 'Resolve this room')
          : strings.checkIssues,
      actionKey: const Key('home-resolve-room-issue'),
      primaryAction: true,
      compact: true,
    );
  }

  Future<void> _disconnectRoom(
    BuildContext context,
    NetworkScopeSnapshot scope,
  ) async {
    final rooms = store.parallelRooms;
    final room = scope.roomId;
    if (room == null || rooms.session(room)?.revision != scope.ownerRevision) {
      return;
    }
    final result = await rooms.disconnect(room);
    if (!context.mounted || result.ok) return;
    final strings = AppStringsScope.of(context);
    showAppNotice(
      context,
      content: Text(RoomStrings(strings.isZh).runtimeText(result.message)),
    );
  }
}

class _ConnectionMark extends StatelessWidget {
  const _ConnectionMark({
    required this.tone,
    required this.accent,
    required this.transitioning,
  });

  final StatusTone tone;
  final Color accent;
  final bool transitioning;

  @override
  Widget build(BuildContext context) {
    if (tone == StatusTone.good && !transitioning) {
      return const _ConnectedPulse();
    }
    final icon = switch (tone) {
      StatusTone.good => Icons.check_rounded,
      StatusTone.warn => Icons.priority_high_rounded,
      StatusTone.bad => Icons.link_off_rounded,
      StatusTone.neutral => Icons.hub_outlined,
    };
    return ExcludeSemantics(
      child: AnimatedContainer(
        duration: AppMotion.durationOf(context),
        curve: AppMotion.curve,
        width: AppTokens.space40,
        height: AppTokens.space40,
        decoration: BoxDecoration(
          color: accent.withValues(alpha: 0.09),
          border: Border.all(color: accent.withValues(alpha: 0.20)),
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        ),
        child: Center(
          child: transitioning && !MediaQuery.disableAnimationsOf(context)
              ? _ButtonSpinner(color: accent)
              : Icon(icon, color: accent, size: AppTokens.iconMd),
        ),
      ),
    );
  }
}

class _ConnectionScopeLabel extends StatelessWidget {
  const _ConnectionScopeLabel({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        color: colors.selectedSurface,
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        child: Text(
          label,
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: colors.successText,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }
}

/// The solid connection dot stays still; only the halo breathes. Leave a
/// short rest between cycles so an idle page does not schedule every frame.
class _ConnectedPulse extends StatefulWidget {
  const _ConnectedPulse();

  @override
  State<_ConnectedPulse> createState() => _ConnectedPulseState();
}

class _ConnectedPulseState extends State<_ConnectedPulse>
    with SingleTickerProviderStateMixin {
  static const _sweep = Duration(milliseconds: 900);
  static const _cycle = Duration(milliseconds: 2450);
  late final AnimationController _halo = AnimationController(
    vsync: this,
    duration: _sweep,
  );
  Timer? _timer;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final animate =
        !MediaQuery.disableAnimationsOf(context) &&
        TickerMode.valuesOf(context).enabled;
    if (!animate) {
      _timer?.cancel();
      _timer = null;
      _halo.reset();
    } else if (_timer == null) {
      _breath();
      _timer = Timer.periodic(_cycle, (_) => _breath());
    }
  }

  void _breath() {
    _halo.value = 0;
    _halo.repeat(reverse: true, count: 2);
  }

  @override
  void dispose() {
    _timer?.cancel();
    _halo.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    return ExcludeSemantics(
      child: RepaintBoundary(
        child: SizedBox.square(
          dimension: 38,
          child: Stack(
            alignment: Alignment.center,
            children: [
              DecoratedBox(
                decoration: BoxDecoration(
                  color: colors.successSurface,
                  shape: BoxShape.circle,
                ),
                child: const SizedBox.expand(),
              ),
              AnimatedBuilder(
                animation: _halo,
                builder: (context, _) {
                  final fraction = Curves.easeInOut.transform(_halo.value);
                  return DecoratedBox(
                    key: const Key('home-connection-halo'),
                    decoration: BoxDecoration(
                      color: Color.lerp(
                        colors.successBorder,
                        colors.selectedSurface,
                        fraction,
                      ),
                      shape: BoxShape.circle,
                    ),
                    child: SizedBox.square(dimension: 19 + 8 * fraction),
                  );
                },
              ),
              DecoratedBox(
                key: const Key('home-connection-solid-dot'),
                decoration: BoxDecoration(
                  color: colors.successDot,
                  shape: BoxShape.circle,
                ),
                child: const SizedBox.square(dimension: 11),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _DesktopGhostDanger extends StatelessWidget {
  const _DesktopGhostDanger({
    super.key,
    required this.onPressed,
    required this.label,
    this.pending = false,
  });

  final VoidCallback? onPressed;
  final String label;
  final bool pending;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    return TextButton.icon(
      onPressed: onPressed,
      style: ButtonStyle(
        minimumSize: const WidgetStatePropertyAll(
          Size(64, AppTokens.desktopControlHeight),
        ),
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        foregroundColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.disabled)) return colors.textMuted;
          if (states.contains(WidgetState.hovered)) return colors.dangerText;
          return colors.textSecondary;
        }),
        overlayColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.hovered)) return colors.dangerSurface;
          if (states.contains(WidgetState.focused)) {
            return colors.selectedSurface;
          }
          if (states.contains(WidgetState.pressed)) return colors.surfaceMuted;
          return Colors.transparent;
        }),
        shape: WidgetStatePropertyAll(
          RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
        ),
      ),
      icon: Builder(
        builder: (context) {
          final color = IconTheme.of(context).color;
          return pending
              ? _ButtonSpinner(color: color ?? colors.textMuted)
              : DesktopIcon('power', size: AppTokens.iconSm, color: color);
        },
      ),
      label: Text(label),
    );
  }
}

class _DesktopOnlineDevices extends StatelessWidget {
  const _DesktopOnlineDevices({
    required this.peers,
    required this.onOpenDevices,
    required this.onOpenPeer,
    required this.onDiagnostics,
    required this.scopeLabels,
    required this.hasCurrentData,
  });

  final List<NetworkPeerSnapshot> peers;
  final VoidCallback? onOpenDevices;
  final VoidCallback? Function(NetworkPeerSnapshot) onOpenPeer;
  final ValueChanged<NetworkPeerSnapshot> onDiagnostics;
  final bool scopeLabels;
  final bool hasCurrentData;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return DesktopCard(
      key: const Key('home-devices-panel'),
      padding: EdgeInsets.fromLTRB(
        16,
        MediaQuery.sizeOf(context).width < 900 ? 8 : 12,
        16,
        8,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Semantics(
                header: true,
                child: Text(
                  strings.isZh ? '在线设备' : 'Online devices',
                  style: theme.textTheme.titleMedium,
                ),
              ),
              if (onOpenDevices != null)
                TextButton.icon(
                  key: const Key('home-view-all-devices'),
                  onPressed: onOpenDevices,
                  label: Text(strings.openDevices),
                  icon: const Icon(
                    Icons.arrow_forward_rounded,
                    size: AppTokens.iconSm,
                  ),
                  iconAlignment: IconAlignment.end,
                ),
            ],
          ),
          if (peers.isEmpty)
            DecoratedBox(
              decoration: BoxDecoration(
                border: Border(top: BorderSide(color: colors.divider)),
              ),
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  vertical: AppTokens.space20,
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      Icons.devices_outlined,
                      size: AppTokens.iconMd,
                      color: colors.textMuted,
                    ),
                    const SizedBox(width: AppTokens.space12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            hasCurrentData
                                ? strings.noDevicesOnline
                                : strings.unavailable,
                            style: theme.textTheme.titleSmall,
                          ),
                          const SizedBox(height: AppTokens.space4),
                          Text(
                            hasCurrentData
                                ? strings.noDevicesOnlineDetail
                                : (strings.isZh
                                      ? '连接网络后可查看在线设备。'
                                      : 'Online devices appear once the network is connected.'),
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: colors.textSecondary,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            )
          else ...[
            const DesktopDeviceListHeader(),
            Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                for (final item in peers)
                  TweenAnimationBuilder<double>(
                    key: ValueKey(item.identity),
                    tween: Tween(begin: 0.86, end: 1),
                    duration: AppMotion.feedbackDurationOf(context),
                    curve: AppMotion.curve,
                    builder: (context, value, child) =>
                        Opacity(opacity: value, child: child),
                    child: DesktopDeviceRow(
                      item: item,
                      rowKey: Key('home-device-row-${item.identity}'),
                      scopeLabel: scopeLabels
                          ? item.roomName ??
                                (strings.isZh ? '当前网络' : 'Current network')
                          : null,
                      onOpen: onOpenPeer(item),
                      onDiagnostics: () => onDiagnostics(item),
                    ),
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}
