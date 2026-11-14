part of '../dashboard_page.dart';

class _DesktopHomeDiagnostics extends StatelessWidget {
  const _DesktopHomeDiagnostics({
    super.key,
    required this.controller,
    required this.diagnosticPeer,
    required this.scopes,
    required this.peers,
    required this.representative,
    this.onOpenTroubleshooting,
    this.onOpenRoom,
    this.onOpenDevices,
  });

  final List<NetworkScopeSnapshot> scopes;
  final List<NetworkPeerSnapshot> peers;
  final ExpansibleController controller;
  final ValueNotifier<String?> diagnosticPeer;
  final NetworkScopeSnapshot? representative;
  final VoidCallback? onOpenTroubleshooting;
  final ValueChanged<String>? onOpenRoom;
  final VoidCallback? onOpenDevices;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final snapshot = representative?.isRunning == true
        ? representative!.snapshot
        : null;
    final roomSummary =
        scopes.length > 1 || scopes.any((scope) => !scope.isPrimary);
    final current = scopes.where((scope) => scope.isRunning).length;
    final confirmed = peers.where((item) => item.available).length;
    final summary = current == 0
        ? strings.unavailable
        : [
            if (snapshot != null)
              '${strings.componentControlServer} ${_controlStatusLabel(strings, snapshot)}',
            if (roomSummary)
              strings.isZh ? '$current 个网络运行中' : '$current active networks',
            if (peers.isNotEmpty)
              strings.isZh
                  ? '$confirmed / ${peers.length} 条链路已确认'
                  : '$confirmed / ${peers.length} verified paths',
          ].join(' · ');
    return Container(
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: colors.divider)),
      ),
      child: ExpansionTile(
        controller: controller,
        key: Key(
          roomSummary
              ? 'home-room-connections-details'
              : 'home-connection-details',
        ),
        tilePadding: EdgeInsets.zero,
        childrenPadding: const EdgeInsets.only(bottom: AppTokens.space16),
        minTileHeight: AppTokens.desktopControlHeight,
        shape: const Border(),
        collapsedShape: const Border(),
        expansionAnimationStyle: AppMotion.expansionStyleOf(context),
        leading: Icon(
          Icons.monitor_heart_outlined,
          color: colors.textSecondary,
          size: AppTokens.iconMd,
        ),
        title: Text(
          strings.isZh ? '连接诊断' : 'Connection diagnostics',
          style: theme.textTheme.titleSmall,
        ),
        subtitle: Text(
          summary,
          key: const Key('home-connection-details-summary'),
          style: theme.textTheme.bodySmall?.copyWith(
            color: colors.textSecondary,
          ),
        ),
        children: [
          if (roomSummary)
            for (final scope in scopes)
              if (!scope.isPrimary ||
                  scope.state != NetworkDisplayState.stopped)
                _DesktopDiagnosticScope(
                  scope: scope,
                  onOpen: scope.roomId != null && onOpenRoom != null
                      ? () => onOpenRoom!(scope.roomId!)
                      : scope.isPrimary
                      ? onOpenDevices
                      : null,
                ),
          if (snapshot != null) ...[
            _DesktopDiagnosticField(
              label: strings.componentControlServer,
              value: _controlStatusLabel(strings, snapshot),
            ),
            if (_overlayTone(snapshot) case final tone?)
              _DesktopDiagnosticField(
                label: strings.componentOverlayRoute,
                value: _overlayLabel(strings, tone),
              ),
          ],
          ValueListenableBuilder(
            valueListenable: diagnosticPeer,
            builder: (context, selectedId, _) => _DesktopPathDiagnostics(
              peers: peers,
              scopes: scopes,
              representative: snapshot,
              selectedId: selectedId,
              onSelected: (id) => diagnosticPeer.value = id,
            ),
          ),
          if (onOpenTroubleshooting != null)
            Align(
              alignment: AlignmentDirectional.centerStart,
              child: TextButton.icon(
                onPressed: onOpenTroubleshooting,
                icon: const Icon(
                  Icons.arrow_forward_rounded,
                  size: AppTokens.iconSm,
                ),
                iconAlignment: IconAlignment.end,
                label: Text(strings.isZh ? '打开故障排查' : 'Open Troubleshooting'),
              ),
            ),
        ],
      ),
    );
  }
}

class _DesktopDiagnosticScope extends StatelessWidget {
  const _DesktopDiagnosticScope({required this.scope, this.onOpen});

  final NetworkScopeSnapshot scope;
  final VoidCallback? onOpen;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final ip = scope.isRunning ? scope.snapshot?.virtualIp : null;
    return ListTile(
      key: Key('home-network-scope-${scope.id}'),
      dense: true,
      minTileHeight: AppTokens.desktopControlHeight,
      contentPadding: EdgeInsets.zero,
      title: Text(networkScopeLabel(strings, scope)),
      subtitle: Text(
        [
          networkDisplayStateLabel(strings, scope.state),
          if (ip != null && ip.isNotEmpty) ip,
        ].join(' · '),
        style: TextStyle(
          color: colors.textSecondary,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
      trailing: onOpen == null
          ? null
          : const Icon(Icons.chevron_right_rounded, size: AppTokens.iconMd),
      onTap: onOpen,
    );
  }
}

class _DesktopPathDiagnostics extends StatelessWidget {
  const _DesktopPathDiagnostics({
    required this.peers,
    required this.scopes,
    required this.representative,
    required this.selectedId,
    required this.onSelected,
  });

  final List<NetworkPeerSnapshot> peers;
  final List<NetworkScopeSnapshot> scopes;
  final DiagnosticsSnapshot? representative;
  final String? selectedId;
  final ValueChanged<String?> onSelected;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final item =
        peers.where((item) => item.identity == selectedId).firstOrNull ??
        peers.firstOrNull;
    final peer = item?.peer;
    final path = peer?.pathObservability;
    final relayReason = _relayFallbackReason(peer);
    final events =
        path?.transitions.reversed.take(4) ?? const <PathTransitionSnapshot>[];
    final nat =
        (item == null
                ? representative
                : scopes
                      .where((scope) => scope.id == item.scopeId)
                      .firstOrNull
                      ?.snapshot)
            ?.natProfile;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (item != null && peers.length > 1)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: AppTokens.space8),
            child: Align(
              alignment: AlignmentDirectional.centerStart,
              child: AppSelect<String>(
                key: const Key('home-diagnostic-peer'),
                value: item.identity,
                width: 360,
                tooltip: strings.isZh
                    ? '选择诊断设备'
                    : 'Select a device to diagnose',
                options: [
                  for (final candidate in peers)
                    AppSelectOption(
                      value: candidate.identity,
                      label: _diagnosticPeerLabel(candidate),
                    ),
                ],
                onChanged: onSelected,
              ),
            ),
          )
        else if (item != null)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: AppTokens.space8),
            child: Text(
              _diagnosticPeerLabel(item),
              style: theme.textTheme.titleSmall,
            ),
          ),
        _DesktopDiagnosticField(
          label: strings.natType,
          value: nat == null
              ? strings.unavailable
              : strings.natTraversalTypeCompactLabel(nat.displayTraversalType),
        ),
        _DesktopDiagnosticField(
          label: strings.isZh ? '当前通信路径' : 'Current path',
          value: peer == null
              ? strings.unavailable
              : _peerStatusLabel(strings, peer),
        ),
        _DesktopDiagnosticField(
          label: 'RTT',
          value: peer?.latencyMs == null
              ? strings.unavailable
              : formatLatency(peer!.latencyMs),
        ),
        _DesktopDiagnosticField(
          label: strings.isZh ? '抖动' : 'Jitter',
          value: peer?.jitterMs == null
              ? strings.unavailable
              : formatLatency(peer!.jitterMs),
        ),
        _DesktopDiagnosticField(
          label: strings.isZh ? '丢包' : 'Packet loss',
          value: strings.unavailable,
        ),
        _DesktopDiagnosticField(
          label: strings.isZh ? '打洞状态' : 'Hole punching',
          value: _punchState(strings, path?.directState),
        ),
        _DesktopDiagnosticField(
          label: strings.isZh ? '中继回退原因' : 'Relay fallback reason',
          value: relayReason == null
              ? strings.unavailable
              : _pathEventLabel(strings, relayReason),
        ),
        const SizedBox(height: AppTokens.space12),
        Text(
          strings.isZh ? '最近连接事件' : 'Recent connection events',
          style: theme.textTheme.titleSmall,
        ),
        const SizedBox(height: AppTokens.space4),
        if (events.isEmpty)
          Text(
            strings.unavailable,
            style: theme.textTheme.bodySmall?.copyWith(
              color: colors.textSecondary,
            ),
          )
        else
          for (final event in events)
            _DesktopDiagnosticField(
              label: _pathEventLabel(strings, event.eventKind),
              value: strings.isZh
                  ? '${formatElapsedTime(event.ageMs, isZh: true)}前'
                  : '${formatElapsedTime(event.ageMs)} ago',
            ),
        const SizedBox(height: AppTokens.space8),
      ],
    );
  }

  String _diagnosticPeerLabel(NetworkPeerSnapshot item) => [
    item.peer.displayName,
    if (item.roomName != null) item.roomName!,
    if (item.peer.virtualIp.isNotEmpty) item.peer.virtualIp,
  ].join(' · ');

  String? _relayFallbackReason(PeerSnapshot? peer) {
    if (peer == null || !peer.isRelayVerified) return null;
    final path = peer.pathObservability;
    final recordedReason = path.lastPathChangeReason;
    if (path.currentPath == 'relay' &&
        recordedReason != null &&
        recordedReason.isNotEmpty &&
        recordedReason != 'initial') {
      return _isRelayFallback(path.previousPath, recordedReason)
          ? recordedReason
          : null;
    }
    // transitionReason may describe a later observation without a path switch.
    // Only surface the reason of the actual transition to the current relay.
    for (final event in path.transitions.reversed) {
      if (event.decision != 'applied' ||
          event.previousPath == event.currentPath) {
        continue;
      }
      if (event.currentPath != 'relay') return null;
      final reason = event.reasonCode.trim();
      return reason.isNotEmpty && _isRelayFallback(event.previousPath, reason)
          ? reason
          : null;
    }
    return null;
  }

  bool _isRelayFallback(String? previousPath, String reason) =>
      previousPath == 'direct' ||
      reason == 'direct_first_deadline' ||
      reason == 'direct_path_failed';

  String _punchState(AppStrings strings, String? state) => switch (state) {
    'idle' => strings.isZh ? '空闲' : 'Idle',
    'probing' => strings.probing,
    'validating' => strings.isZh ? '正在验证' : 'Validating',
    'committed' => strings.isZh ? '已确认直连' : 'Direct path confirmed',
    _ => strings.unavailable,
  };

  String _pathEventLabel(AppStrings strings, String code) => switch (code) {
    'peer_online' => strings.isZh ? '设备上线' : 'Device came online',
    'peer_left' => strings.isZh ? '设备离线' : 'Device went offline',
    'direct_first_deadline' =>
      strings.isZh ? '等待直连超时' : 'Direct connection timed out',
    'direct_probe_started' => strings.isZh ? '开始直连探测' : 'Direct probe started',
    'direct_validation_started' =>
      strings.isZh ? '开始验证直连' : 'Direct validation started',
    'direct_committed' => strings.isZh ? '直连已确认' : 'Direct path confirmed',
    'direct_probe_failed' => strings.isZh ? '直连探测失败' : 'Direct probe failed',
    'direct_path_failed' => strings.isZh ? '直连链路失败' : 'Direct path failed',
    'relay_business_usable' =>
      strings.isZh ? '中继链路可用' : 'Relay path became usable',
    'relay_peer_confirmed' => strings.isZh ? '中继对端已确认' : 'Relay peer confirmed',
    'relay_health_observed' =>
      strings.isZh ? '已采样中继状态' : 'Relay health sampled',
    'relay_path_failed' => strings.isZh ? '中继链路失败' : 'Relay path failed',
    'network_generation_advanced' =>
      strings.isZh ? '网络环境变化' : 'Network changed',
    '' => strings.unavailable,
    _ => code.replaceAll('_', ' '),
  };
}

class _DesktopDiagnosticField extends StatelessWidget {
  const _DesktopDiagnosticField({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: AppTokens.space4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: colors.textSecondary,
              ),
            ),
          ),
          const SizedBox(width: AppTokens.space12),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.end,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
