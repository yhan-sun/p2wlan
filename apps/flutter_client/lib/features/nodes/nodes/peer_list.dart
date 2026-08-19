part of '../nodes_page.dart';

class _PeerList extends StatelessWidget {
  const _PeerList({
    required this.peers,
    required this.showGroups,
    this.selectedPeerId,
    required this.copiedKey,
    required this.busyPeerId,
    required this.compact,
    required this.onCopy,
    required this.onEdit,
    required this.onDelete,
    required this.onSpeedTest,
    required this.onTap,
  });

  final List<PeerSnapshot> peers;
  final bool showGroups;
  final String? selectedPeerId;
  final String? copiedKey;
  final String? busyPeerId;
  final bool compact;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<bool> Function(PeerSnapshot peer) onDelete;
  final Future<void> Function(PeerSnapshot peer) onSpeedTest;
  final ValueChanged<PeerSnapshot> onTap;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final groups = showGroups ? _buildPeerGroups(peers, strings) : null;
    final items = <_PeerListItem>[
      if (groups != null)
        for (final group in groups) ...[
          _PeerListItem.group(group),
          for (final peer in group.peers) _PeerListItem.peer(peer),
        ]
      else
        for (final peer in peers) _PeerListItem.peer(peer),
    ];
    return Column(
      children: [
        for (final item in items)
          if (item.group != null)
            _PeerGroupHeader(group: item.group!)
          else
            _PeerListRow(
              peer: item.peer!,
              strings: strings,
              compact: compact,
              selected: selectedPeerId == item.peer!.nodeId,
              copiedKey: copiedKey,
              busy: busyPeerId == item.peer!.nodeId,
              onCopy: onCopy,
              onEdit: onEdit,
              onDelete: onDelete,
              onSpeedTest: onSpeedTest,
              onTap: onTap,
            ),
      ],
    );
  }
}

class _PeerListItem {
  const _PeerListItem.group(this.group) : peer = null;
  const _PeerListItem.peer(this.peer) : group = null;

  final _PeerGroup? group;
  final PeerSnapshot? peer;
}

class _PeerGroup {
  const _PeerGroup({
    required this.title,
    required this.tone,
    required this.peers,
  });

  final String title;
  final StatusTone tone;
  final List<PeerSnapshot> peers;
}

class _PeerGroupHeader extends StatelessWidget {
  const _PeerGroupHeader({required this.group});

  final _PeerGroup group;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      key: Key('nodes-group-${group.title.hashCode}'),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        border: Border(
          bottom: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
        borderRadius: const BorderRadius.vertical(
          top: Radius.circular(AppTokens.radiusSm),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              group.title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          const SizedBox(width: AppTokens.space8),
          StatusBadge(label: formatInt(group.peers.length), tone: group.tone),
        ],
      ),
    );
  }
}

class _PeerListRow extends StatelessWidget {
  const _PeerListRow({
    required this.peer,
    required this.strings,
    required this.compact,
    required this.selected,
    required this.copiedKey,
    required this.busy,
    required this.onCopy,
    required this.onEdit,
    required this.onDelete,
    required this.onSpeedTest,
    required this.onTap,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool compact;
  final bool selected;
  final String? copiedKey;
  final bool busy;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<bool> Function(PeerSnapshot peer) onDelete;
  final Future<void> Function(PeerSnapshot peer) onSpeedTest;
  final ValueChanged<PeerSnapshot> onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final menu = _actionsMenu(ipKey, pingKey);
    final speedTestAction = _speedTestAction();
    final rowColor = selected
        ? P2WlanColors.of(context).selectedSurface
        : theme.colorScheme.surface;
    return Material(
      color: rowColor,
      child: InkWell(
        key: Key('node-row-${peer.nodeId}'),
        onTap: () => onTap(peer),
        child: Container(
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(color: theme.colorScheme.outlineVariant),
            ),
          ),
          child: IntrinsicHeight(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Container(
                  width: 3,
                  color: selected
                      ? theme.colorScheme.primary
                      : Colors.transparent,
                ),
                Expanded(
                  child: Padding(
                    padding: EdgeInsets.symmetric(
                      horizontal: 14,
                      vertical: compact ? 8 : 6,
                    ),
                    child: compact
                        ? _CompactRowContent(
                            peer: peer,
                            strings: strings,
                            speedTestAction: speedTestAction,
                            menu: menu,
                          )
                        : _RowContent(
                            peer: peer,
                            strings: strings,
                            speedTestAction: speedTestAction,
                            menu: menu,
                          ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _actionsMenu(String ipKey, String pingKey) {
    if (busy) {
      return SizedBox.square(
        dimension: AppTokens.minTouchTarget,
        child: const Center(child: _TinySpinner()),
      );
    }
    return SizedBox.square(
      dimension: AppTokens.minTouchTarget,
      child: PopupMenuButton<String>(
        padding: EdgeInsets.zero,
        iconSize: 20,
        tooltip: strings.deviceActions,
        onSelected: (value) {
          switch (value) {
            case 'copy_ip':
              onCopy(peer.virtualIp, ipKey);
              break;
            case 'copy_ping':
              onCopy('ping ${peer.virtualIp}', pingKey);
              break;
            case 'edit':
              onEdit(peer);
              break;
            case 'delete':
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onDelete(peer);
              });
              break;
            case 'details':
              onTap(peer);
              break;
            case 'speed_test':
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onSpeedTest(peer);
              });
              break;
          }
        },
        itemBuilder: (context) => [
          PopupMenuItem(value: 'details', child: Text(strings.viewDetails)),
          PopupMenuItem(
            key: ValueKey('node-speedtest-action-${peer.nodeId}'),
            value: 'speed_test',
            enabled: _canRunSpeedTest(peer),
            child: Text(strings.speedTest),
          ),
          PopupMenuItem(value: 'copy_ip', child: Text(strings.copyVirtualIp)),
          PopupMenuItem(
            value: 'copy_ping',
            child: Text(strings.copyPingCommand),
          ),
          PopupMenuItem(value: 'edit', child: Text(strings.renameDevice)),
          PopupMenuItem(value: 'delete', child: Text(strings.removeDevice)),
        ],
      ),
    );
  }

  Widget _speedTestAction() {
    return SizedBox.square(
      dimension: AppTokens.minTouchTarget,
      child: IconButton(
        key: Key('node-speedtest-button-${peer.nodeId}'),
        tooltip: strings.speedTestTooltip,
        onPressed: _canRunSpeedTest(peer) ? () => onSpeedTest(peer) : null,
        icon: const Icon(Icons.speed_rounded, size: 19),
      ),
    );
  }
}

class _RowContent extends StatelessWidget {
  const _RowContent({
    required this.peer,
    required this.strings,
    required this.speedTestAction,
    required this.menu,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final Widget speedTestAction;
  final Widget menu;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          flex: 3,
          child: _PeerPrimaryText(peer: peer, strings: strings),
        ),
        const SizedBox(width: AppTokens.space12),
        SizedBox(
          width: 92,
          child: Align(
            alignment: Alignment.centerRight,
            child: _LatencyText(peer: peer),
          ),
        ),
        const SizedBox(width: AppTokens.space12),
        SizedBox(
          width: 116,
          child: Align(
            alignment: Alignment.centerRight,
            child: _PathBadge(peer: peer, strings: strings),
          ),
        ),
        const SizedBox(width: AppTokens.space4),
        speedTestAction,
        menu,
      ],
    );
  }
}

class _CompactRowContent extends StatelessWidget {
  const _CompactRowContent({
    required this.peer,
    required this.strings,
    required this.speedTestAction,
    required this.menu,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final Widget speedTestAction;
  final Widget menu;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: _PeerPrimaryText(peer: peer, strings: strings),
            ),
            const SizedBox(width: AppTokens.space8),
            speedTestAction,
            menu,
          ],
        ),
        const SizedBox(height: AppTokens.space6),
        Row(
          children: [
            _LatencyText(peer: peer),
            const SizedBox(width: AppTokens.space10),
            Expanded(
              child: Align(
                alignment: Alignment.centerRight,
                child: _PathBadge(peer: peer, strings: strings),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _LatencyText extends StatelessWidget {
  const _LatencyText({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Text(
      formatLatency(peer.latencyMs),
      textAlign: TextAlign.right,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        fontSize: 12,
        fontWeight: FontWeight.w700,
        color: theme.colorScheme.onSurfaceVariant,
        fontFeatures: AppTokens.tabularFontFeatures,
      ),
    );
  }
}

class _TinySpinner extends StatelessWidget {
  const _TinySpinner();

  @override
  Widget build(BuildContext context) {
    return const SizedBox.square(
      dimension: 16,
      child: CircularProgressIndicator(strokeWidth: 2),
    );
  }
}

class _PeerPrimaryText extends StatelessWidget {
  const _PeerPrimaryText({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final error = peer.lastError?.trim();
    final detail = peer.appVersion.trim().isEmpty
        ? dash(peer.virtualIp)
        : '${dash(peer.virtualIp)} · v${peer.appVersion.trim()}';
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Flexible(
              child: Text(
                dash(peer.displayName),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 13.5,
                  fontWeight: FontWeight.w700,
                  color: theme.colorScheme.onSurface,
                ),
              ),
            ),
            if (error != null && error.isNotEmpty) ...[
              const SizedBox(width: AppTokens.space6),
              Tooltip(
                message: error,
                child: Icon(
                  Icons.warning_amber_rounded,
                  size: 15,
                  color: P2WlanColors.of(context).probing,
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: AppTokens.space4),
        Text(
          detail,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: theme.colorScheme.onSurfaceVariant,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}

/// Distinct empty states: no devices in the network, no search results, or no
/// filter results — never a single generic "no peers" message.
class _NodesEmptyState extends StatelessWidget {
  const _NodesEmptyState({
    required this.icon,
    required this.title,
    required this.body,
    this.actionLabel,
    this.onAction,
  });

  final IconData icon;
  final String title;
  final String body;
  final String? actionLabel;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 34, color: theme.colorScheme.onSurfaceVariant),
            const SizedBox(height: AppTokens.space10),
            Text(
              title,
              textAlign: TextAlign.center,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 15,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: AppTokens.space4),
            Text(
              body,
              textAlign: TextAlign.center,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 13,
                height: 1.35,
              ),
            ),
            if (actionLabel != null && onAction != null) ...[
              const SizedBox(height: AppTokens.space12),
              OutlinedButton.icon(
                onPressed: onAction,
                icon: const Icon(Icons.clear_rounded, size: 17),
                label: Text(actionLabel!),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
