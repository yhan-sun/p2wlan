part of '../nodes_page.dart';

/// One continuous device list. The recommended sort already structures the
/// set (attention → direct → relay → probing → offline), so no group headers
/// or per-group badges are needed on the first level.
class _PeerList extends StatelessWidget {
  const _PeerList({
    required this.peers,
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
    return Column(
      children: [
        for (var index = 0; index < peers.length; index++) ...[
          if (index > 0) const Divider(height: 1),
          _PeerListRow(
            peer: peers[index],
            strings: strings,
            compact: compact,
            selected: selectedPeerId == peers[index].nodeId,
            copiedKey: copiedKey,
            busy: busyPeerId == peers[index].nodeId,
            onCopy: onCopy,
            onEdit: onEdit,
            onDelete: onDelete,
            onSpeedTest: onSpeedTest,
            onTap: onTap,
          ),
        ],
      ],
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
    final rowColor = selected
        ? P2WlanColors.of(context).selectedSurface
        : Colors.transparent;
    return Material(
      color: rowColor,
      child: InkWell(
        key: Key('node-row-${peer.nodeId}'),
        onTap: () => onTap(peer),
        child: Padding(
          padding: EdgeInsets.symmetric(
            horizontal: 14,
            vertical: compact ? 11 : 9,
          ),
          child: compact
              ? _CompactRowContent(peer: peer, strings: strings)
              : _RowContent(
                  peer: peer,
                  strings: strings,
                  busy: busy,
                  copiedKey: copiedKey,
                  onCopy: onCopy,
                  onEdit: onEdit,
                  onDelete: onDelete,
                  onSpeedTest: onSpeedTest,
                ),
        ),
      ),
    );
  }
}

/// Desktop row: status dot, name + IP, path, latency, overflow menu. Only the
/// judgment columns — nothing technical on the first level.
class _RowContent extends StatelessWidget {
  const _RowContent({
    required this.peer,
    required this.strings,
    required this.busy,
    required this.copiedKey,
    required this.onCopy,
    required this.onEdit,
    required this.onDelete,
    required this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool busy;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<bool> Function(PeerSnapshot peer) onDelete;
  final Future<void> Function(PeerSnapshot peer) onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final ipKey = '${peer.nodeId}:ip';
    final menu = _actionsMenu(ipKey);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _StatusDot(peer: peer),
        const SizedBox(width: AppTokens.space10),
        Expanded(
          child: _PeerPrimaryText(peer: peer, strings: strings),
        ),
        const SizedBox(width: AppTokens.space12),
        SizedBox(
          width: 76,
          child: Align(
            alignment: Alignment.centerRight,
            child: _PathText(peer: peer, strings: strings),
          ),
        ),
        const SizedBox(width: AppTokens.space12),
        SizedBox(
          width: 56,
          child: Align(
            alignment: Alignment.centerRight,
            child: _LatencyText(peer: peer),
          ),
        ),
        const SizedBox(width: AppTokens.space4),
        menu,
      ],
    );
  }

  Widget _actionsMenu(String ipKey) {
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
            case 'edit':
              onEdit(peer);
              break;
            case 'delete':
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onDelete(peer);
              });
              break;
            case 'speed_test':
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onSpeedTest(peer);
              });
              break;
          }
        },
        itemBuilder: (context) => [
          PopupMenuItem(
            key: ValueKey('node-speedtest-action-${peer.nodeId}'),
            value: 'speed_test',
            enabled: _canRunSpeedTest(peer),
            child: Text(strings.speedTest),
          ),
          PopupMenuItem(value: 'copy_ip', child: Text(strings.copyVirtualIp)),
          PopupMenuItem(value: 'edit', child: Text(strings.renameDevice)),
          PopupMenuItem(value: 'delete', child: Text(strings.removeDevice)),
        ],
      ),
    );
  }
}

/// Mobile row: status dot, name, IP, and a right-aligned "path · latency"
/// summary. Actions live on the full-screen detail page, keeping the row
/// dense and whole-row tappable.
class _CompactRowContent extends StatelessWidget {
  const _CompactRowContent({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _StatusDot(peer: peer),
        const SizedBox(width: AppTokens.space10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                dash(peer.displayName),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 13.5,
                  fontWeight: FontWeight.w700,
                  color: theme.colorScheme.onSurface,
                ),
              ),
              const SizedBox(height: 3),
              Text(
                dash(peer.virtualIp),
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
          ),
        ),
        const SizedBox(width: AppTokens.space10),
        Text(
          _pathSummaryLabel(strings, peer),
          maxLines: 1,
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

class _StatusDot extends StatelessWidget {
  const _StatusDot({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(
        color: _rowStatusColor(context, peer),
        shape: BoxShape.circle,
      ),
    );
  }
}

class _PathText extends StatelessWidget {
  const _PathText({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final label = _rowPathLabel(strings, peer);
    return Text(
      label,
      textAlign: TextAlign.right,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        fontSize: 12,
        fontWeight: FontWeight.w600,
        color: _peerIsOffline(peer)
            ? theme.colorScheme.onSurfaceVariant
            : theme.colorScheme.onSurface,
        fontFeatures: AppTokens.tabularFontFeatures,
      ),
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
    return Column(
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
        const SizedBox(height: 3),
        Text(
          dash(peer.virtualIp),
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
