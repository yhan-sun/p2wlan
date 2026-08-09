part of '../nodes_page.dart';

class _PeerList extends StatelessWidget {
  const _PeerList({
    required this.peers,
    required this.copiedKey,
    required this.busyPeerId,
    required this.onCopy,
    required this.onDetails,
    required this.onEdit,
    required this.onDelete,
    required this.onSpeedTest,
  });

  final List<PeerSnapshot> peers;
  final String? copiedKey;
  final String? busyPeerId;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onDetails;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<void> Function(PeerSnapshot peer) onDelete;
  final Future<void> Function(PeerSnapshot peer) onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.isZh ? '其他设备' : 'Other devices',
      flushContent: true,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final compact = constraints.maxWidth < 430;
          final rowHeight = compact ? _compactRowHeight : _rowHeight;
          final maxBodyHeight = compact
              ? _compactMaxBodyHeight
              : _maxBodyHeight;
          final groups = _buildPeerGroups(peers, strings);
          final items = <_PeerListItem>[
            for (final group in groups) ...[
              _PeerListItem.group(group),
              for (final peer in group.peers) _PeerListItem.peer(peer),
            ],
          ];
          final contentHeight =
              (groups.length * _groupHeaderHeight) + (peers.length * rowHeight);
          final bodyHeight = contentHeight
              .clamp(rowHeight + _groupHeaderHeight, maxBodyHeight)
              .toDouble();
          return ClipRRect(
            borderRadius: const BorderRadius.only(
              bottomLeft: Radius.circular(AppTokens.radiusLg),
              bottomRight: Radius.circular(AppTokens.radiusLg),
            ),
            child: SizedBox(
              height: bodyHeight,
              child: ListView.builder(
                padding: EdgeInsets.zero,
                primary: false,
                itemCount: items.length,
                itemBuilder: (context, index) {
                  final item = items[index];
                  final group = item.group;
                  if (group != null) {
                    return SizedBox(
                      height: _groupHeaderHeight,
                      child: _PeerGroupHeader(group: group),
                    );
                  }
                  final peer = item.peer!;
                  return SizedBox(
                    height: rowHeight,
                    child: _PeerListRow(
                      peer: peer,
                      strings: strings,
                      shaded: index.isOdd,
                      compact: compact,
                      copiedKey: copiedKey,
                      busy: busyPeerId == peer.nodeId,
                      onCopy: onCopy,
                      onDetails: onDetails,
                      onEdit: onEdit,
                      onDelete: onDelete,
                      onSpeedTest: onSpeedTest,
                    ),
                  );
                },
              ),
            ),
          );
        },
      ),
    );
  }

  static const _rowHeight = 68.0;
  static const _maxBodyHeight = 456.0;
  static const _compactRowHeight = 96.0;
  static const _compactMaxBodyHeight = 520.0;
  static const _groupHeaderHeight = 34.0;
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
      padding: const EdgeInsets.symmetric(horizontal: 14),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        border: Border(
          bottom: BorderSide(color: theme.colorScheme.outlineVariant),
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
          const SizedBox(width: 8),
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
    required this.shaded,
    required this.compact,
    required this.copiedKey,
    required this.busy,
    required this.onCopy,
    required this.onDetails,
    required this.onEdit,
    required this.onDelete,
    required this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;
  final bool compact;
  final String? copiedKey;
  final bool busy;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onDetails;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<void> Function(PeerSnapshot peer) onDelete;
  final Future<void> Function(PeerSnapshot peer) onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final menu = _actionsMenu(ipKey, pingKey);
    final speedTestAction = _speedTestAction();
    final rowColor = shaded
        ? theme.colorScheme.surfaceContainerHighest
        : theme.colorScheme.surface;
    return Material(
      color: rowColor,
      child: InkWell(
        onTap: () => onDetails(peer),
        child: Container(
          padding: EdgeInsets.symmetric(
            horizontal: 14,
            vertical: compact ? 8 : 0,
          ),
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(color: theme.colorScheme.outlineVariant),
            ),
          ),
          child: compact
              ? Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Expanded(child: _PeerPrimaryText(peer: peer)),
                        const SizedBox(width: 8),
                        speedTestAction,
                        menu,
                      ],
                    ),
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        _LatencyText(peer: peer),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Align(
                            alignment: Alignment.centerRight,
                            child: _PathBadge(peer: peer),
                          ),
                        ),
                      ],
                    ),
                  ],
                )
              : Row(
                  children: [
                    Expanded(flex: 3, child: _PeerPrimaryText(peer: peer)),
                    const SizedBox(width: 12),
                    SizedBox(
                      width: 92,
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: _LatencyText(peer: peer),
                      ),
                    ),
                    const SizedBox(width: 12),
                    SizedBox(
                      width: 116,
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: _PathBadge(peer: peer),
                      ),
                    ),
                    const SizedBox(width: 4),
                    speedTestAction,
                    menu,
                  ],
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
        tooltip: strings.isZh ? '设备操作' : 'Device actions',
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
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onDetails(peer);
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
            value: 'details',
            child: Text(strings.isZh ? '查看详情' : 'View details'),
          ),
          PopupMenuItem(
            key: ValueKey('node-speedtest-action-${peer.nodeId}'),
            value: 'speed_test',
            enabled: _canRunSpeedTest(peer),
            child: Text(strings.speedTest),
          ),
          PopupMenuItem(
            value: 'copy_ip',
            child: Text(strings.isZh ? '复制虚拟 IP' : 'Copy virtual IP'),
          ),
          PopupMenuItem(
            value: 'copy_ping',
            child: Text(strings.isZh ? '复制 ping 命令' : 'Copy ping command'),
          ),
          PopupMenuItem(
            value: 'edit',
            child: Text(strings.isZh ? '修改名称' : 'Rename'),
          ),
          PopupMenuItem(
            value: 'delete',
            child: Text(strings.isZh ? '移除设备' : 'Remove device'),
          ),
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
  const _PeerPrimaryText({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final error = peer.lastError?.trim();
    final detail = error != null && error.isNotEmpty
        ? error
        : peer.appVersion.trim().isEmpty
        ? dash(peer.virtualIp)
        : '${dash(peer.virtualIp)} · v${peer.appVersion.trim()}';
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
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
        const SizedBox(height: 4),
        Text(
          detail,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: error != null && error.isNotEmpty
                ? theme.colorScheme.error
                : theme.colorScheme.onSurfaceVariant,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}

class _PeerActions extends StatelessWidget {
  const _PeerActions({
    required this.peer,
    required this.copiedKey,
    required this.onCopy,
    required this.onEdit,
  });

  final PeerSnapshot peer;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final ipCopied = copiedKey == ipKey;
    final pingCopied = copiedKey == pingKey;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconButton(
          tooltip: ipCopied
              ? (strings.isZh ? '已复制' : 'Copied')
              : (strings.isZh ? '复制虚拟 IP' : 'Copy virtual IP'),
          onPressed: () => onCopy(peer.virtualIp, ipKey),
          icon: Icon(
            ipCopied ? Icons.check_circle_outline : Icons.copy_outlined,
            size: 18,
          ),
        ),
        IconButton(
          tooltip: pingCopied
              ? (strings.isZh ? '已复制' : 'Copied')
              : (strings.isZh ? '复制 ping 命令' : 'Copy ping command'),
          onPressed: () => onCopy('ping ${peer.virtualIp}', pingKey),
          icon: Icon(
            pingCopied ? Icons.check_circle_outline : Icons.terminal_outlined,
            size: 18,
          ),
        ),
        IconButton(
          tooltip: strings.isZh ? '编辑设备' : 'Edit device',
          onPressed: () => onEdit(peer),
          icon: const Icon(Icons.edit_outlined, size: 18),
        ),
      ],
    );
  }
}
