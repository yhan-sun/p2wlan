part of '../nodes_page.dart';

class _DetailLine extends StatelessWidget {
  const _DetailLine({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final labelText = Text(
            label,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          );
          final valueText = SelectableText(
            value,
            style: TextStyle(
              fontSize: 12,
              color: theme.colorScheme.onSurface,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          );
          if (constraints.maxWidth < 340) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [labelText, const SizedBox(height: 3), valueText],
            );
          }
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: 96, child: labelText),
              Expanded(child: valueText),
            ],
          );
        },
      ),
    );
  }
}

class _PathBadge extends StatelessWidget {
  const _PathBadge({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final tone = _peerNeedsAttention(peer)
        ? StatusTone.warn
        : switch (peer.path) {
            'direct' => StatusTone.good,
            'relay' => StatusTone.neutral,
            'direct_trial' || 'probing' => StatusTone.warn,
            _ => StatusTone.neutral,
          };
    return StatusBadge(
      label: _connectionLabel(stringsOf(context), peer),
      tone: tone,
    );
  }
}

/// Shared device detail content used by the expanded detail pane, the medium
/// dialog, and the compact full-screen detail. Information is grouped by
/// section instead of a flat list of every field.
class _PeerDetailsContent extends StatelessWidget {
  const _PeerDetailsContent({
    required this.peer,
    required this.strings,
    this.copiedKey,
    this.busy = false,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final String? copiedKey;
  final bool busy;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final error = peer.lastError?.trim();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _DetailHeader(peer: peer, strings: strings),
        const SizedBox(height: 12),
        const Divider(height: 1),
        const SizedBox(height: 12),
        _DetailSection(
          title: strings.sectionConnection,
          rows: [
            _DetailLine(
              label: strings.latency,
              value: formatLatency(peer.latencyMs),
            ),
            _DetailLine(
              label: strings.connectionType,
              value: _connectionLabel(strings, peer),
            ),
            _DetailLine(
              label: strings.onlineState,
              value: peer.online ? strings.online : strings.offline,
            ),
            _DetailLine(label: strings.lastSeen, value: _formatLastSeen(peer)),
          ],
        ),
        _DetailSection(
          title: strings.sectionNetwork,
          rows: [
            _DetailLine(label: strings.virtualIp, value: dash(peer.virtualIp)),
            _DetailLine(label: strings.endpoint, value: dash(peer.endpoint)),
            _DetailLine(label: strings.relay, value: dash(peer.relayServer)),
            if (peer.currentPathSelection?.reason.isNotEmpty == true)
              _DetailLine(
                label: strings.pathDecision,
                value: peer.currentPathSelection!.reason,
              ),
          ],
        ),
        _DetailSection(
          title: strings.sectionDevice,
          rows: [
            _DetailLine(label: strings.nodeId, value: peer.nodeId),
            _DetailLine(
              label: strings.isZh ? '版本' : 'Version',
              value: dash(peer.appVersion),
            ),
            _DetailLine(label: strings.state, value: dash(peer.state)),
          ],
        ),
        if (error != null && error.isNotEmpty) ...[
          _DetailSection(
            title: strings.sectionIssues,
            rows: [_DetailIssueNote(message: error, strings: strings)],
          ),
        ],
        const SizedBox(height: 4),
        const Divider(height: 1),
        const SizedBox(height: 12),
        _DetailActions(
          peer: peer,
          strings: strings,
          copiedKey: copiedKey,
          busy: busy,
          onCopy: onCopy,
          onEdit: onEdit,
          onDelete: onDelete,
          onSpeedTest: onSpeedTest,
        ),
      ],
    );
  }
}

class _DetailHeader extends StatelessWidget {
  const _DetailHeader({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final onlineColor = theme.brightness == Brightness.dark
        ? AppTokens.colorDarkGoodText
        : AppTokens.colorGoodText;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
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
                        color: theme.colorScheme.onSurface,
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    peer.online ? strings.online : strings.offline,
                    style: TextStyle(
                      color: peer.online
                          ? onlineColor
                          : theme.colorScheme.onSurfaceVariant,
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                dash(peer.virtualIp),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(width: 10),
        _PathBadge(peer: peer),
      ],
    );
  }
}

class _DetailSection extends StatelessWidget {
  const _DetailSection({required this.title, required this.rows});

  final String title;
  final List<Widget> rows;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w800,
              letterSpacing: 0.4,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 4),
          ...rows,
        ],
      ),
    );
  }
}

class _DetailIssueNote extends StatelessWidget {
  const _DetailIssueNote({required this.message, required this.strings});

  final String message;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: isDark ? AppTokens.colorDarkWarnBg : AppTokens.colorWarnBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(
          color: isDark
              ? AppTokens.colorDarkWarnBorder
              : AppTokens.colorWarnBorder,
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            Icons.warning_amber_rounded,
            size: 17,
            color: isDark
                ? AppTokens.colorDarkWarnText
                : AppTokens.colorWarnText,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: SelectableText(
              message,
              style: TextStyle(
                fontSize: 12,
                height: 1.35,
                color: isDark
                    ? AppTokens.colorDarkWarnText
                    : AppTokens.colorWarnText,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _DetailActions extends StatelessWidget {
  const _DetailActions({
    required this.peer,
    required this.strings,
    this.copiedKey,
    this.busy = false,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final String? copiedKey;
  final bool busy;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final ipCopied = copiedKey == ipKey;
    final pingCopied = copiedKey == pingKey;
    final primaryActions = Wrap(
      spacing: 8,
      runSpacing: 8,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        FilledButton.tonalIcon(
          key: Key('node-detail-speedtest-${peer.nodeId}'),
          onPressed: _canRunSpeedTest(peer) && onSpeedTest != null
              ? () => onSpeedTest!(peer)
              : null,
          icon: const Icon(Icons.speed_rounded, size: 17),
          label: Text(strings.speedTest),
        ),
        if (onCopy != null) ...[
          OutlinedButton.icon(
            onPressed: () => onCopy!(peer.virtualIp, ipKey),
            icon: Icon(
              ipCopied ? Icons.check_circle_outline : Icons.copy_outlined,
              size: 16,
            ),
            label: Text(strings.copyVirtualIp),
          ),
          OutlinedButton.icon(
            onPressed: () => onCopy!('ping ${peer.virtualIp}', pingKey),
            icon: Icon(
              pingCopied ? Icons.check_circle_outline : Icons.terminal_outlined,
              size: 16,
            ),
            label: Text(strings.copyPingCommand),
          ),
        ],
        if (onEdit != null)
          OutlinedButton.icon(
            onPressed: busy ? null : () => onEdit!(peer),
            icon: const Icon(Icons.edit_outlined, size: 16),
            label: Text(strings.renameDevice),
          ),
      ],
    );
    final remove = onDelete == null
        ? null
        : Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              onPressed: busy ? null : () => onDelete!(peer),
              icon: Icon(
                Icons.delete_outline_rounded,
                size: 16,
                color: theme.colorScheme.error,
              ),
              label: Text(
                strings.removeDevice,
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ),
          );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        primaryActions,
        if (remove != null) ...[const SizedBox(height: 6), remove],
      ],
    );
  }
}

/// Expanded-layout right-hand detail pane.
class _PeerDetailPane extends StatelessWidget {
  const _PeerDetailPane({
    super.key,
    required this.peer,
    required this.strings,
    this.copiedKey,
    this.busyPeerId,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot? peer;
  final AppStrings strings;
  final String? copiedKey;
  final String? busyPeerId;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final current = peer;
    if (current == null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            strings.noSelectionHint,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
            ),
          ),
        ),
      );
    }
    return _PeerDetailsContent(
      peer: current,
      strings: strings,
      copiedKey: copiedKey,
      busy: busyPeerId == current.nodeId,
      onCopy: onCopy,
      onEdit: onEdit,
      onDelete: onDelete,
      onSpeedTest: onSpeedTest,
    );
  }
}

/// Medium-layout detail dialog (also the desktop fallback from the actions
/// menu). Shares the same content as the expanded pane and mobile detail.
class _PeerDetailsDialog extends StatelessWidget {
  const _PeerDetailsDialog({
    required this.peer,
    required this.strings,
    this.copiedKey,
    this.busyPeerId,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final String? copiedKey;
  final String? busyPeerId;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final size = MediaQuery.sizeOf(context);
    final usableWidth = size.width > 64 ? size.width - 32 : size.width;
    final usableHeight = size.height > 96 ? size.height - 48 : size.height;
    final dialogWidth = usableWidth < 520 ? usableWidth : 520.0;
    final maxDialogHeight = usableHeight < 620 ? usableHeight : 620.0;

    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
      backgroundColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: dialogWidth,
          maxHeight: maxDialogHeight,
        ),
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            border: Border.all(color: theme.colorScheme.outlineVariant),
            boxShadow: AppTokens.shadowBorder,
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(18, 14, 10, 8),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          dash(peer.displayName),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: theme.colorScheme.onSurface,
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                      IconButton(
                        tooltip: strings.cancel,
                        onPressed: () => Navigator.of(context).pop(),
                        icon: const Icon(Icons.close_rounded, size: 20),
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1),
                Flexible(
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.fromLTRB(18, 12, 18, 14),
                    child: _PeerDetailsContent(
                      peer: peer,
                      strings: strings,
                      copiedKey: copiedKey,
                      busy: busyPeerId == peer.nodeId,
                      onCopy: onCopy,
                      onEdit: onEdit,
                      onDelete: onDelete == null
                          ? null
                          : (selected) => _closeDetailOnRemoved(
                              context,
                              () => onDelete!(selected),
                            ),
                      onSpeedTest: onSpeedTest,
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
}

/// Compact full-screen device detail that behaves like a mobile detail page.
class _MobilePeerDetails extends StatelessWidget {
  const _MobilePeerDetails({
    required this.peer,
    required this.strings,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      key: const Key('nodes-mobile-detail'),
      appBar: AppBar(
        title: Text(
          dash(peer.displayName),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(18, 16, 18, 24),
          children: [
            _PeerDetailsContent(
              peer: peer,
              strings: strings,
              onCopy: onCopy,
              onEdit: onEdit,
              onDelete: onDelete == null
                  ? null
                  : (selected) => _closeDetailOnRemoved(
                      context,
                      () => onDelete!(selected),
                    ),
              onSpeedTest: onSpeedTest,
            ),
          ],
        ),
      ),
    );
  }
}

/// Closes the enclosing detail surface (dialog or mobile route) only when the
/// remove operation actually succeeded. Cancelling or a failed deletion keeps
/// the detail open. Returns whether the device was removed.
Future<bool> _closeDetailOnRemoved(
  BuildContext context,
  Future<bool> Function() remove,
) async {
  final removed = await remove();
  if (removed && context.mounted) {
    Navigator.of(context).pop();
  }
  return removed;
}
