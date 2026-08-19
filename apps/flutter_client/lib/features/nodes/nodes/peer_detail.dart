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

/// Shared device detail content used by the expanded detail pane, the medium
/// dialog, and the compact full-screen detail. Common information first
/// (connection, network), technical metadata behind the Advanced disclosure.
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
        const SizedBox(height: AppTokens.space12),
        const Divider(height: 1),
        const SizedBox(height: AppTokens.space12),
        _DetailSection(
          title: strings.sectionConnection,
          rows: [
            _DetailLine(
              label: strings.connectionType,
              value: _connectionLabel(strings, peer),
            ),
            _DetailLine(
              label: strings.latency,
              value: formatLatency(peer.latencyMs),
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
          ],
        ),
        if (error != null && error.isNotEmpty) ...[
          _DetailSection(
            title: strings.sectionIssues,
            rows: [_DetailIssueNote(message: error, strings: strings)],
          ),
        ],
        _AdvancedSection(
          peer: peer,
          strings: strings,
          copiedKey: copiedKey,
          onCopy: onCopy,
        ),
        const SizedBox(height: AppTokens.space4),
        const Divider(height: 1),
        const SizedBox(height: AppTokens.space12),
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

/// Header answers the three first questions: who is it, is it online, how is
/// it connected. No Node ID, no version, no raw state on the first level.
class _DetailHeader extends StatelessWidget {
  const _DetailHeader({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final statusColor = _rowStatusColor(context, peer);
    final statusLabel = peer.online ? strings.online : strings.offline;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
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
            const SizedBox(width: AppTokens.space10),
            Container(
              width: 8,
              height: 8,
              decoration: BoxDecoration(
                color: statusColor,
                shape: BoxShape.circle,
              ),
            ),
            const SizedBox(width: 6),
            Text(
              statusLabel,
              style: TextStyle(
                color: statusColor,
                fontSize: 12,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
        const SizedBox(height: AppTokens.space4),
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
        const SizedBox(height: AppTokens.space4),
        Text(
          _pathSummaryLabel(strings, peer),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 12.5,
            fontWeight: FontWeight.w600,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}

/// Collapsed by default: Node ID, version, state, path decision, and the
/// copy-ping command stay out of the way until explicitly requested.
class _AdvancedSection extends StatefulWidget {
  const _AdvancedSection({
    required this.peer,
    required this.strings,
    this.copiedKey,
    this.onCopy,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final String? copiedKey;
  final Future<void> Function(String value, String key)? onCopy;

  @override
  State<_AdvancedSection> createState() => _AdvancedSectionState();
}

class _AdvancedSectionState extends State<_AdvancedSection> {
  var _expanded = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final peer = widget.peer;
    final strings = widget.strings;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          key: const Key('nodes-advanced-toggle'),
          onTap: () => setState(() => _expanded = !_expanded),
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    strings.advancedInfo,
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.4,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
                AnimatedRotation(
                  turns: _expanded ? 0.5 : 0,
                  duration: const Duration(milliseconds: 150),
                  child: Icon(
                    Icons.expand_more_rounded,
                    size: 18,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ),
        AnimatedSize(
          duration: const Duration(milliseconds: 180),
          curve: Curves.easeOut,
          alignment: Alignment.topCenter,
          child: _expanded
              ? Padding(
                  padding: const EdgeInsets.only(top: 2, bottom: 4),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _DetailLine(label: strings.nodeId, value: peer.nodeId),
                      _DetailLine(
                        label: strings.version,
                        value: dash(peer.appVersion),
                      ),
                      _DetailLine(
                        label: strings.state,
                        value: dash(peer.state),
                      ),
                      if (peer.currentPathSelection?.reason.isNotEmpty == true)
                        _DetailLine(
                          label: strings.pathDecision,
                          value: peer.currentPathSelection!.reason,
                        ),
                      if (widget.onCopy != null) ...[
                        const SizedBox(height: AppTokens.space6),
                        _CopyPingAction(
                          peer: peer,
                          strings: strings,
                          copiedKey: widget.copiedKey,
                          onCopy: widget.onCopy!,
                        ),
                      ],
                    ],
                  ),
                )
              : const SizedBox(width: double.infinity),
        ),
      ],
    );
  }
}

class _CopyPingAction extends StatelessWidget {
  const _CopyPingAction({
    required this.peer,
    required this.strings,
    required this.copiedKey,
    required this.onCopy,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;

  @override
  Widget build(BuildContext context) {
    final pingKey = '${peer.nodeId}:ping';
    final copied = copiedKey == pingKey;
    return TextButton.icon(
      onPressed: () => onCopy('ping ${peer.virtualIp}', pingKey),
      style: TextButton.styleFrom(
        visualDensity: VisualDensity.compact,
        padding: const EdgeInsets.symmetric(horizontal: 6),
      ),
      icon: Icon(
        copied ? Icons.check_circle_outline : Icons.terminal_outlined,
        size: 15,
      ),
      label: Text(strings.copyPingCommand),
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
          const SizedBox(height: AppTokens.space4),
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
    final c = P2WlanColors.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space10),
      decoration: BoxDecoration(
        color: c.warningSurface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: c.warningBorder),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.warning_amber_rounded, size: 17, color: c.warningText),
          const SizedBox(width: AppTokens.space8),
          Expanded(
            child: SelectableText(
              message,
              style: TextStyle(
                fontSize: 12,
                height: 1.35,
                color: c.warningText,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// One prominent action (speed test when usable); everything else is a quiet
/// text action. Remove keeps its danger semantics.
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
    final ipCopied = copiedKey == ipKey;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (_canRunSpeedTest(peer) && onSpeedTest != null)
          FilledButton.tonalIcon(
            key: Key('node-detail-speedtest-${peer.nodeId}'),
            onPressed: () => onSpeedTest!(peer),
            icon: const Icon(Icons.speed_rounded, size: 17),
            label: Text(strings.speedTest),
          ),
        const SizedBox(height: AppTokens.space8),
        Wrap(
          spacing: 4,
          runSpacing: 2,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            if (onCopy != null)
              TextButton.icon(
                onPressed: () => onCopy!(peer.virtualIp, ipKey),
                style: TextButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(horizontal: 6),
                ),
                icon: Icon(
                  ipCopied ? Icons.check_circle_outline : Icons.copy_outlined,
                  size: 15,
                ),
                label: Text(strings.copyVirtualIp),
              ),
            if (onEdit != null)
              TextButton.icon(
                onPressed: busy ? null : () => onEdit!(peer),
                style: TextButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(horizontal: 6),
                ),
                icon: const Icon(Icons.edit_outlined, size: 15),
                label: Text(strings.renameDevice),
              ),
            if (onDelete != null)
              TextButton.icon(
                onPressed: busy ? null : () => onDelete!(peer),
                style: TextButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(horizontal: 6),
                ),
                icon: Icon(
                  Icons.delete_outline_rounded,
                  size: 15,
                  color: theme.colorScheme.error,
                ),
                label: Text(
                  strings.removeDevice,
                  style: TextStyle(color: theme.colorScheme.error),
                ),
              ),
          ],
        ),
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
          padding: const EdgeInsets.all(AppTokens.space24),
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
      insetPadding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space16,
        vertical: AppTokens.space24,
      ),
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
