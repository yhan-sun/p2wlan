part of '../nodes_page.dart';

class _DetailLine extends StatelessWidget {
  const _DetailLine({
    required this.label,
    required this.value,
    this.onCopy,
    this.copyKey,
  });

  final String label;
  final String value;
  final VoidCallback? onCopy;
  final Key? copyKey;

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
          if (onCopy != null) {
            final strings = stringsOf(context);
            return Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [labelText, const SizedBox(height: 3), valueText],
                  ),
                ),
                IconButton(
                  key: copyKey,
                  tooltip: strings.isZh ? '复制$label' : 'Copy $label',
                  onPressed: onCopy,
                  icon: const Icon(Icons.copy_outlined, size: 17),
                ),
              ],
            );
          }
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

/// The two pieces of information needed to judge a connection stay together
/// near the top of the detail surface. The first level remains quiet; opening
/// a device is what reveals its path and verified latency.
class _ConnectionSummary extends StatelessWidget {
  const _ConnectionSummary({
    required this.peer,
    required this.strings,
    required this.current,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool current;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final pathColor = current
        ? _rowStatusColor(context, peer)
        : colors.warningText;
    return LayoutBuilder(
      builder: (context, constraints) {
        final metrics = [
          _DetailMetric(
            icon: Icons.route_outlined,
            label: strings.connectionType,
            value: current ? _connectionLabel(strings, peer) : strings.stale,
            valueColor: pathColor,
          ),
          _DetailMetric(
            icon: Icons.speed_rounded,
            label: strings.latency,
            value: formatLatency(current ? peer.latencyMs : null),
          ),
        ];
        return Container(
          key: const Key('peer-detail-connection-summary'),
          width: double.infinity,
          padding: const EdgeInsets.all(AppTokens.space14),
          decoration: BoxDecoration(
            color: colors.surfaceMuted,
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            border: Border.all(color: colors.border),
          ),
          child:
              constraints.maxWidth < 330 ||
                  MediaQuery.textScalerOf(context).scale(12) > 16
              ? Column(
                  children: [
                    metrics[0],
                    Padding(
                      padding: const EdgeInsets.symmetric(
                        vertical: AppTokens.space12,
                      ),
                      child: Divider(height: 1, color: colors.divider),
                    ),
                    metrics[1],
                  ],
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: metrics[0]),
                    Container(
                      width: 1,
                      height: 48,
                      margin: const EdgeInsets.symmetric(
                        horizontal: AppTokens.space14,
                      ),
                      color: colors.divider,
                    ),
                    Expanded(child: metrics[1]),
                  ],
                ),
        );
      },
    );
  }
}

class _DetailMetric extends StatelessWidget {
  const _DetailMetric({
    required this.icon,
    required this.label,
    required this.value,
    this.valueColor,
  });

  final IconData icon;
  final String label;
  final String value;
  final Color? valueColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Container(
          width: 36,
          height: 36,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surface,
            borderRadius: BorderRadius.circular(AppTokens.radiusMd),
          ),
          child: Icon(
            icon,
            size: 18,
            color: valueColor ?? theme.colorScheme.primary,
          ),
        ),
        const SizedBox(width: AppTokens.space10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: TextStyle(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: AppTokens.space4),
              Text(
                value,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: valueColor ?? theme.colorScheme.onSurface,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                  height: 1.15,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ),
        ),
      ],
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
    this.current = true,
    this.trafficCounters,
    this.transferBytesPerSecond,
    this.serviceUptimeMs,
    this.networkId,
    this.copiedKey,
    this.busy = false,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool current;
  final TrafficCounters? trafficCounters;
  final int? transferBytesPerSecond;
  final int? serviceUptimeMs;
  final String? networkId;
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
        _DetailHeader(peer: peer, strings: strings, current: current),
        const SizedBox(height: AppTokens.space12),
        _ConnectionSummary(peer: peer, strings: strings, current: current),
        const SizedBox(height: AppTokens.space12),
        _PeerTrafficSection(
          counters: trafficCounters ?? TrafficCounters.fromPeer(peer),
          strings: strings,
          current: current && (trafficCounters != null || peer.online),
          localScope: trafficCounters != null,
          serviceUptimeMs: serviceUptimeMs,
          transferBytesPerSecond: transferBytesPerSecond,
          networkId: networkId,
          peerId: peer.nodeId,
        ),
        const SizedBox(height: AppTokens.space12),
        _DetailSection(
          key: const Key('peer-detail-network-card'),
          icon: Icons.lan_outlined,
          title: strings.sectionNetwork,
          rows: [
            _DetailLine(label: strings.lastSeen, value: _formatLastSeen(peer)),
            _networkLine(strings.virtualIp, peer.virtualIp, 'ip'),
            _DetailLine(
              label: strings.isZh ? '连接时长' : 'Connected for',
              value: formatElapsedTime(
                current && peer.online ? peer.connectedForMs : null,
                isZh: strings.isZh,
              ),
            ),
            _DetailLine(
              label: strings.natType,
              value: peer.natType.trim().toLowerCase() == 'unknown'
                  ? '—'
                  : dash(peer.natType),
            ),
            _networkLine(strings.endpoint, peer.endpoint, 'endpoint'),
            _networkLine(strings.relay, peer.relayServer, 'relay'),
          ],
        ),
        if (error != null && error.isNotEmpty) ...[
          const SizedBox(height: AppTokens.space12),
          _DetailIssueNote(peer: peer, message: error, strings: strings),
        ],
        const SizedBox(height: AppTokens.space12),
        _AdvancedSection(
          peer: peer,
          strings: strings,
          copiedKey: copiedKey,
          onCopy: onCopy,
        ),
        if (onCopy != null ||
            onEdit != null ||
            onDelete != null ||
            onSpeedTest != null) ...[
          const SizedBox(height: AppTokens.space12),
          _DetailActions(
            peer: peer,
            strings: strings,
            copiedKey: copiedKey,
            busy: busy,
            onCopy: onCopy,
            onEdit: onEdit,
            onDelete: onDelete,
            onSpeedTest: current ? onSpeedTest : null,
          ),
        ],
      ],
    );
  }

  Widget _networkLine(String label, String? rawValue, String field) {
    final value = rawValue?.trim() ?? '';
    return _DetailLine(
      label: label,
      value: dash(value),
      copyKey: Key('node-detail-copy-$field-${peer.nodeId}'),
      onCopy: value.isEmpty || onCopy == null
          ? null
          : () => onCopy!(value, '${peer.nodeId}:$field'),
    );
  }
}

/// Header answers the three first questions: who is it, is it online, how is
/// it connected. No Node ID, no version, no raw state on the first level.
class _DetailHeader extends StatelessWidget {
  const _DetailHeader({
    required this.peer,
    required this.strings,
    required this.current,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool current;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final statusLabel = !current
        ? strings.stale
        : peer.online
        ? strings.online
        : strings.offline;
    return Container(
      key: const Key('peer-detail-header'),
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space16),
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border),
        boxShadow: AppTokens.shadowBorder,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            width: 48,
            height: 48,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: colors.selectedSurface,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
            ),
            child: Icon(
              peerDeviceIcon(peer),
              size: 24,
              color: theme.colorScheme.primary,
            ),
          ),
          const SizedBox(width: AppTokens.space14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  dash(peer.displayName),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 17,
                    fontWeight: FontWeight.w700,
                    height: 1.2,
                  ),
                ),
                const SizedBox(height: AppTokens.space6),
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
          const SizedBox(width: AppTokens.space10),
          StatusBadge(
            label: statusLabel,
            tone: !current
                ? StatusTone.warn
                : peer.online
                ? StatusTone.good
                : StatusTone.neutral,
          ),
        ],
      ),
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
    final colors = P2WlanColors.of(context);
    final peer = widget.peer;
    final strings = widget.strings;
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            InkWell(
              key: const Key('nodes-advanced-toggle'),
              onTap: () => setState(() => _expanded = !_expanded),
              child: ConstrainedBox(
                constraints: const BoxConstraints(
                  minHeight: AppTokens.minTouchTarget,
                ),
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppTokens.space14,
                    vertical: AppTokens.space10,
                  ),
                  child: Row(
                    children: [
                      Icon(
                        Icons.tune_rounded,
                        size: 18,
                        color: theme.colorScheme.primary,
                      ),
                      const SizedBox(width: AppTokens.space10),
                      Expanded(
                        child: Text(
                          strings.advancedInfo,
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.onSurface,
                          ),
                        ),
                      ),
                      AnimatedRotation(
                        turns: _expanded ? 0.5 : 0,
                        duration: AppTokens.durationMedium,
                        child: Icon(
                          Icons.expand_more_rounded,
                          size: 20,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            AnimatedSize(
              duration: AppTokens.durationMedium,
              curve: AppTokens.curveEase,
              alignment: Alignment.topCenter,
              child: _expanded
                  ? Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Divider(height: 1, color: colors.divider),
                        Padding(
                          padding: const EdgeInsets.fromLTRB(
                            AppTokens.space14,
                            AppTokens.space10,
                            AppTokens.space14,
                            AppTokens.space12,
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              _DetailLine(
                                label: strings.nodeId,
                                value: peer.nodeId,
                                copyKey: Key(
                                  'node-detail-copy-id-${peer.nodeId}',
                                ),
                                onCopy:
                                    peer.nodeId.trim().isEmpty ||
                                        widget.onCopy == null
                                    ? null
                                    : () => widget.onCopy!(
                                        peer.nodeId,
                                        '${peer.nodeId}:id',
                                      ),
                              ),
                              _DetailLine(
                                label: strings.version,
                                value: dash(peer.appVersion),
                              ),
                              _DetailLine(
                                label: strings.state,
                                value: dash(peer.state),
                              ),
                              if (peer
                                      .currentPathSelection
                                      ?.reason
                                      .isNotEmpty ==
                                  true)
                                _DetailLine(
                                  label: strings.pathDecision,
                                  value: peer.currentPathSelection!.reason,
                                ),
                              if (widget.onCopy != null &&
                                  peer.virtualIp.trim().isNotEmpty) ...[
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
                        ),
                      ],
                    )
                  : const SizedBox(width: double.infinity),
            ),
          ],
        ),
      ),
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
    return OutlinedButton.icon(
      onPressed: () => onCopy('ping ${peer.virtualIp}', pingKey),
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(0, AppTokens.minTouchTarget),
      ),
      icon: Icon(
        copied ? Icons.check_circle_outline : Icons.terminal_outlined,
        size: 17,
      ),
      label: Text(strings.copyPingCommand),
    );
  }
}

class _DetailSection extends StatelessWidget {
  const _DetailSection({
    super.key,
    required this.title,
    required this.rows,
    this.icon,
  });

  final String title;
  final IconData? icon;
  final List<Widget> rows;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space14),
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              if (icon != null) ...[
                Icon(icon, size: 18, color: theme.colorScheme.primary),
                const SizedBox(width: AppTokens.space8),
              ],
              Expanded(
                child: Text(
                  title,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: AppTokens.space8),
          for (var index = 0; index < rows.length; index++) ...[
            if (index > 0) Divider(height: 1, color: colors.divider),
            rows[index],
          ],
        ],
      ),
    );
  }
}

class _DetailIssueNote extends StatefulWidget {
  const _DetailIssueNote({
    required this.peer,
    required this.message,
    required this.strings,
  });

  final PeerSnapshot peer;
  final String message;
  final AppStrings strings;

  @override
  State<_DetailIssueNote> createState() => _DetailIssueNoteState();
}

class _DetailIssueNoteState extends State<_DetailIssueNote> {
  var _showTechnicalDetails = false;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final peer = widget.peer;
    final isOffline = _peerIsOffline(peer);
    final isConnecting =
        peer.online && (peer.path == 'probing' || peer.path == 'direct_trial');
    final title = isOffline
        ? widget.strings.deviceUnavailableTitle
        : isConnecting
        ? widget.strings.connectionInProgressTitle
        : widget.strings.connectionNeedsAttentionTitle;
    final body = isOffline
        ? widget.strings.deviceUnavailableBody
        : isConnecting
        ? widget.strings.connectionInProgressBody
        : widget.strings.connectionNeedsAttentionBody;
    final surface = isOffline ? colors.neutralSurface : colors.warningSurface;
    final border = isOffline ? colors.neutralBorder : colors.warningBorder;
    final foreground = isOffline ? colors.neutralText : colors.warningText;

    return Container(
      key: const Key('peer-detail-issue-card'),
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space14),
      decoration: BoxDecoration(
        color: surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(
                isOffline ? Icons.cloud_off_outlined : Icons.sync_rounded,
                size: 19,
                color: foreground,
              ),
              const SizedBox(width: AppTokens.space10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        color: foreground,
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: AppTokens.space4),
                    Text(
                      body,
                      style: TextStyle(
                        color: foreground,
                        fontSize: 12,
                        height: 1.4,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: AppTokens.space6),
          TextButton.icon(
            key: const Key('nodes-issue-details-toggle'),
            onPressed: () =>
                setState(() => _showTechnicalDetails = !_showTechnicalDetails),
            style: TextButton.styleFrom(
              foregroundColor: foreground,
              minimumSize: const Size(0, AppTokens.minTouchTarget),
              padding: EdgeInsets.zero,
            ),
            icon: Icon(
              _showTechnicalDetails
                  ? Icons.expand_less_rounded
                  : Icons.code_rounded,
              size: 17,
            ),
            label: Text(
              _showTechnicalDetails
                  ? widget.strings.hideTechnicalDetails
                  : widget.strings.technicalDetails,
            ),
          ),
          AnimatedSize(
            duration: AppTokens.durationMedium,
            curve: AppTokens.curveEase,
            alignment: Alignment.topCenter,
            child: _showTechnicalDetails
                ? Container(
                    key: const Key('peer-detail-raw-error'),
                    width: double.infinity,
                    padding: const EdgeInsets.all(AppTokens.space12),
                    decoration: BoxDecoration(
                      color: colors.consoleSurface,
                      borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                      border: Border.all(color: colors.consoleBorder),
                    ),
                    child: SelectableText(
                      redactSensitive(widget.message),
                      style: TextStyle(
                        color: colors.consoleText,
                        fontSize: 11.5,
                        height: 1.45,
                        fontFamily: 'monospace',
                      ),
                    ),
                  )
                : const SizedBox(width: double.infinity),
          ),
        ],
      ),
    );
  }
}

/// One prominent action (speed test when usable); everything else is a quiet
/// secondary action. Remove keeps its danger semantics.
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
    if (onCopy == null &&
        onEdit == null &&
        onDelete == null &&
        onSpeedTest == null) {
      return const SizedBox.shrink();
    }
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final ipCopied = copiedKey == ipKey;
    return Container(
      key: const Key('peer-detail-actions'),
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space14),
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border),
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final buttons = <Widget>[
            if (_canRunSpeedTest(peer) && onSpeedTest != null)
              FilledButton.icon(
                key: Key('node-detail-speedtest-${peer.nodeId}'),
                onPressed: () => onSpeedTest!(peer),
                icon: const Icon(Icons.speed_rounded, size: 18),
                label: Text(strings.speedTest),
              ),
            if (onCopy != null && peer.virtualIp.trim().isNotEmpty)
              OutlinedButton.icon(
                onPressed: () => onCopy!(peer.virtualIp, ipKey),
                icon: Icon(
                  ipCopied ? Icons.check_circle_outline : Icons.copy_outlined,
                  size: 17,
                ),
                label: Text(strings.copyVirtualIp),
              ),
            if (onEdit != null)
              OutlinedButton.icon(
                onPressed: busy ? null : () => onEdit!(peer),
                icon: const Icon(Icons.edit_outlined, size: 17),
                label: Text(strings.renameDevice),
              ),
            if (onDelete != null)
              OutlinedButton.icon(
                onPressed: busy ? null : () => onDelete!(peer),
                style: OutlinedButton.styleFrom(
                  foregroundColor: theme.colorScheme.error,
                  side: BorderSide(
                    color: theme.colorScheme.error.withValues(alpha: 0.45),
                  ),
                ),
                icon: const Icon(Icons.delete_outline_rounded, size: 17),
                label: Text(strings.removeDevice),
              ),
          ];
          final narrow = constraints.maxWidth < 360;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                strings.sectionActions,
                style: TextStyle(
                  color: theme.colorScheme.onSurface,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: AppTokens.space10),
              if (narrow)
                ...buttons.map(
                  (button) => Padding(
                    padding: const EdgeInsets.only(bottom: AppTokens.space8),
                    child: SizedBox(width: double.infinity, child: button),
                  ),
                )
              else
                Wrap(
                  spacing: AppTokens.space8,
                  runSpacing: AppTokens.space8,
                  children: buttons,
                ),
            ],
          );
        },
      ),
    );
  }
}

/// Detail dialog used by medium and wide layouts. Shares the same content as
/// the compact full-screen detail.
class DeviceDetailsDialog extends StatelessWidget {
  const DeviceDetailsDialog({
    super.key,
    this.peer,
    this.content,
    this.contextHeader,
    required this.strings,
    this.statusStore,
    this.networkId,
    this.current,
    this.trafficCounters,
    this.serviceUptimeMs,
    this.transferBytesPerSecond,
    this.copiedKey,
    this.busyPeerId,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  }) : assert(peer != null || content != null);

  final PeerSnapshot? peer;
  final Widget? content;
  final Widget? contextHeader;
  final AppStrings strings;
  final StatusStore? statusStore;
  final String? networkId;
  final bool? current;

  /// Local-device counters from its own network scope; peer counters default
  /// to TrafficCounters.fromPeer and never borrow another scope's statistics.
  final TrafficCounters? trafficCounters;
  final int? serviceUptimeMs;
  final int? transferBytesPerSecond;
  final String? copiedKey;
  final String? busyPeerId;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final size = MediaQuery.sizeOf(context);
    final usableWidth = size.width > 64 ? size.width - 32 : size.width;
    final usableHeight = size.height > 96 ? size.height - 48 : size.height;
    final dialogWidth = usableWidth < 640 ? usableWidth : 640.0;
    final maxDialogHeight = usableHeight < 720 ? usableHeight : 720.0;

    Widget details(PeerSnapshot currentPeer) => _PeerDetailsContent(
      peer: currentPeer,
      strings: strings,
      current:
          current ??
          _primaryPeerCurrent(
            statusStore,
            currentPeer.nodeId,
            networkId: networkId,
          ),
      trafficCounters: trafficCounters,
      serviceUptimeMs: serviceUptimeMs,
      transferBytesPerSecond:
          transferBytesPerSecond ??
          (current == null
              ? _primaryPeerRate(statusStore, currentPeer.nodeId, networkId)
              : null),
      networkId: networkId,
      copiedKey: copiedKey,
      busy: busyPeerId == currentPeer.nodeId,
      onCopy: onCopy,
      onEdit: onEdit,
      onDelete: onDelete == null
          ? null
          : (selected) =>
                _closeDetailOnRemoved(context, () => onDelete!(selected)),
      onSpeedTest: onSpeedTest,
    );

    return AppStringsScope(
      strings: strings,
      child: Dialog(
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
              color: colors.surfaceMuted,
              borderRadius: BorderRadius.circular(AppTokens.radiusLg),
              boxShadow: AppTokens.shadowBorder,
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(AppTokens.radiusLg),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(20, 12, 10, 12),
                    child: Row(
                      children: [
                        Container(
                          width: 34,
                          height: 34,
                          alignment: Alignment.center,
                          decoration: BoxDecoration(
                            color: colors.selectedSurface,
                            borderRadius: BorderRadius.circular(
                              AppTokens.radiusSm,
                            ),
                          ),
                          child: Icon(
                            Icons.devices_rounded,
                            size: 18,
                            color: theme.colorScheme.primary,
                          ),
                        ),
                        const SizedBox(width: AppTokens.space10),
                        Expanded(
                          child: Text(
                            strings.deviceDetails,
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
                          key: const Key('nodes-detail-close'),
                          tooltip: strings.close,
                          onPressed: () => Navigator.of(context).pop(),
                          icon: const Icon(Icons.close_rounded, size: 20),
                        ),
                      ],
                    ),
                  ),
                  Divider(height: 1, color: colors.divider),
                  Flexible(
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.all(AppTokens.space20),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (contextHeader != null) ...[
                            contextHeader!,
                            const SizedBox(height: 12),
                          ],
                          if (content != null && trafficCounters != null) ...[
                            _PeerTrafficSection(
                              counters: trafficCounters!,
                              strings: strings,
                              current: current ?? true,
                              localScope: true,
                              serviceUptimeMs: serviceUptimeMs,
                              transferBytesPerSecond: transferBytesPerSecond,
                              networkId: networkId,
                            ),
                            const SizedBox(height: 12),
                          ],
                          content ??
                              (statusStore == null
                                  ? details(peer!)
                                  : AnimatedBuilder(
                                      animation: statusStore!,
                                      builder: (context, _) => details(
                                        _latestPeer(
                                          statusStore,
                                          peer!,
                                          networkId: networkId,
                                        ),
                                      ),
                                    )),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
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
    this.statusStore,
    this.networkId,
    this.copiedKey,
    this.busyPeerId,
    this.onCopy,
    this.onEdit,
    this.onDelete,
    this.onSpeedTest,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final StatusStore? statusStore;
  final String? networkId;
  final String? copiedKey;
  final String? busyPeerId;
  final Future<void> Function(String value, String key)? onCopy;
  final Future<bool> Function(PeerSnapshot peer)? onDelete;
  final Future<void> Function(PeerSnapshot peer)? onEdit;
  final Future<void> Function(PeerSnapshot peer)? onSpeedTest;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);

    Widget details(PeerSnapshot currentPeer) => _PeerDetailsContent(
      peer: currentPeer,
      strings: strings,
      current: _primaryPeerCurrent(
        statusStore,
        currentPeer.nodeId,
        networkId: networkId,
      ),
      transferBytesPerSecond: _primaryPeerRate(
        statusStore,
        currentPeer.nodeId,
        networkId,
      ),
      networkId: networkId,
      copiedKey: copiedKey,
      busy: busyPeerId == currentPeer.nodeId,
      onCopy: onCopy,
      onEdit: onEdit,
      onDelete: onDelete == null
          ? null
          : (selected) =>
                _closeDetailOnRemoved(context, () => onDelete!(selected)),
      onSpeedTest: onSpeedTest,
    );

    return AppStringsScope(
      strings: strings,
      child: Scaffold(
        key: const Key('nodes-mobile-detail'),
        backgroundColor: colors.surfaceMuted,
        appBar: AppBar(
          leading: const AppBackButton(key: Key('nodes-mobile-detail-back')),
          title: Text(strings.deviceDetails),
          backgroundColor: colors.surface,
          elevation: 0,
          scrolledUnderElevation: 0,
          surfaceTintColor: Colors.transparent,
          bottom: PreferredSize(
            preferredSize: const Size.fromHeight(1),
            child: Divider(height: 1, color: colors.divider),
          ),
        ),
        body: SafeArea(
          top: false,
          child: LayoutBuilder(
            builder: (context, constraints) => SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(
                AppTokens.space16,
                AppTokens.space16,
                AppTokens.space16,
                AppTokens.space32,
              ),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 620),
                  child: statusStore == null
                      ? details(peer)
                      : AnimatedBuilder(
                          animation: statusStore!,
                          builder: (context, _) => details(
                            _latestPeer(
                              statusStore,
                              peer,
                              networkId: networkId,
                            ),
                          ),
                        ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

bool _primaryPeerCurrent(
  StatusStore? store,
  String nodeId, {
  String? networkId,
}) =>
    store == null ||
    ((networkId == null || store.snapshot?.networkId == networkId) &&
        NetworkOverview.read(store).peers.any(
          (item) =>
              item.isPrimary && item.current && item.peer.nodeId == nodeId,
        ));

int? _primaryPeerRate(StatusStore? store, String nodeId, String? networkId) {
  if (store == null ||
      !_primaryPeerCurrent(store, nodeId, networkId: networkId)) {
    return null;
  }
  return store.peerTransferRatesBytesPerSecond[nodeId];
}

PeerSnapshot _latestPeer(
  StatusStore? store,
  PeerSnapshot fallback, {
  String? networkId,
}) {
  if (networkId != null && store?.snapshot?.networkId != networkId) {
    return fallback;
  }
  final peers = store?.snapshot?.peers;
  if (peers == null) return fallback;
  for (final peer in peers) {
    if (peer.nodeId == fallback.nodeId) return peer;
  }
  return fallback;
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
