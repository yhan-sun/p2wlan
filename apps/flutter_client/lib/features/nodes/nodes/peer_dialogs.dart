part of '../nodes_page.dart';

class _PeerDetailsDialog extends StatelessWidget {
  const _PeerDetailsDialog({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
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
            color: colorScheme.surface,
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            border: Border.all(color: colorScheme.outlineVariant),
            boxShadow: AppTokens.shadowBorder,
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(18, 16, 10, 14),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              dash(peer.displayName),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: colorScheme.onSurface,
                                fontSize: 16,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            const SizedBox(height: 5),
                            Text(
                              dash(peer.virtualIp),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: colorScheme.onSurfaceVariant,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                                fontFeatures: AppTokens.tabularFontFeatures,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      Padding(
                        padding: const EdgeInsets.only(top: 1),
                        child: _PathBadge(peer: peer),
                      ),
                      const SizedBox(width: 2),
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
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _DetailLine(
                          label: strings.virtualIp,
                          value: dash(peer.virtualIp),
                        ),
                        _DetailLine(
                          label: strings.isZh ? '版本' : 'Version',
                          value: dash(peer.appVersion),
                        ),
                        _DetailLine(label: strings.nodeId, value: peer.nodeId),
                        _DetailLine(
                          label: strings.connectionType,
                          value: _connectionLabel(strings, peer),
                        ),
                        _DetailLine(
                          label: strings.latency,
                          value: formatLatency(peer.latencyMs),
                        ),
                        _DetailLine(
                          label: strings.isZh ? '在线状态' : 'Online state',
                          value: peer.online ? strings.online : strings.offline,
                        ),
                        _DetailLine(
                          label: strings.isZh ? '最后在线' : 'Last seen',
                          value: _formatLastSeen(peer),
                        ),
                        _DetailLine(
                          label: strings.state,
                          value: dash(peer.state),
                        ),
                        _DetailLine(
                          label: strings.type,
                          value: dash(peer.connectionType),
                        ),
                        _DetailLine(
                          label: strings.endpoint,
                          value: dash(peer.endpoint),
                        ),
                        _DetailLine(
                          label: strings.relay,
                          value: dash(peer.relayServer),
                        ),
                        if (peer.currentPathSelection?.reason.isNotEmpty ==
                            true)
                          _DetailLine(
                            label: strings.isZh ? '路径判定' : 'Path decision',
                            value: peer.currentPathSelection!.reason,
                          ),
                        if (peer.lastError != null)
                          _DetailLine(
                            label: strings.lastError,
                            value: peer.lastError!,
                          ),
                      ],
                    ),
                  ),
                ),
                const Divider(height: 1),
                Padding(
                  padding: const EdgeInsets.fromLTRB(18, 10, 18, 12),
                  child: Align(
                    alignment: Alignment.centerRight,
                    child: TextButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: Text(strings.cancel),
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

class _RemoveDeviceDialogContent extends StatelessWidget {
  const _RemoveDeviceDialogContent({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 420),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DecoratedBox(
            decoration: BoxDecoration(
              color: AppTokens.colorBadBg,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              border: Border.all(color: AppTokens.colorBadBorder),
            ),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(
                    Icons.warning_amber_rounded,
                    size: 20,
                    color: AppTokens.colorBadText,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      strings.isZh
                          ? '该设备会从控制面移除，之后需要重新登录/注册才能加入网络。'
                          : 'This removes the device from the control plane. It must sign in or register again to rejoin.',
                      style: const TextStyle(
                        color: AppTokens.colorBadText,
                        fontSize: 13,
                        height: 1.35,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          _RemoveDeviceMetaRow(
            label: strings.isZh ? '设备名称' : 'Device',
            value: peer.displayName,
          ),
          _RemoveDeviceMetaRow(
            label: strings.virtualIp,
            value: dash(peer.virtualIp),
          ),
          _RemoveDeviceMetaRow(
            label: strings.nodeId,
            value: shortId(peer.nodeId),
          ),
          const SizedBox(height: 4),
          Text(
            strings.isZh
                ? '如果只是临时离线，不需要移除；离线设备已自动排在列表底部。'
                : 'If it is only temporarily offline, leave it. Offline devices already sort to the bottom.',
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 12,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}

class _RemoveDeviceMetaRow extends StatelessWidget {
  const _RemoveDeviceMetaRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 88,
            child: Text(
              label,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              value,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 12,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
