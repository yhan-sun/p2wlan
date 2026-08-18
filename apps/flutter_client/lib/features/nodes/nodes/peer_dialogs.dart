part of '../nodes_page.dart';

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
          _RemoveDeviceMetaRow(label: strings.device, value: peer.displayName),
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
