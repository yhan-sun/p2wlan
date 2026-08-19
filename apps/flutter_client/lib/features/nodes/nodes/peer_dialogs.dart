part of '../nodes_page.dart';

class _RemoveDeviceDialogContent extends StatelessWidget {
  const _RemoveDeviceDialogContent({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final c = P2WlanColors.of(context);
    return ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 420),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DecoratedBox(
            decoration: BoxDecoration(
              color: c.dangerSurface,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              border: Border.all(color: c.dangerBorder),
            ),
            child: Padding(
              padding: const EdgeInsets.all(AppTokens.space12),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.warning_amber_rounded,
                    size: 20,
                    color: c.dangerText,
                  ),
                  const SizedBox(width: AppTokens.space10),
                  Expanded(
                    child: Text(
                      strings.removeDeviceConfirmation,
                      style: TextStyle(
                        color: c.dangerText,
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
          const SizedBox(height: AppTokens.space14),
          _RemoveDeviceMetaRow(label: strings.device, value: peer.displayName),
          _RemoveDeviceMetaRow(
            label: strings.virtualIp,
            value: dash(peer.virtualIp),
          ),
          _RemoveDeviceMetaRow(
            label: strings.nodeId,
            value: shortId(peer.nodeId),
          ),
          const SizedBox(height: AppTokens.space4),
          Text(
            strings.removeDeviceOfflineHint,
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
          const SizedBox(width: AppTokens.space8),
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
