part of '../nodes_page.dart';

class _LocalNodeProfileResult {
  const _LocalNodeProfileResult({
    required this.deviceName,
    required this.virtualIp,
  });

  final String deviceName;
  final String virtualIp;
}

/// Compact local-device section: name, virtual IP, connection status, and a
/// quiet edit affordance. No Node ID, no sync text, no big panel — the
/// details live in the edit dialog.
class _LocalNodePanel extends StatelessWidget {
  const _LocalNodePanel({
    required this.snapshot,
    required this.settings,
    required this.daemonReachable,
    required this.onEdit,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool daemonReachable;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final c = P2WlanColors.of(context);
    final deviceName = settings.deviceName.trim();
    final virtualIp = snapshot?.virtualIp.trim() ?? '';
    // Real daemon reachability signals only; never claim "offline" when the
    // daemon is actually reachable but the snapshot is unavailable.
    final online = snapshot != null;
    final statusLabel = online
        ? strings.connected
        : daemonReachable
        ? strings.unavailable
        : strings.offline;
    final statusColor = online ? c.direct : c.offline;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          strings.thisDeviceTitle,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 15,
            fontWeight: FontWeight.w700,
            letterSpacing: 0,
          ),
        ),
        const SizedBox(height: AppTokens.space4),
        Material(
          color: theme.colorScheme.surface,
          child: InkWell(
            key: const Key('nodes-local-row'),
            onTap: onEdit,
            child: Padding(
              padding: const EdgeInsets.symmetric(
                horizontal: AppTokens.space4,
                vertical: 8,
              ),
              child: Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      color: theme.colorScheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                    ),
                    child: Icon(
                      localDeviceIcon(),
                      size: 17,
                      color: theme.colorScheme.primary,
                    ),
                  ),
                  const SizedBox(width: AppTokens.space10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          dash(deviceName),
                          // Keep long hostnames readable on phones; the
                          // status/edit affordances already consume the
                          // trailing space in this row.
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            fontSize: 13.5,
                            fontWeight: FontWeight.w700,
                            color: theme.colorScheme.onSurface,
                            height: 1.2,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          dash(virtualIp),
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
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: statusColor,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(
                          statusLabel,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: statusColor,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ],
                  ),
                  IconButton(
                    key: const Key('nodes-edit-local'),
                    tooltip: strings.renameDevice,
                    onPressed: onEdit,
                    iconSize: 18,
                    icon: const Icon(Icons.edit_outlined),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}
