part of '../nodes_page.dart';

/// Mobile/web devices state. A remote-management client cannot read the live
/// peer/path snapshot from the desktop daemon through localhost, so it must
/// not render an invented offline local node or empty live peer catalog.
class _RemoteOnlyNodesState extends StatelessWidget {
  const _RemoteOnlyNodesState();

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final c = P2WlanColors.of(context);
    return AppPanel(
      title: strings.mobileModeTitle,
      trailing: StatusBadge(
        label: strings.mobileModeBadge,
        tone: StatusTone.neutral,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.devices_other_rounded, color: theme.colorScheme.primary),
          const SizedBox(width: AppTokens.space12),
          Expanded(
            child: Text(
              strings.mobileModeDetail,
              style: TextStyle(color: c.textMuted, fontSize: 13, height: 1.45),
            ),
          ),
        ],
      ),
    );
  }
}
