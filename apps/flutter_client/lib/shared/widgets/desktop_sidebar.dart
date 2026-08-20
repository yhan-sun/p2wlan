import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/navigation_model.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/state/status_store.dart';
import 'status_badge.dart';

/// Expanded desktop side navigation: brand header, primary sections grouped
/// by quiet dividers, and a lightweight network status footer.
///
/// The footer reads the existing [StatusStore] snapshot — no extra polling,
/// no duplicate network fetch. It navigates to Troubleshooting on tap.
class DesktopSidebar extends StatelessWidget {
  const DesktopSidebar({
    super.key,
    required this.selected,
    required this.strings,
    required this.statusStore,
    required this.onSelect,
    required this.onFooterTap,
  });

  static const width = 184.0;

  final P2WlanSection? selected;
  final AppStrings strings;
  final StatusStore statusStore;
  final ValueChanged<P2WlanSection> onSelect;
  final VoidCallback onFooterTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      key: const Key('desktop-sidebar-surface'),
      width: width,
      color: theme.colorScheme.surface,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _SidebarBrandHeader(strings: strings),
            const Divider(height: 1),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: AppTokens.space6),
                children: [
                  for (final (index, group)
                      in P2WlanSection.sidebarGroups.indexed) ...[
                    if (index > 0)
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 6),
                        child: Divider(height: 1, indent: 16),
                      ),
                    for (final section in group)
                      _SidebarItem(
                        icon: section.icon,
                        label: strings.sectionLabel(section.name),
                        selected: selected == section,
                        onTap: () => onSelect(section),
                      ),
                  ],
                ],
              ),
            ),
            _SidebarFooter(
              strings: strings,
              statusStore: statusStore,
              onTap: onFooterTap,
            ),
          ],
        ),
      ),
    );
  }
}

class _SidebarBrandHeader extends StatelessWidget {
  const _SidebarBrandHeader({required this.strings});

  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SizedBox(
      key: const Key('desktop-sidebar-brand'),
      height: 52,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: AppTokens.space14),
        child: Row(
          children: [
            Container(
              width: 26,
              height: 26,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary,
                borderRadius: BorderRadius.circular(AppTokens.radiusSm + 1),
              ),
              child: Icon(
                Icons.hub_outlined,
                size: 16,
                color: theme.colorScheme.onPrimary,
              ),
            ),
            const SizedBox(width: AppTokens.space10),
            Text(
              strings.appName,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
                letterSpacing: 0,
                color: theme.colorScheme.onSurface,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _SidebarItem extends StatelessWidget {
  const _SidebarItem({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final foreground = selected
        ? theme.colorScheme.primary
        : theme.colorScheme.onSurfaceVariant;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: AppTokens.space8),
      child: AnimatedContainer(
        duration: AppTokens.durationMedium,
        curve: AppTokens.curveEase,
        decoration: BoxDecoration(
          color: selected ? colors.selectedSurface : Colors.transparent,
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        ),
        child: Material(
          type: MaterialType.transparency,
          child: MouseRegion(
            cursor: SystemMouseCursors.click,
            child: InkWell(
              onTap: onTap,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              hoverColor: selected ? null : colors.hoverSurface,
              child: SizedBox(
                height: 36,
                child: Row(
                  children: [
                    const SizedBox(width: AppTokens.space8),
                    AnimatedContainer(
                      duration: AppTokens.durationMedium,
                      width: 2,
                      height: selected ? 18 : 0,
                      decoration: BoxDecoration(
                        color: selected
                            ? theme.colorScheme.primary
                            : Colors.transparent,
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                    const SizedBox(width: AppTokens.space8),
                    Icon(icon, size: 18, color: foreground),
                    const SizedBox(width: AppTokens.space10),
                    Expanded(
                      child: Text(
                        label,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: selected
                              ? FontWeight.w600
                              : FontWeight.w500,
                          color: foreground,
                        ),
                      ),
                    ),
                    const SizedBox(width: AppTokens.space8),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _SidebarFooter extends StatelessWidget {
  const _SidebarFooter({
    required this.strings,
    required this.statusStore,
    required this.onTap,
  });

  final AppStrings strings;
  final StatusStore statusStore;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final (tone, label, detail) = _footerStatus(strings, statusStore);
        final colors = P2WlanColors.of(context);
        final dotColor = switch (tone) {
          StatusTone.good => colors.successDot,
          StatusTone.warn => colors.warningDot,
          StatusTone.bad => colors.dangerDot,
          StatusTone.neutral => colors.neutralDot,
        };
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Divider(height: 1),
            Container(
              key: const Key('desktop-sidebar-status'),
              child: Tooltip(
                message: strings.openTroubleshooting,
                child: Material(
                  type: MaterialType.transparency,
                  child: InkWell(
                    onTap: onTap,
                    hoverColor: colors.hoverSurface,
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(
                        AppTokens.space14,
                        AppTokens.space10,
                        AppTokens.space10,
                        AppTokens.space10,
                      ),
                      child: Row(
                        children: [
                          Container(
                            width: 7,
                            height: 7,
                            decoration: BoxDecoration(
                              color: dotColor,
                              shape: BoxShape.circle,
                            ),
                          ),
                          const SizedBox(width: AppTokens.space8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  label,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.w600,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  detail,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: TextStyle(
                                    fontSize: 11,
                                    color: theme.colorScheme.onSurfaceVariant,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Icon(
                            Icons.chevron_right_rounded,
                            size: 16,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  /// Last-known-data status summary for the footer. Never blocks on network;
  /// everything derives from the existing snapshot the shell already polls.
  (StatusTone, String, String) _footerStatus(
    AppStrings strings,
    StatusStore store,
  ) {
    if (!store.daemonReachable || store.snapshot == null) {
      return (
        StatusTone.neutral,
        strings.shellStatusOffline,
        strings.shellStatusOfflineDetail,
      );
    }
    if (store.snapshotStale) {
      return (StatusTone.warn, strings.stale, strings.shellStatusStaleDetail);
    }
    final health = store.snapshot!.health.status.toLowerCase();
    if (health == 'healthy') {
      final online = store.snapshot!.peers.where((p) => p.online).length;
      return (
        StatusTone.good,
        strings.shellStatusHealthy,
        strings.shellPeersOnline(online),
      );
    }
    return (
      StatusTone.warn,
      strings.shellStatusAttention,
      strings.needsAttention,
    );
  }
}
