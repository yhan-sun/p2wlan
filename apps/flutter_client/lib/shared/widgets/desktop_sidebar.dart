import 'package:flutter/material.dart';

import 'app_motion.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/navigation_model.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/state/status_store.dart';
import '../../core/presentation/network_overview.dart';
import '../network_overview_presentation.dart';
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

  static const width = 196.0;

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
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: AppTokens.space8),
                children: [
                  for (final (index, group)
                      in P2WlanSection.sidebarGroups.indexed) ...[
                    if (index > 0)
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 12),
                        child: Divider(height: 1, indent: 20, endIndent: 20),
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
    return ConstrainedBox(
      key: const Key('desktop-sidebar-brand'),
      constraints: const BoxConstraints(minHeight: 68),
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: AppTokens.space20,
          vertical: 16,
        ),
        child: Wrap(
          spacing: AppTokens.space10,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary,
                borderRadius: BorderRadius.circular(AppTokens.radiusSm + 1),
              ),
              child: Icon(
                Icons.hub_outlined,
                size: 20,
                color: theme.colorScheme.onPrimary,
              ),
            ),
            Text(
              strings.appName,
              style: TextStyle(
                fontSize: 15,
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
    return Semantics(
      button: true,
      selected: selected,
      label: label,
      child: Tooltip(
        message: label,
        excludeFromSemantics: true,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(12, 2, 12, 2),
          child: AnimatedContainer(
            duration: AppMotion.feedbackDurationOf(context),
            curve: AppMotion.curve,
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
                  child: ExcludeSemantics(
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(minHeight: 44),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        child: Row(
                          children: [
                            const SizedBox(width: AppTokens.space8),
                            AnimatedContainer(
                              duration: AppMotion.feedbackDurationOf(context),
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
                            if (MediaQuery.textScalerOf(context).scale(14) <=
                                18) ...[
                              Icon(icon, size: 20, color: foreground),
                              const SizedBox(width: AppTokens.space10),
                            ],
                            Expanded(
                              child: Text(
                                label,
                                style: TextStyle(
                                  fontSize: 14,
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
      animation: Listenable.merge([statusStore, statusStore.parallelRooms]),
      builder: (context, _) {
        final (tone, label, detail) = _footerStatus(strings, statusStore);
        final colors = P2WlanColors.of(context);
        final dotColor = switch (tone) {
          StatusTone.good => colors.successDot,
          StatusTone.warn => colors.warningDot,
          StatusTone.bad => colors.dangerDot,
          StatusTone.neutral => colors.neutralDot,
        };
        final description = '$label, $detail';
        return Semantics(
          label: description,
          hint: strings.openTroubleshooting,
          button: true,
          child: Padding(
            padding: const EdgeInsets.all(AppTokens.space12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Container(
                  key: const Key('desktop-sidebar-status'),
                  decoration: BoxDecoration(
                    color: colors.surfaceMuted,
                    border: Border.all(color: colors.border),
                    borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                  ),
                  child: Tooltip(
                    message: '$label\n$detail\n${strings.openTroubleshooting}',
                    excludeFromSemantics: true,
                    child: Material(
                      type: MaterialType.transparency,
                      child: InkWell(
                        onTap: onTap,
                        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                        hoverColor: colors.hoverSurface,
                        child: ExcludeSemantics(
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
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        label,
                                        style: TextStyle(
                                          fontSize: 13,
                                          fontWeight: FontWeight.w600,
                                          color: theme.colorScheme.onSurface,
                                        ),
                                      ),
                                      const SizedBox(height: 2),
                                      Text(
                                        detail,
                                        style: TextStyle(
                                          fontSize: 12,
                                          color: theme
                                              .colorScheme
                                              .onSurfaceVariant,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                                if (MediaQuery.textScalerOf(context)
                                        .scale(13) <=
                                    18)
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
                ),
              ],
            ),
          ),
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
    return networkOverviewStatus(strings, NetworkOverview.read(store));
  }
}
