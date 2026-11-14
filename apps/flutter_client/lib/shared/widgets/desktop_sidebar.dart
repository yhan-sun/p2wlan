import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/navigation_model.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/state/status_store.dart';
import '../../core/presentation/network_overview.dart';
import '../network_overview_presentation.dart';
import 'sidebar_item.dart';
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
    this.shortcuts = const {},
  });

  static const width = 176.0;

  final P2WlanSection? selected;
  final AppStrings strings;
  final StatusStore statusStore;
  final ValueChanged<P2WlanSection> onSelect;
  final VoidCallback onFooterTap;
  final Map<P2WlanSection, String> shortcuts;

  @override
  Widget build(BuildContext context) {
    return Container(
      key: const Key('desktop-sidebar-surface'),
      width: width,
      color: P2WlanColors.of(context).surfaceMuted,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _SidebarBrandHeader(strings: strings),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(
                  AppTokens.space12,
                  0,
                  AppTokens.space12,
                  AppTokens.space8,
                ),
                children: [
                  for (final (index, group)
                      in P2WlanSection.sidebarGroups.indexed) ...[
                    if (index > 0)
                      const Padding(
                        padding: EdgeInsets.symmetric(
                          vertical: AppTokens.space12,
                        ),
                        child: Divider(
                          indent: AppTokens.space4,
                          endIndent: AppTokens.space4,
                        ),
                      ),
                    for (final section in group)
                      SidebarItem(
                        key: ValueKey('sidebar-${section.name}'),
                        icon: section.icon,
                        label: strings.sectionLabel(section.name),
                        selected: selected == section,
                        shortcut: shortcuts[section],
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
    return Padding(
      key: const Key('desktop-sidebar-brand'),
      padding: const EdgeInsets.fromLTRB(
        AppTokens.space20,
        AppTokens.space16,
        AppTokens.space12,
        AppTokens.space20,
      ),
      child: Row(
        children: [
          const SidebarBrandMark(),
          const SizedBox(width: AppTokens.space8),
          Expanded(
            child: Text(
              strings.appName,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.titleMedium,
            ),
          ),
        ],
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
          child: Container(
            key: const Key('desktop-sidebar-status'),
            decoration: BoxDecoration(
              border: Border(top: BorderSide(color: colors.border)),
            ),
            child: Tooltip(
              message: '$label\n$detail\n${strings.openTroubleshooting}',
              excludeFromSemantics: true,
              child: Material(
                type: MaterialType.transparency,
                child: InkWell(
                  onTap: onTap,
                  mouseCursor: SystemMouseCursors.click,
                  hoverColor: colors.hoverSurface,
                  child: ExcludeSemantics(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: AppTokens.space16,
                        vertical: AppTokens.space12,
                      ),
                      child: Row(
                        children: [
                          SizedBox.square(
                            dimension: AppTokens.space8,
                            child: DecoratedBox(
                              decoration: BoxDecoration(
                                color: dotColor,
                                shape: BoxShape.circle,
                              ),
                            ),
                          ),
                          const SizedBox(width: AppTokens.space8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(label, style: theme.textTheme.labelLarge),
                                const SizedBox(height: AppTokens.space2),
                                Text(
                                  detail,
                                  style: theme.textTheme.labelSmall?.copyWith(
                                    color: colors.textSecondary,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          if (MediaQuery.textScalerOf(context).scale(13) <= 18)
                            Icon(
                              Icons.chevron_right_rounded,
                              size: AppTokens.iconSm,
                              color: colors.textMuted,
                            ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
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
