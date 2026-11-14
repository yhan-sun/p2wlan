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

/// Compact desktop and medium non-desktop navigation.
///
/// This is intentionally not Material's [NavigationRail]. A desktop-sized
/// window should keep a quiet, native-style navigation surface: labels are
/// horizontal when present, and compact desktop shows only icon buttons with
/// tooltips. It never uses the stock icon-above-label presentation.
class AppNavRail extends StatelessWidget {
  const AppNavRail({
    super.key,
    required this.selected,
    required this.iconOnly,
    required this.strings,
    required this.statusStore,
    required this.onSelect,
    required this.onFooterTap,
    this.shortcuts = const {},
  });

  /// Labeled width for non-desktop medium layouts.
  static const expandedWidth = 156.0;

  /// Compact desktop width: icon buttons and a bottom status entry.
  static const compactWidth = 56.0;

  /// Current section; secondary/non-primary sections render no selection.
  final P2WlanSection? selected;
  final bool iconOnly;
  final AppStrings strings;
  final StatusStore statusStore;
  final ValueChanged<P2WlanSection> onSelect;
  final VoidCallback onFooterTap;
  final Map<P2WlanSection, String> shortcuts;

  @override
  Widget build(BuildContext context) {
    return Container(
      key: const Key('app-nav-rail-surface'),
      width: iconOnly ? compactWidth : expandedWidth,
      color: P2WlanColors.of(context).surfaceMuted,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _RailBrand(strings: strings, iconOnly: iconOnly),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(
                  AppTokens.space8,
                  0,
                  AppTokens.space8,
                  AppTokens.space8,
                ),
                children: [
                  for (final (index, group)
                      in P2WlanSection.sidebarGroups.indexed) ...[
                    if (index > 0)
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 5),
                        child: Divider(indent: 8, endIndent: 8),
                      ),
                    for (final section in group)
                      SidebarItem(
                        key: ValueKey(section),
                        icon: section.icon,
                        shortcut: shortcuts[section],
                        iconOnly: iconOnly,
                        selected: selected == section,
                        label: strings.sectionLabel(section.name),
                        onTap: () => onSelect(section),
                      ),
                  ],
                ],
              ),
            ),
            if (iconOnly)
              _CompactRailStatus(
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

class _RailBrand extends StatelessWidget {
  const _RailBrand({required this.strings, required this.iconOnly});

  final AppStrings strings;
  final bool iconOnly;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    const mark = SidebarBrandMark();
    if (iconOnly) {
      return Tooltip(
        message: strings.appName,
        child: SizedBox(
          key: const Key('compact-sidebar-brand'),
          height: 52,
          child: Center(child: mark),
        ),
      );
    }
    return SizedBox(
      key: const Key('rail-brand'),
      height: 52,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: AppTokens.space12),
        child: Row(
          children: [
            mark,
            const SizedBox(width: AppTokens.space8),
            Text(
              strings.appName,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 13,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CompactRailStatus extends StatelessWidget {
  const _CompactRailStatus({
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
        final (tone, label, detail) = _status(strings, statusStore);
        final colors = P2WlanColors.of(context);
        final dotColor = switch (tone) {
          StatusTone.good => colors.successDot,
          StatusTone.warn => colors.warningDot,
          StatusTone.bad => colors.dangerDot,
          StatusTone.neutral => colors.neutralDot,
        };
        return Container(
          key: const Key('compact-sidebar-status'),
          decoration: BoxDecoration(
            border: Border(top: BorderSide(color: theme.colorScheme.outline)),
          ),
          child: Tooltip(
            message: [
              strings.openTroubleshooting,
              '$label · $detail',
            ].join(': '),
            excludeFromSemantics: true,
            child: Semantics(
              label: '$label, $detail',
              hint: strings.openTroubleshooting,
              button: true,
              child: Material(
                type: MaterialType.transparency,
                child: InkWell(
                  onTap: onTap,
                  hoverColor: colors.hoverSurface,
                  child: SizedBox(
                    height: 48,
                    child: Center(child: _StatusDot(color: dotColor)),
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  (StatusTone, String, String) _status(AppStrings strings, StatusStore store) {
    return networkOverviewStatus(strings, NetworkOverview.read(store));
  }
}

class _StatusDot extends StatelessWidget {
  const _StatusDot({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(color: color, shape: BoxShape.circle),
    );
  }
}
