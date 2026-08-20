import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/navigation_model.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/state/status_store.dart';
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
  });

  /// Labeled width for non-desktop medium layouts.
  static const expandedWidth = 156.0;

  /// Compact desktop width: icon buttons and a bottom status entry.
  static const compactWidth = 64.0;

  /// Current section; secondary/non-primary sections render no selection.
  final P2WlanSection? selected;
  final bool iconOnly;
  final AppStrings strings;
  final StatusStore statusStore;
  final ValueChanged<P2WlanSection> onSelect;
  final VoidCallback onFooterTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      key: const Key('app-nav-rail-surface'),
      width: iconOnly ? compactWidth : expandedWidth,
      color: theme.colorScheme.surface,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _RailBrand(strings: strings, iconOnly: iconOnly),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(
                  horizontal: AppTokens.space4,
                  vertical: AppTokens.space6,
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
                      _NavRailItem(
                        section: section,
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
    final mark = Container(
      width: 24,
      height: 24,
      decoration: BoxDecoration(
        color: theme.colorScheme.primary,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
      ),
      child: Icon(
        Icons.hub_outlined,
        size: 15,
        color: theme.colorScheme.onPrimary,
      ),
    );
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

class _NavRailItem extends StatelessWidget {
  const _NavRailItem({
    required this.section,
    required this.iconOnly,
    required this.selected,
    required this.label,
    required this.onTap,
  });

  final P2WlanSection section;
  final bool iconOnly;
  final bool selected;
  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final item = _RailItemSurface(
      icon: section.icon,
      iconOnly: iconOnly,
      selected: selected,
      label: label,
      onTap: onTap,
    );
    if (iconOnly) {
      return Tooltip(message: label, child: item);
    }
    return item;
  }
}

class _RailItemSurface extends StatelessWidget {
  const _RailItemSurface({
    required this.icon,
    required this.iconOnly,
    required this.selected,
    required this.label,
    required this.onTap,
  });

  final IconData icon;
  final bool iconOnly;
  final bool selected;
  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final foreground = selected
        ? theme.colorScheme.primary
        : theme.colorScheme.onSurfaceVariant;
    final labelStyle = TextStyle(
      fontSize: 13,
      fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
      color: foreground,
    );
    return MouseRegion(
      cursor: SystemMouseCursors.click,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: AppTokens.space4),
        child: AnimatedContainer(
          duration: AppTokens.durationMedium,
          curve: AppTokens.curveEase,
          decoration: BoxDecoration(
            color: selected ? colors.selectedSurface : Colors.transparent,
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          child: Material(
            type: MaterialType.transparency,
            child: InkWell(
              onTap: onTap,
              borderRadius: BorderRadius.circular(AppTokens.radiusSm),
              hoverColor: selected ? null : colors.hoverSurface,
              child: SizedBox(
                height: 40,
                child: Stack(
                  children: [
                    if (selected)
                      Align(
                        alignment: Alignment.centerLeft,
                        child: Container(
                          width: 2,
                          height: 18,
                          decoration: BoxDecoration(
                            color: theme.colorScheme.primary,
                            borderRadius: BorderRadius.circular(2),
                          ),
                        ),
                      ),
                    if (iconOnly)
                      Center(child: Icon(icon, size: 19, color: foreground))
                    else
                      Padding(
                        padding: const EdgeInsets.only(
                          left: AppTokens.space12,
                          right: AppTokens.space8,
                        ),
                        child: Row(
                          children: [
                            Icon(icon, size: 19, color: foreground),
                            const SizedBox(width: AppTokens.space10),
                            Expanded(
                              child: Text(
                                label,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: labelStyle,
                              ),
                            ),
                          ],
                        ),
                      ),
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
      animation: statusStore,
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
            child: Semantics(
              label: '$label, $detail',
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
