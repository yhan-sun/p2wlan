import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/navigation_model.dart';
import '../../app/p2wlan_colors.dart';

/// Custom primary navigation rail for medium layouts (tablet / small desktop
/// windows) and compact desktop windows.
///
/// Deliberately not Material's `NavigationRail`: the stock widget's pill
/// indicator reads as a Material demo, while the shell needs a quiet
/// native-style rail (subtle selected surface, short left accent bar, muted
/// hover). Window width and input form factor are different things — a
/// desktop window squeezed below the compact width must not become a phone
/// bottom bar.
class AppNavRail extends StatelessWidget {
  const AppNavRail({
    super.key,
    required this.selected,
    required this.iconOnly,
    required this.strings,
    required this.onSelect,
  });

  /// Rail width when labels are shown (medium layouts).
  static const expandedWidth = 88.0;

  /// Rail width for compact desktop windows (icon-only).
  static const compactWidth = 60.0;

  /// Current section; secondary sections (tunnels) render no selection.
  final P2WlanSection? selected;
  final bool iconOnly;
  final AppStrings strings;
  final ValueChanged<P2WlanSection> onSelect;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: iconOnly ? compactWidth : expandedWidth,
      color: theme.colorScheme.surface,
      child: SafeArea(
        child: Column(
          children: [
            for (final section in P2WlanSection.primary)
              _NavRailItem(
                section: section,
                iconOnly: iconOnly,
                selected: selected == section,
                label: strings.sectionLabel(section.name),
                onTap: () => onSelect(section),
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
    // Icon-only rail: labels are hidden from pixels but the tooltip keeps the
    // destination discoverable.
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
      fontSize: 12,
      fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
      color: foreground,
    );
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
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
              height: iconOnly ? 44 : 56,
              child: Stack(
                children: [
                  if (selected)
                    Align(
                      alignment: Alignment.centerLeft,
                      child: Container(
                        width: 3,
                        height: 18,
                        margin: const EdgeInsets.only(left: 3),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.primary,
                          borderRadius: BorderRadius.circular(2),
                        ),
                      ),
                    ),
                  if (iconOnly)
                    Center(child: Icon(icon, size: 20, color: foreground))
                  else
                    Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(icon, size: 20, color: foreground),
                        const SizedBox(height: AppTokens.space4),
                        Text(label, maxLines: 1, style: labelStyle),
                      ],
                    ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
