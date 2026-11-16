import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/navigation_model.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/state/status_store.dart';
import '../../core/presentation/network_overview.dart';
import '../network_overview_presentation.dart';
import 'app_motion.dart';
import 'desktop_card.dart';
import 'desktop_icon.dart';
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

  static const width = 192.0;

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
                padding: const EdgeInsets.symmetric(
                  horizontal: AppTokens.space16,
                ),
                children: [
                  for (final section in P2WlanSection.primary) ...[
                    SidebarItem(
                      key: ValueKey('sidebar-${section.name}'),
                      icon: section.icon,
                      desktopIcon: switch (section) {
                        P2WlanSection.home => 'home',
                        P2WlanSection.devices => 'monitor',
                        P2WlanSection.interconnect => 'users',
                        P2WlanSection.settings => 'settings',
                        P2WlanSection.troubleshooting => 'activity',
                      },
                      label: strings.sectionLabel(section.name),
                      selected: selected == section,
                      shortcut: shortcuts[section],
                      onTap: () => onSelect(section),
                    ),
                    const SizedBox(height: 5),
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
      padding: const EdgeInsets.fromLTRB(22, 18, AppTokens.space16, 26),
      child: Row(
        children: [
          const SidebarBrandMark(size: 34),
          const SizedBox(width: AppTokens.space10),
          Expanded(
            child: Text(
              strings.appName,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.titleMedium?.copyWith(
                color: theme.colorScheme.primary,
                fontSize: 17,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SidebarFooter extends StatefulWidget {
  const _SidebarFooter({
    required this.strings,
    required this.statusStore,
    required this.onTap,
  });

  final AppStrings strings;
  final StatusStore statusStore;
  final VoidCallback onTap;

  @override
  State<_SidebarFooter> createState() => _SidebarFooterState();
}

class _SidebarFooterState extends State<_SidebarFooter> {
  bool _hovered = false;
  bool _focused = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = widget.strings;
    final statusStore = widget.statusStore;
    return AnimatedBuilder(
      animation: Listenable.merge([statusStore, statusStore.parallelRooms]),
      builder: (context, _) {
        final (tone, label, detail) = networkOverviewStatus(
          strings,
          NetworkOverview.read(statusStore),
        );
        final colors = P2WlanColors.of(context);
        final (dotColor, dotBackground) = switch (tone) {
          StatusTone.good => (colors.successDot, colors.successSurface),
          StatusTone.warn => (colors.warningDot, colors.warningSurface),
          StatusTone.bad => (colors.dangerDot, colors.dangerSurface),
          StatusTone.neutral => (colors.neutralDot, colors.neutralSurface),
        };
        final radius = BorderRadius.circular(AppTokens.radiusMd);
        final border = _focused
            ? theme.colorScheme.primary
            : _hovered
            ? colors.successBorder
            : DesktopCard.borderOf(context);
        return Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Semantics(
            label: '$label, $detail',
            hint: strings.openTroubleshooting,
            button: true,
            child: AnimatedContainer(
              key: const Key('desktop-sidebar-status'),
              duration: AppMotion.feedbackDurationOf(context),
              decoration: BoxDecoration(
                color: _hovered
                    ? colors.selectedSurface
                    : colors.surfaceElevated,
                border: Border.all(color: border),
                borderRadius: radius,
              ),
              child: Tooltip(
                message: '$label\n$detail\n${strings.openTroubleshooting}',
                excludeFromSemantics: true,
                child: Material(
                  type: MaterialType.transparency,
                  child: InkWell(
                    onTap: widget.onTap,
                    onHover: (hovered) => setState(() => _hovered = hovered),
                    onFocusChange: (focused) =>
                        setState(() => _focused = focused),
                    mouseCursor: SystemMouseCursors.click,
                    borderRadius: radius,
                    overlayColor: const WidgetStatePropertyAll(
                      Colors.transparent,
                    ),
                    child: ExcludeSemantics(
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(minHeight: 60),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 9,
                            vertical: 9,
                          ),
                          child: Row(
                            children: [
                              SizedBox.square(
                                dimension: 22,
                                child: DecoratedBox(
                                  decoration: BoxDecoration(
                                    color: dotBackground,
                                    shape: BoxShape.circle,
                                  ),
                                  child: Center(
                                    child: SizedBox.square(
                                      dimension: 7,
                                      child: DecoratedBox(
                                        decoration: BoxDecoration(
                                          color: dotColor,
                                          shape: BoxShape.circle,
                                        ),
                                      ),
                                    ),
                                  ),
                                ),
                              ),
                              const SizedBox(width: AppTokens.space8),
                              Expanded(
                                child: Column(
                                  mainAxisSize: MainAxisSize.min,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      label,
                                      style: theme.textTheme.labelMedium
                                          ?.copyWith(
                                            fontWeight: FontWeight.w600,
                                          ),
                                    ),
                                    const SizedBox(height: AppTokens.space2),
                                    Text(
                                      detail,
                                      style: theme.textTheme.labelSmall
                                          ?.copyWith(
                                            color: colors.textSecondary,
                                            fontFeatures:
                                                AppTokens.tabularFontFeatures,
                                          ),
                                    ),
                                  ],
                                ),
                              ),
                              if (MediaQuery.textScalerOf(context).scale(13) <=
                                  18)
                                const DesktopIcon('chevron-right', size: 14),
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
        );
      },
    );
  }
}
