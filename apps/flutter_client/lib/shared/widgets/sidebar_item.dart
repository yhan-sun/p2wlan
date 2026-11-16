import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import 'app_motion.dart';
import 'desktop_icon.dart';

/// The navigation interaction used by the labeled sidebar and the compact rail.
class SidebarItem extends StatefulWidget {
  const SidebarItem({
    super.key,
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
    this.iconOnly = false,
    this.shortcut,
    this.desktopIcon,
  });

  final IconData icon;
  final String label;
  final bool selected;
  final bool iconOnly;
  final String? shortcut;
  final String? desktopIcon;
  final VoidCallback onTap;

  @override
  State<SidebarItem> createState() => _SidebarItemState();
}

class _SidebarItemState extends State<SidebarItem> {
  var _focused = false;
  var _hovered = false;
  var _pressed = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final foreground = widget.selected
        ? theme.colorScheme.primary
        : colors.textSecondary;
    final radius = BorderRadius.circular(AppTokens.radiusMd);
    final background = widget.selected
        ? colors.selectedSurface
        : _hovered
        ? colors.hoverSurface
        : Colors.transparent;
    final fill = _pressed
        ? Color.alphaBlend(foreground.withValues(alpha: .12), background)
        : background;
    return Semantics(
      button: true,
      selected: widget.selected,
      label: widget.label,
      child: Tooltip(
        message: [widget.label, ?widget.shortcut].join('  '),
        excludeFromSemantics: true,
        child: AnimatedContainer(
          duration: AppMotion.feedbackDurationOf(context),
          curve: AppMotion.curve,
          decoration: BoxDecoration(
            color: fill,
            borderRadius: radius,
            border: Border.all(
              color: _focused ? theme.colorScheme.primary : Colors.transparent,
            ),
          ),
          child: Material(
            type: MaterialType.transparency,
            child: InkWell(
              mouseCursor: SystemMouseCursors.click,
              borderRadius: radius,
              overlayColor: const WidgetStatePropertyAll(Colors.transparent),
              splashFactory: NoSplash.splashFactory,
              onFocusChange: (value) => setState(() => _focused = value),
              onHover: (value) => setState(() => _hovered = value),
              onHighlightChanged: (value) => setState(() => _pressed = value),
              onTap: widget.onTap,
              child: ExcludeSemantics(
                child: ConstrainedBox(
                  constraints: BoxConstraints(
                    minHeight: widget.desktopIcon != null
                        ? 42
                        : AppTokens.desktopControlHeight,
                  ),
                  child: widget.iconOnly
                      ? Center(child: _icon(foreground, AppTokens.iconMd))
                      : Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: AppTokens.space12,
                            vertical: AppTokens.space4,
                          ),
                          child: Row(
                            children: [
                              _icon(
                                foreground,
                                widget.desktopIcon == null
                                    ? AppTokens.iconSm
                                    : 17,
                              ),
                              const SizedBox(width: AppTokens.space10),
                              Expanded(
                                child: Text(
                                  widget.label,
                                  style: theme.textTheme.labelLarge?.copyWith(
                                    color: foreground,
                                    fontSize: widget.desktopIcon == null
                                        ? null
                                        : 14,
                                    fontWeight: widget.selected
                                        ? FontWeight.w700
                                        : FontWeight.w500,
                                  ),
                                ),
                              ),
                              if (widget.shortcut != null &&
                                  MediaQuery.textScalerOf(context).scale(11) <=
                                      14)
                                Padding(
                                  padding: const EdgeInsetsDirectional.only(
                                    start: 4,
                                  ),
                                  child: Text(
                                    widget.shortcut!,
                                    style: theme.textTheme.labelSmall?.copyWith(
                                      color: colors.textMuted,
                                      fontFeatures:
                                          AppTokens.tabularFontFeatures,
                                    ),
                                  ),
                                ),
                            ],
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

  Widget _icon(Color color, double size) => widget.desktopIcon == null
      ? Icon(widget.icon, size: size, color: color)
      : DesktopIcon(widget.desktopIcon!, size: size, color: color);
}

/// The P2WLAN loop from the app icon, rendered in a single color at small sizes.
class SidebarBrandMark extends StatelessWidget {
  const SidebarBrandMark({super.key, this.size = 28});

  final double size;

  @override
  Widget build(BuildContext context) => DesktopIcon(
    'infinity',
    size: size,
    color: Theme.of(context).colorScheme.primary,
  );
}
