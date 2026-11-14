import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import 'app_motion.dart';

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
  });

  final IconData icon;
  final String label;
  final bool selected;
  final bool iconOnly;
  final String? shortcut;
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
    final radius = BorderRadius.circular(AppTokens.radiusSm);
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
                  constraints: const BoxConstraints(
                    minHeight: AppTokens.desktopControlHeight,
                  ),
                  child: Stack(
                    alignment: AlignmentDirectional.centerStart,
                    children: [
                      if (widget.iconOnly)
                        Center(
                          child: Icon(
                            widget.icon,
                            size: AppTokens.iconMd,
                            color: foreground,
                          ),
                        )
                      else
                        Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: AppTokens.space12,
                            vertical: AppTokens.space4,
                          ),
                          child: Row(
                            children: [
                              Icon(
                                widget.icon,
                                size: AppTokens.iconSm,
                                color: foreground,
                              ),
                              const SizedBox(width: AppTokens.space8),
                              Expanded(
                                child: Text(
                                  widget.label,
                                  style: theme.textTheme.labelLarge?.copyWith(
                                    color: foreground,
                                    fontWeight: widget.selected
                                        ? FontWeight.w600
                                        : FontWeight.w500,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      AnimatedContainer(
                        duration: AppMotion.feedbackDurationOf(context),
                        curve: AppMotion.curve,
                        width: 2,
                        height: widget.selected ? AppTokens.space16 : 0,
                        decoration: BoxDecoration(
                          color: foreground,
                          borderRadius: BorderRadius.circular(
                            AppTokens.radiusXs,
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
    );
  }
}

/// The P2WLAN loop from the app icon, rendered in a single color at small sizes.
class SidebarBrandMark extends StatelessWidget {
  const SidebarBrandMark({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: scheme.primary,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
      ),
      child: CustomPaint(
        size: const Size.square(28),
        painter: _BrandLoop(scheme.onPrimary),
      ),
    );
  }
}

class _BrandLoop extends CustomPainter {
  const _BrandLoop(this.color);

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    canvas.scale(size.width / 28, size.height / 28);
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.2
      ..strokeCap = StrokeCap.round
      ..color = color;
    final loop = Path()
      ..moveTo(14, 14)
      ..cubicTo(16, 7, 23, 8, 23, 14)
      ..cubicTo(23, 20, 16, 21, 14, 14)
      ..cubicTo(12, 7, 5, 8, 5, 14)
      ..cubicTo(5, 20, 12, 21, 14, 14)
      ..close();
    canvas.drawPath(loop, paint);
  }

  @override
  bool shouldRepaint(_BrandLoop oldDelegate) => oldDelegate.color != color;
}
