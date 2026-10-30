part of '../settings_page.dart';

/// One focus/hover owner for settings category cards and the desktop rail.
/// The caller owns the single semantic button and its selected state.
class _SettingsTapSurface extends StatefulWidget {
  const _SettingsTapSurface({
    required this.child,
    required this.onTap,
    this.interactionKey,
    this.outlined = false,
    this.selected = false,
    this.radius = 12,
  });

  final Widget child;
  final VoidCallback onTap;
  final Key? interactionKey;
  final bool outlined;
  final bool selected;
  final double radius;

  @override
  State<_SettingsTapSurface> createState() => _SettingsTapSurfaceState();
}

class _SettingsTapSurfaceState extends State<_SettingsTapSurface> {
  var _focused = false;
  var _hovered = false;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final radius = BorderRadius.circular(widget.radius);
    final border = _focused
        ? Theme.of(context).colorScheme.primary
        : _hovered
        ? colors.borderStrong
        : widget.outlined
        ? colors.border
        : Colors.transparent;
    return Material(
      animationDuration: AppMotion.feedbackDurationOf(context),
      color: widget.selected
          ? colors.selectedSurface
          : _hovered
          ? colors.hoverSurface
          : widget.outlined
          ? colors.surface
          : Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: radius,
        side: BorderSide(color: border, width: _focused ? 1.5 : 1),
      ),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        key: widget.interactionKey,
        excludeFromSemantics: true,
        onTap: widget.onTap,
        onHover: (value) => setState(() => _hovered = value),
        onFocusChange: (value) => setState(() => _focused = value),
        mouseCursor: SystemMouseCursors.click,
        splashFactory: MediaQuery.disableAnimationsOf(context)
            ? NoSplash.splashFactory
            : InkRipple.splashFactory,
        hoverColor: Colors.transparent,
        focusColor: Colors.transparent,
        borderRadius: radius,
        child: widget.child,
      ),
    );
  }
}

class _SettingsSaveSlot extends StatefulWidget {
  const _SettingsSaveSlot({super.key, required this.child});

  final Widget child;

  @override
  State<_SettingsSaveSlot> createState() => _SettingsSaveSlotState();
}

class _SettingsSaveSlotState extends State<_SettingsSaveSlot> {
  // Reparent the current bar when reduced motion bypasses AnimatedSize.
  final _contentKey = GlobalKey();

  @override
  Widget build(BuildContext context) {
    final duration = AppMotion.durationOf(context);
    final child = KeyedSubtree(key: _contentKey, child: widget.child);
    if (duration == Duration.zero) return child;
    return AnimatedSize(
      duration: duration,
      curve: AppMotion.curve,
      alignment: Alignment.bottomCenter,
      child: child,
    );
  }
}

/// Preserve native mobile route/back behavior while respecting reduced motion.
class _SettingsCategoryRoute extends MaterialPageRoute<void> {
  _SettingsCategoryRoute({
    required this.duration,
    required super.builder,
    super.settings,
  });

  final Duration duration;

  @override
  Duration get transitionDuration => duration;

  @override
  Duration get reverseTransitionDuration => duration;
}
