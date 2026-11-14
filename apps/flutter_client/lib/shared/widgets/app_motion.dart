import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';

/// Restrained timing shared by navigation, feedback and disclosure surfaces.
abstract final class AppMotion {
  static const Curve curve = Curves.easeOutCubic;

  static Duration durationOf(BuildContext context) =>
      MediaQuery.disableAnimationsOf(context)
      ? Duration.zero
      : AppTokens.durationDisclosure;

  static Duration feedbackDurationOf(BuildContext context) =>
      MediaQuery.disableAnimationsOf(context)
      ? Duration.zero
      : AppTokens.durationFast;

  static Duration navigationDurationOf(BuildContext context) =>
      MediaQuery.disableAnimationsOf(context)
      ? Duration.zero
      : AppTokens.durationNavigation;

  static AnimationStyle expansionStyleOf(BuildContext context) =>
      AnimationStyle(
        duration: durationOf(context),
        reverseDuration: durationOf(context),
        curve: curve,
        reverseCurve: curve,
      );
}

/// Animate the current child without retaining an outgoing interactive tree.
/// The caller owns child keys and any lifecycle or session identity boundary.
class AppEntrance extends StatefulWidget {
  const AppEntrance({
    super.key,
    required this.identity,
    required this.child,
    this.navigation = false,
  });

  final Object identity;
  final bool navigation;
  final Widget child;

  @override
  State<AppEntrance> createState() => _AppEntranceState();
}

class _AppEntranceState extends State<AppEntrance>
    with SingleTickerProviderStateMixin {
  late final _controller = AnimationController(vsync: this, value: 1);

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _controller.duration = widget.navigation
        ? AppMotion.navigationDurationOf(context)
        : AppMotion.durationOf(context);
    if (_controller.duration == Duration.zero) _controller.value = 1;
  }

  @override
  void didUpdateWidget(covariant AppEntrance oldWidget) {
    super.didUpdateWidget(oldWidget);
    _controller.duration = widget.navigation
        ? AppMotion.navigationDurationOf(context)
        : AppMotion.durationOf(context);
    if (_controller.duration == Duration.zero) {
      _controller.value = 1;
    } else if (oldWidget.identity != widget.identity) {
      _controller.forward(from: 0);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => ClipRect(
    child: AnimatedBuilder(
      animation: _controller,
      child: widget.child,
      builder: (context, child) {
        final progress = AppMotion.curve.transform(_controller.value);
        return Opacity(
          // The first frame remains readable without keeping the old child.
          opacity: 0.85 + 0.15 * progress,
          child: Transform.translate(
            offset: Offset(0, 4 * (1 - progress)),
            child: child,
          ),
        );
      },
    ),
  );
}
