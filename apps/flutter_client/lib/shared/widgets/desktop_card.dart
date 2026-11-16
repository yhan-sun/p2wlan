import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';

/// The desktop surface used for lists, metrics and other grouped content.
class DesktopCard extends StatelessWidget {
  const DesktopCard({
    super.key,
    required this.child,
    this.padding = EdgeInsets.zero,
    this.borderColor,
  });

  final Widget child;
  final EdgeInsetsGeometry padding;
  final Color? borderColor;

  static Color borderOf(BuildContext context) =>
      Theme.of(context).brightness == Brightness.light
      ? AppTokens.colorDesktopBorder
      : P2WlanColors.of(context).border;

  static BoxDecoration decorationOf(
    BuildContext context, {
    Color? borderColor,
  }) {
    final dark = Theme.of(context).brightness == Brightness.dark;
    return BoxDecoration(
      color: P2WlanColors.of(context).surfaceElevated,
      border: Border.all(color: borderColor ?? borderOf(context)),
      borderRadius: BorderRadius.circular(AppTokens.radiusLg),
      boxShadow: [
        BoxShadow(
          color: dark ? const Color(0x2A000000) : const Color(0x0C102B20),
          offset: const Offset(0, 2),
          blurRadius: 5,
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: decorationOf(context, borderColor: borderColor),
      child: Material(
        type: MaterialType.transparency,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        clipBehavior: Clip.antiAlias,
        child: Padding(padding: padding, child: child),
      ),
    );
  }
}
