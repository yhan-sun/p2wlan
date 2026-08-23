import 'package:flutter/material.dart';

import '../../app/app_strings.dart';

/// Product back button that follows the app's selected language rather than
/// the device locale. [BackButtonIcon] keeps the correct platform/direction
/// glyph while the default action pops exactly one Navigator route.
class AppBackButton extends StatelessWidget {
  const AppBackButton({super.key, this.onPressed});

  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    return IconButton(
      tooltip: AppStringsScope.of(context).back,
      onPressed: onPressed ?? () => Navigator.of(context).maybePop(),
      icon: const BackButtonIcon(),
    );
  }
}
