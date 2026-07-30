import 'package:flutter/material.dart';

abstract final class AppMotion {
  static bool disableAnimations(BuildContext context) {
    return MediaQuery.maybeDisableAnimationsOf(context) ?? false;
  }

  static Duration duration(BuildContext context, Duration duration) {
    return disableAnimations(context) ? Duration.zero : duration;
  }
}
