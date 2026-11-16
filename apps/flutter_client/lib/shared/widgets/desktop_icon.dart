import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import '../../app/p2wlan_colors.dart';

/// Line artwork shared by the desktop pages and sidebar.
class DesktopIcon extends StatelessWidget {
  const DesktopIcon(this.name, {super.key, this.size = 18, this.color});

  final String name;
  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final foreground = color ?? P2WlanColors.of(context).textMuted;
    final asset = switch ((name, size)) {
      ('monitor', 23) => 'monitor-local',
      ('chevron-right', 14) => 'chevron-right-muted',
      _ => name,
    };
    return SvgPicture.asset(
      'assets/desktop_icons/$asset.svg',
      width: size,
      height: size,
      theme: SvgTheme(currentColor: foreground),
      colorFilter: name == 'sliders'
          ? null
          : ColorFilter.mode(foreground, BlendMode.srcIn),
      excludeFromSemantics: true,
    );
  }
}
