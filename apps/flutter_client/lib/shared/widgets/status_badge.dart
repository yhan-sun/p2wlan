import 'package:flutter/material.dart';

import '../../app/p2wlan_colors.dart';
import '../../app/app_tokens.dart';

enum StatusTone { good, warn, bad, neutral }

class StatusBadge extends StatelessWidget {
  const StatusBadge({
    super.key,
    required this.label,
    this.tone = StatusTone.neutral,
  });

  final String label;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final (bg, border, text, dot) = _colors(context);
    return Container(
      constraints: const BoxConstraints(minHeight: 24, maxWidth: 200),
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space8,
        vertical: AppTokens.space4,
      ),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: border, width: 1),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(color: dot, shape: BoxShape.circle),
          ),
          const SizedBox(width: AppTokens.space6),
          Flexible(
            child: Text(
              label,
              overflow: TextOverflow.ellipsis,
              maxLines: 1,
              style: TextStyle(
                color: text,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                letterSpacing: 0,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }

  (Color, Color, Color, Color) _colors(BuildContext context) {
    final c = P2WlanColors.of(context);
    return switch (tone) {
      StatusTone.good => (
        c.successSurface,
        c.successBorder,
        c.successText,
        c.successDot,
      ),
      StatusTone.warn => (
        c.warningSurface,
        c.warningBorder,
        c.warningText,
        c.warningDot,
      ),
      StatusTone.bad => (
        c.dangerSurface,
        c.dangerBorder,
        c.dangerText,
        c.dangerDot,
      ),
      StatusTone.neutral => (
        c.neutralSurface,
        c.neutralBorder,
        c.neutralText,
        c.neutralDot,
      ),
    };
  }
}
