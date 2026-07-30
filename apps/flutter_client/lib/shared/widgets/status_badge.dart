import 'package:flutter/material.dart';

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
    final surfaceColor = Theme.of(context).colorScheme.surface;
    final (bg, border, text, dot) = _colors(surfaceColor);
    return Container(
      constraints: const BoxConstraints(minHeight: 24, maxWidth: 200),
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
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
          const SizedBox(width: 6),
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

  (Color, Color, Color, Color) _colors(Color surface) {
    return switch (tone) {
      StatusTone.good => (
        surface,
        AppTokens.colorGoodBorder,
        AppTokens.colorGoodText,
        AppTokens.colorGoodText,
      ),
      StatusTone.warn => (
        surface,
        AppTokens.colorWarnBorder,
        AppTokens.colorWarnText,
        AppTokens.colorWarnText,
      ),
      StatusTone.bad => (
        surface,
        AppTokens.colorBadBorder,
        AppTokens.colorBadText,
        AppTokens.colorBadText,
      ),
      StatusTone.neutral => (
        surface,
        AppTokens.colorNeutralBorder,
        AppTokens.colorNeutralText,
        AppTokens.colorNeutralText,
      ),
    };
  }
}
