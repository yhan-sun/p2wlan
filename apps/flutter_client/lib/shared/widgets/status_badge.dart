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
    final (bg, border, text, dot) = _colors(context);
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

  (Color, Color, Color, Color) _colors(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    if (isDark) {
      return switch (tone) {
        StatusTone.good => (
          AppTokens.colorDarkGoodBg,
          AppTokens.colorDarkGoodBorder,
          AppTokens.colorDarkGoodText,
          AppTokens.colorDarkGoodDot,
        ),
        StatusTone.warn => (
          AppTokens.colorDarkWarnBg,
          AppTokens.colorDarkWarnBorder,
          AppTokens.colorDarkWarnText,
          AppTokens.colorDarkWarnDot,
        ),
        StatusTone.bad => (
          AppTokens.colorDarkBadBg,
          AppTokens.colorDarkBadBorder,
          AppTokens.colorDarkBadText,
          AppTokens.colorDarkBadDot,
        ),
        StatusTone.neutral => (
          AppTokens.colorDarkNeutralBg,
          AppTokens.colorDarkNeutralBorder,
          AppTokens.colorDarkNeutralText,
          AppTokens.colorDarkNeutralDot,
        ),
      };
    }

    return switch (tone) {
      StatusTone.good => (
        AppTokens.colorGoodBg,
        AppTokens.colorGoodBorder,
        AppTokens.colorGoodText,
        AppTokens.colorGoodText,
      ),
      StatusTone.warn => (
        AppTokens.colorWarnBg,
        AppTokens.colorWarnBorder,
        AppTokens.colorWarnText,
        AppTokens.colorWarnText,
      ),
      StatusTone.bad => (
        AppTokens.colorBadBg,
        AppTokens.colorBadBorder,
        AppTokens.colorBadText,
        AppTokens.colorBadText,
      ),
      StatusTone.neutral => (
        AppTokens.colorNeutralBg,
        AppTokens.colorNeutralBorder,
        AppTokens.colorNeutralText,
        AppTokens.colorNeutralText,
      ),
    };
  }
}
