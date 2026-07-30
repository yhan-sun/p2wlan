import 'package:flutter/material.dart';

import '../../app/app_motion.dart';
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
    final (bg, border, text) = _colors();
    final duration = AppMotion.duration(context, AppTokens.durationFast);
    return AnimatedContainer(
      duration: duration,
      curve: AppTokens.curveEase,
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
            decoration: BoxDecoration(color: text, shape: BoxShape.circle),
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
                letterSpacing: -0.1,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }

  (Color, Color, Color) _colors() {
    return switch (tone) {
      StatusTone.good => (
        AppTokens.colorGoodBg,
        AppTokens.colorGoodBorder,
        AppTokens.colorGoodText,
      ),
      StatusTone.warn => (
        AppTokens.colorWarnBg,
        AppTokens.colorWarnBorder,
        AppTokens.colorWarnText,
      ),
      StatusTone.bad => (
        AppTokens.colorBadBg,
        AppTokens.colorBadBorder,
        AppTokens.colorBadText,
      ),
      StatusTone.neutral => (
        AppTokens.colorNeutralBg,
        AppTokens.colorNeutralBorder,
        AppTokens.colorNeutralText,
      ),
    };
  }
}
