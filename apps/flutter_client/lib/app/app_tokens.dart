import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

/// Design tokens for P2WLAN Flutter Client UI/UX.
/// Calm connectivity aesthetic: modern, reliable, precise, and platform-neutral.
abstract final class AppTokens {
  // --- Color Palette ---
  // Reference-aligned light neutral background & surfaces.
  static const colorBg = Color(0xFFF6F7F8);
  static const colorSurface = Color(0xFFFFFFFF);
  static const colorSurfaceSubtle = Color(0xFFF8FAFC);
  static const colorBorder = Color(0xFFE6E9EB);
  static const colorBorderSubtle = Color(0xFFF0F2F4);

  // Dark theme neutral background & surfaces
  static const colorDarkBg = Color(0xFF0B1220);
  static const colorDarkSurface = Color(0xFF111827);
  static const colorDarkSurfaceSubtle = Color(0xFF172033);
  static const colorDarkBorder = Color(0xFF2A3547);
  static const colorDarkBorderSubtle = Color(0xFF202A3A);

  // Text hierarchy
  static const colorTextPrimary = Color(0xFF171A1F);
  static const colorTextSecondary = Color(0xFF667078);
  static const colorTextMuted = Color(0xFF8A949E);

  // Dark text hierarchy
  static const colorDarkTextPrimary = Color(0xFFF7F9FC);
  static const colorDarkTextSecondary = Color(0xFFB5C0D0);
  static const colorDarkTextMuted = Color(0xFF7F8BA0);

  // Brand blue from the approved visual reference.
  static const colorAccent = Color(0xFF2563EB);
  static const colorAccentMuted = Color(0xFF1D4ED8);

  // Dark mode raises blue lightness for contrast while preserving brand hue.
  static const colorDarkAccent = Color(0xFF60A5FA);
  static const colorDarkAccentMuted = Color(0xFF1E3A8A);

  // Status Tones (Semantic, strictly scoped)
  // Good / Online / Direct
  static const colorGoodBg = Color(0xFFF0FDF4);
  static const colorGoodBorder = Color(0xFFBBF7D0);
  static const colorGoodText = Color(0xFF15803D);

  // Warning / Degraded / Probing
  static const colorWarnBg = Color(0xFFFFFBEB);
  static const colorWarnBorder = Color(0xFFFDE68A);
  static const colorWarnText = Color(0xFFB45309);

  // Bad / Unhealthy / Actual failures
  static const colorBadBg = Color(0xFFFEF2F2);
  static const colorBadBorder = Color(0xFFFECACA);
  static const colorBadText = Color(0xFFDC2626);

  // Neutral / Offline / Skipped / Idle
  static const colorNeutralBg = Color(0xFFF3F4F6);
  static const colorNeutralBorder = Color(0xFFD1D5DB);
  static const colorNeutralText = Color(0xFF667078);

  // Dark status tones keep semantic color visible on dark surfaces without
  // falling back to pale light-theme labels.
  static const colorDarkGoodBg = Color(0xFF10241D);
  static const colorDarkGoodBorder = Color(0xFF2F7A4F);
  static const colorDarkGoodText = Color(0xFF8DE2B1);
  static const colorDarkGoodDot = Color(0xFF35C46F);

  static const colorDarkWarnBg = Color(0xFF2A2112);
  static const colorDarkWarnBorder = Color(0xFF7A5D24);
  static const colorDarkWarnText = Color(0xFFF1C96A);
  static const colorDarkWarnDot = Color(0xFFE3A92F);

  static const colorDarkBadBg = Color(0xFF2B1716);
  static const colorDarkBadBorder = Color(0xFF8E423D);
  static const colorDarkBadText = Color(0xFFFFA39A);
  static const colorDarkBadDot = Color(0xFFEF5D54);

  static const colorDarkNeutralBg = Color(0xFF1D2927);
  static const colorDarkNeutralBorder = Color(0xFF3A4A47);
  static const colorDarkNeutralText = Color(0xFFB8C7C4);
  static const colorDarkNeutralDot = Color(0xFF81918E);

  // Debug Console / Raw JSON
  static const colorConsoleBg = Color(0xFF111817);
  static const colorConsoleBorder = Color(0xFF26312F);
  static const colorConsoleText = Color(0xFFE5ECE8);

  static const shadowBorder = [
    BoxShadow(color: Color(0x0D0F172A), blurRadius: 0, spreadRadius: 1),
    BoxShadow(
      color: Color(0x0F0F172A),
      offset: Offset(0, 6),
      blurRadius: 20,
      spreadRadius: -8,
    ),
  ];

  // --- Radius & Spacing ---
  static const radiusSm = 8.0;
  static const radiusMd = 10.0;
  static const radiusLg = 14.0;

  // --- Spacing scale (visual rhythm) ---
  // page/section/card rhythm uses these; per-row or painter-specific offsets
  // may stay local literals.
  static const space2 = 2.0;
  static const space4 = 4.0;
  static const space6 = 6.0;
  static const space8 = 8.0;
  static const space10 = 10.0;
  static const space12 = 12.0;
  static const space14 = 14.0;
  static const space16 = 16.0;
  static const space20 = 20.0;
  static const space24 = 24.0;
  static const space32 = 32.0;
  static const space40 = 40.0;

  // Touch Targets
  static const minTouchTarget = 44.0;

  // --- Durations & Curves ---
  static const durationFast = Duration(milliseconds: 110);
  static const durationMedium = Duration(milliseconds: 160);
  static const curveEase = Curves.easeOutQuart;

  // --- Tabular Figures TextStyle modifier ---
  static const tabularFontFeatures = [FontFeature.tabularFigures()];

  // Prefer modern, readable CJK UI fonts before generic platform fallbacks.
  // This avoids Windows falling back to older serif-style Chinese glyphs.
  static const fontFamilyFallback = [
    'Microsoft YaHei UI',
    'Microsoft YaHei',
    'PingFang SC',
    'Noto Sans CJK SC',
    'Source Han Sans SC',
    'Hiragino Sans GB',
    'WenQuanYi Micro Hei',
    'Segoe UI',
    'Arial',
    'sans-serif',
  ];

  /// Use the native UI family for Latin text on each desktop/mobile platform
  /// and let the ordered fallback list fill in CJK glyphs. In particular,
  /// Windows must not inherit the renderer's generic fallback family: that
  /// produces visibly mismatched weights and awkward Chinese glyph metrics.
  static String get primaryFontFamily => switch (defaultTargetPlatform) {
    TargetPlatform.windows => 'Segoe UI',
    TargetPlatform.macOS || TargetPlatform.iOS => 'SF Pro Text',
    TargetPlatform.android || TargetPlatform.fuchsia => 'Roboto',
    TargetPlatform.linux => 'Noto Sans',
  };
}
