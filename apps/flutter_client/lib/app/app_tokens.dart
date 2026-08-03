import 'package:flutter/material.dart';

/// Design tokens for P2WLAN Flutter Client UI/UX.
/// Native engineering aesthetic: calm, reliable, precise, full P2WLAN network client.
abstract final class AppTokens {
  // --- Color Palette ---
  // Cool light neutral background & surfaces
  static const colorBg = Color(0xFFF2F4F3);
  static const colorSurface = Color(0xFFFEFEFC);
  static const colorSurfaceSubtle = Color(0xFFF7F8F6);
  static const colorBorder = Color(0xFFDDE4E1);
  static const colorBorderSubtle = Color(0xFFE9EEEB);

  // Dark theme neutral background & surfaces
  static const colorDarkBg = Color(0xFF101716);
  static const colorDarkSurface = Color(0xFF182220);
  static const colorDarkSurfaceSubtle = Color(0xFF1F2B29);
  static const colorDarkBorder = Color(0xFF2E3D3A);
  static const colorDarkBorderSubtle = Color(0xFF263330);

  // Text hierarchy
  static const colorTextPrimary = Color(0xFF151A1D);
  static const colorTextSecondary = Color(0xFF48535A);
  static const colorTextMuted = Color(0xFF68757B);

  // Dark text hierarchy
  static const colorDarkTextPrimary = Color(0xFFEDF2F0);
  static const colorDarkTextSecondary = Color(0xFFA1AFAC);
  static const colorDarkTextMuted = Color(0xFF758582);

  // Brand / Low-frequency accent (Slate blue / Slate blue-teal)
  static const colorAccent = Color(0xFF173E3C);
  static const colorAccentMuted = Color(0xFF2A5653);

  // Dark Brand accent
  static const colorDarkAccent = Color(0xFF38BDF8);
  static const colorDarkAccentMuted = Color(0xFF1E3A4C);

  // Status Tones (Semantic, strictly scoped)
  // Good / Online / Direct
  static const colorGoodBg = Color(0xFFF2FAF5);
  static const colorGoodBorder = Color(0xFFB9DFC9);
  static const colorGoodText = Color(0xFF276044);

  // Warning / Degraded / Relay
  static const colorWarnBg = Color(0xFFFCF7EA);
  static const colorWarnBorder = Color(0xFFE6CD8F);
  static const colorWarnText = Color(0xFF755622);

  // Bad / Offline / Unhealthy
  static const colorBadBg = Color(0xFFFCF3F1);
  static const colorBadBorder = Color(0xFFE7B8AE);
  static const colorBadText = Color(0xFF8B372D);

  // Neutral / Skipped / Idle
  static const colorNeutralBg = Color(0xFFF1F4F3);
  static const colorNeutralBorder = Color(0xFFD3DCDA);
  static const colorNeutralText = Color(0xFF4C585D);

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
    BoxShadow(color: Color(0x12000000), blurRadius: 0, spreadRadius: 1),
    BoxShadow(
      color: Color(0x08000000),
      offset: Offset(0, 1),
      blurRadius: 2,
      spreadRadius: -1,
    ),
  ];

  // --- Radius & Spacing ---
  static const radiusSm = 6.0;
  static const radiusMd = 8.0;
  static const radiusLg = 12.0;

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
}
