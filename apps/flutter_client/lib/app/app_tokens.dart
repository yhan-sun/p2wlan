import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

/// Design tokens for P2WLAN Flutter Client UI/UX.
/// Calm connectivity aesthetic: modern, reliable, precise, and platform-neutral.
abstract final class AppTokens {
  // Light theme: warm canvas, quiet surfaces and deep green controls.
  static const colorBg = Color(0xFFF7F7F4);
  static const colorSurface = Color(0xFFFCFCF9);
  static const colorSurfaceSubtle = Color(0xFFF0F1ED);
  static const colorBorder = Color(0xFFDBDFD8);
  static const colorBorderSubtle = Color(0xFFE6E8E2);
  static const colorTextPrimary = Color(0xFF1E2926);
  static const colorTextSecondary = Color(0xFF495752);
  static const colorTextMuted = Color(0xFF5C6963);
  static const colorAccent = Color(0xFF173E3C);

  // Dark theme: charcoal with a subtle green undertone.
  static const colorDarkBg = Color(0xFF1B1F1E);
  static const colorDarkSurface = Color(0xFF212624);
  static const colorDarkSurfaceSubtle = Color(0xFF252B28);
  static const colorDarkBorder = Color(0xFF363D38);
  static const colorDarkBorderSubtle = Color(0xFF303732);
  static const colorDarkTextPrimary = Color(0xFFF0F2ED);
  static const colorDarkTextSecondary = Color(0xFFBCC7BF);
  static const colorDarkTextMuted = Color(0xFF9EAEA3);
  static const colorDarkAccent = Color(0xFF35B5AD);

  // Product semantics. Relay and warning both use amber with distinct roles.
  static const colorGoodBg = Color(0xFFE9F4EE);
  static const colorGoodBorder = Color(0xFFC8DFD2);
  static const colorGoodText = Color(0xFF21644E);
  static const colorWarnBg = Color(0xFFFAF1E4);
  static const colorWarnBorder = Color(0xFFE6D6BC);
  static const colorWarnText = Color(0xFF81531E);
  static const colorBadBg = Color(0xFFF9EDE9);
  static const colorBadBorder = Color(0xFFEACCC4);
  static const colorBadText = Color(0xFF9A3C31);
  static const colorNeutralBg = Color(0xFFEBEEE8);
  static const colorNeutralBorder = Color(0xFFD9DED6);
  static const colorNeutralText = colorTextMuted;
  static const colorProgress = Color(0xFF285E98);

  static const colorDarkGoodBg = Color(0xFF213731);
  static const colorDarkGoodBorder = Color(0xFF395A4D);
  static const colorDarkGoodText = Color(0xFF81D7B8);
  static const colorDarkGoodDot = Color(0xFF58C8A0);
  static const colorDarkWarnBg = Color(0xFF372D20);
  static const colorDarkWarnBorder = Color(0xFF5E4D35);
  static const colorDarkWarnText = Color(0xFFF0C180);
  static const colorDarkWarnDot = Color(0xFFDBA959);
  static const colorDarkBadBg = Color(0xFF392825);
  static const colorDarkBadBorder = Color(0xFF63413B);
  static const colorDarkBadText = Color(0xFFF0A399);
  static const colorDarkBadDot = Color(0xFFE58276);
  static const colorDarkNeutralBg = Color(0xFF2B322E);
  static const colorDarkNeutralBorder = Color(0xFF465049);
  static const colorDarkNeutralText = colorDarkTextSecondary;
  static const colorDarkNeutralDot = Color(0xFF89988F);
  static const colorDarkProgress = Color(0xFF91BDFC);

  static const colorConsoleBg = Color(0xFF141918);
  static const colorConsoleBorder = Color(0xFF2D3833);
  static const colorConsoleText = Color(0xFFE5ECE8);

  static const elevationFlat = 0.0;
  static const elevationMenu = 4.0;
  static const elevationDialog = 8.0;
  static const shadowBorder = <BoxShadow>[];

  // --- Radius & Spacing ---
  static const radiusXs = 4.0;
  static const radiusSm = 8.0;
  static const radiusMd = 10.0;
  static const radiusLg = 12.0;

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
  static const space28 = 28.0;
  static const space32 = 32.0;
  static const space40 = 40.0;

  // Touch Targets
  static const minTouchTarget = 48.0;
  static const desktopControlHeight = 36.0;
  static const desktopToolbarHeight = 48.0;
  static const desktopPagePadding = space24;
  static const iconSm = 16.0;
  static const iconMd = 20.0;
  static const borderWidth = 1.0;

  static bool isDesktopPlatform(TargetPlatform platform) => switch (platform) {
    TargetPlatform.macOS ||
    TargetPlatform.windows ||
    TargetPlatform.linux => true,
    _ => false,
  };

  // --- Durations & Curves ---
  static const durationFast = Duration(milliseconds: 110);
  static const durationMedium = Duration(milliseconds: 160);
  static const durationDisclosure = Duration(milliseconds: 180);
  static const durationNavigation = Duration(milliseconds: 220);
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
    // Covers Linux and additional platforms supplied by SDK ports.
    _ => 'Noto Sans',
  };
}
