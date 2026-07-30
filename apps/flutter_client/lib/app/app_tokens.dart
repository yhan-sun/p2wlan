import 'package:flutter/material.dart';

/// Design tokens for P2WLAN Flutter Client UI/UX.
/// Native engineering aesthetic: calm, reliable, precise, read-only network tool.
abstract final class AppTokens {
  // --- Color Palette ---
  // Cool light neutral background & surfaces
  static const colorBg = Color(0xFFF4F6F8);
  static const colorSurface = Color(0xFFFFFFFF);
  static const colorSurfaceSubtle = Color(0xFFF8FAFC);
  static const colorBorder = Color(0xFFE2E8F0);
  static const colorBorderSubtle = Color(0xFFEDF2F7);

  // Text hierarchy
  static const colorTextPrimary = Color(0xFF0F172A);
  static const colorTextSecondary = Color(0xFF475569);
  static const colorTextMuted = Color(0xFF64748B);

  // Brand / Low-frequency accent (Slate blue / Slate blue-teal)
  static const colorAccent = Color(0xFF1E293B);
  static const colorAccentMuted = Color(0xFF334155);

  // Status Tones (Semantic, strictly scoped)
  // Good / Online / Direct
  static const colorGoodBg = Color(0xFFECFDF5);
  static const colorGoodBorder = Color(0xFFA7F3D0);
  static const colorGoodText = Color(0xFF065F46);

  // Warning / Degraded / Relay
  static const colorWarnBg = Color(0xFFFFFBEB);
  static const colorWarnBorder = Color(0xFFFDE68A);
  static const colorWarnText = Color(0xFF92400E);

  // Bad / Offline / Unhealthy
  static const colorBadBg = Color(0xFFFEF2F2);
  static const colorBadBorder = Color(0xFFFCA5A5);
  static const colorBadText = Color(0xFF991B1B);

  // Neutral / Skipped / Idle
  static const colorNeutralBg = Color(0xFFF1F5F9);
  static const colorNeutralBorder = Color(0xFFCBD5E1);
  static const colorNeutralText = Color(0xFF475569);

  // Debug Console / Raw JSON
  static const colorConsoleBg = Color(0xFF0F172A);
  static const colorConsoleBorder = Color(0xFF1E293B);
  static const colorConsoleText = Color(0xFFE2E8F0);

  // --- Radius & Spacing ---
  static const radiusSm = 6.0;
  static const radiusMd = 8.0;
  static const radiusLg = 12.0;

  // Touch Targets
  static const minTouchTarget = 40.0;

  // --- Durations & Curves ---
  static const durationFast = Duration(milliseconds: 140);
  static const durationMedium = Duration(milliseconds: 200);
  static const curveEase = Curves.easeOutCubic;

  // --- Tabular Figures TextStyle modifier ---
  static const tabularFontFeatures = [FontFeature.tabularFigures()];
}
