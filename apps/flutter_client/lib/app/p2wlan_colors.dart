import 'package:flutter/material.dart';

import 'app_tokens.dart';

/// Product-semantic colors that Material's `ColorScheme` cannot express
/// cleanly (connection path states, subtle status surfaces, console, text
/// hierarchy, interaction surfaces).
///
/// Both palettes are static constants; widgets read them through
/// [P2WlanColors.of] and never branch on `Theme.of(context).brightness`.
@immutable
class P2WlanColors extends ThemeExtension<P2WlanColors> {
  const P2WlanColors({
    required this.textPrimary,
    required this.textSecondary,
    required this.textMuted,
    required this.border,
    required this.borderStrong,
    required this.divider,
    required this.surface,
    required this.surfaceElevated,
    required this.surfaceMuted,
    required this.selectedSurface,
    required this.hoverSurface,
    required this.direct,
    required this.relay,
    required this.probing,
    required this.offline,
    required this.successSurface,
    required this.successBorder,
    required this.successText,
    required this.successDot,
    required this.warningSurface,
    required this.warningBorder,
    required this.warningText,
    required this.warningDot,
    required this.dangerSurface,
    required this.dangerBorder,
    required this.dangerText,
    required this.dangerDot,
    required this.neutralSurface,
    required this.neutralBorder,
    required this.neutralText,
    required this.neutralDot,
    required this.consoleSurface,
    required this.consoleBorder,
    required this.consoleText,
  });

  // Text hierarchy.
  final Color textPrimary;
  final Color textSecondary;
  final Color textMuted;

  // Lines.
  final Color border;
  final Color borderStrong;
  final Color divider;

  // Surface hierarchy.
  final Color surface;
  final Color surfaceElevated;
  final Color surfaceMuted;
  final Color selectedSurface;
  final Color hoverSurface;

  // Connection path semantics. Relay can remain healthy and usable.
  final Color direct;
  final Color relay;
  final Color probing;
  final Color offline;

  // Status tone surfaces (bg / border / text / dot).
  final Color successSurface;
  final Color successBorder;
  final Color successText;
  final Color successDot;
  final Color warningSurface;
  final Color warningBorder;
  final Color warningText;
  final Color warningDot;
  final Color dangerSurface;
  final Color dangerBorder;
  final Color dangerText;
  final Color dangerDot;
  final Color neutralSurface;
  final Color neutralBorder;
  final Color neutralText;
  final Color neutralDot;

  // Technical console (logs / raw JSON / commands). Intentionally the same
  // dark terminal look in both themes.
  final Color consoleSurface;
  final Color consoleBorder;
  final Color consoleText;

  Color get progress => probing;

  static const light = P2WlanColors(
    textPrimary: AppTokens.colorTextPrimary,
    textSecondary: AppTokens.colorTextSecondary,
    textMuted: AppTokens.colorTextMuted,
    border: AppTokens.colorBorder,
    borderStrong: Color(0xFFBAC4BB),
    divider: AppTokens.colorBorderSubtle,
    surface: AppTokens.colorSurface,
    surfaceElevated: Color(0xFFFFFFFF),
    surfaceMuted: AppTokens.colorSurfaceSubtle,
    selectedSurface: Color(0xFFE2EBE5),
    hoverSurface: Color(0xFFECEFEA),
    direct: AppTokens.colorGoodText,
    relay: Color(0xFF8A5A24),
    probing: AppTokens.colorProgress,
    offline: AppTokens.colorTextMuted,
    successSurface: AppTokens.colorGoodBg,
    successBorder: AppTokens.colorGoodBorder,
    successText: AppTokens.colorGoodText,
    successDot: Color(0xFF2C8B68),
    warningSurface: AppTokens.colorWarnBg,
    warningBorder: AppTokens.colorWarnBorder,
    warningText: AppTokens.colorWarnText,
    warningDot: Color(0xFFB37A34),
    dangerSurface: AppTokens.colorBadBg,
    dangerBorder: AppTokens.colorBadBorder,
    dangerText: AppTokens.colorBadText,
    dangerDot: Color(0xFFC95F51),
    neutralSurface: AppTokens.colorNeutralBg,
    neutralBorder: AppTokens.colorNeutralBorder,
    neutralText: AppTokens.colorNeutralText,
    neutralDot: Color(0xFF77877C),
    consoleSurface: AppTokens.colorConsoleBg,
    consoleBorder: AppTokens.colorConsoleBorder,
    consoleText: AppTokens.colorConsoleText,
  );

  static const dark = P2WlanColors(
    textPrimary: AppTokens.colorDarkTextPrimary,
    textSecondary: AppTokens.colorDarkTextSecondary,
    textMuted: AppTokens.colorDarkTextMuted,
    border: AppTokens.colorDarkBorder,
    borderStrong: Color(0xFF505D54),
    divider: AppTokens.colorDarkBorderSubtle,
    surface: AppTokens.colorDarkSurface,
    surfaceElevated: Color(0xFF2A312D),
    surfaceMuted: AppTokens.colorDarkSurfaceSubtle,
    selectedSurface: Color(0xFF2A3A34),
    hoverSurface: Color(0xFF2D3631),
    direct: AppTokens.colorDarkGoodText,
    relay: Color(0xFFE5B170),
    probing: AppTokens.colorDarkProgress,
    offline: AppTokens.colorDarkTextMuted,
    successSurface: AppTokens.colorDarkGoodBg,
    successBorder: AppTokens.colorDarkGoodBorder,
    successText: AppTokens.colorDarkGoodText,
    successDot: AppTokens.colorDarkGoodDot,
    warningSurface: AppTokens.colorDarkWarnBg,
    warningBorder: AppTokens.colorDarkWarnBorder,
    warningText: AppTokens.colorDarkWarnText,
    warningDot: AppTokens.colorDarkWarnDot,
    dangerSurface: AppTokens.colorDarkBadBg,
    dangerBorder: AppTokens.colorDarkBadBorder,
    dangerText: AppTokens.colorDarkBadText,
    dangerDot: AppTokens.colorDarkBadDot,
    neutralSurface: AppTokens.colorDarkNeutralBg,
    neutralBorder: AppTokens.colorDarkNeutralBorder,
    neutralText: AppTokens.colorDarkNeutralText,
    neutralDot: AppTokens.colorDarkNeutralDot,
    consoleSurface: AppTokens.colorConsoleBg,
    consoleBorder: AppTokens.colorConsoleBorder,
    consoleText: AppTokens.colorConsoleText,
  );

  /// Resolves the palette for [context]. The official `AppTheme` themes always
  /// register the extension explicitly; this fallback only guards against a
  /// theme that lacks it, choosing the palette that matches the effective
  /// brightness so a dark theme never silently falls back to light colors.
  static P2WlanColors of(BuildContext context) {
    final theme = Theme.of(context);
    return theme.extension<P2WlanColors>() ??
        (theme.brightness == Brightness.dark
            ? P2WlanColors.dark
            : P2WlanColors.light);
  }

  @override
  P2WlanColors copyWith({
    Color? textPrimary,
    Color? textSecondary,
    Color? textMuted,
    Color? border,
    Color? borderStrong,
    Color? divider,
    Color? surface,
    Color? surfaceElevated,
    Color? surfaceMuted,
    Color? selectedSurface,
    Color? hoverSurface,
    Color? direct,
    Color? relay,
    Color? probing,
    Color? offline,
    Color? successSurface,
    Color? successBorder,
    Color? successText,
    Color? successDot,
    Color? warningSurface,
    Color? warningBorder,
    Color? warningText,
    Color? warningDot,
    Color? dangerSurface,
    Color? dangerBorder,
    Color? dangerText,
    Color? dangerDot,
    Color? neutralSurface,
    Color? neutralBorder,
    Color? neutralText,
    Color? neutralDot,
    Color? consoleSurface,
    Color? consoleBorder,
    Color? consoleText,
  }) {
    return P2WlanColors(
      textPrimary: textPrimary ?? this.textPrimary,
      textSecondary: textSecondary ?? this.textSecondary,
      textMuted: textMuted ?? this.textMuted,
      border: border ?? this.border,
      borderStrong: borderStrong ?? this.borderStrong,
      divider: divider ?? this.divider,
      surface: surface ?? this.surface,
      surfaceElevated: surfaceElevated ?? this.surfaceElevated,
      surfaceMuted: surfaceMuted ?? this.surfaceMuted,
      selectedSurface: selectedSurface ?? this.selectedSurface,
      hoverSurface: hoverSurface ?? this.hoverSurface,
      direct: direct ?? this.direct,
      relay: relay ?? this.relay,
      probing: probing ?? this.probing,
      offline: offline ?? this.offline,
      successSurface: successSurface ?? this.successSurface,
      successBorder: successBorder ?? this.successBorder,
      successText: successText ?? this.successText,
      successDot: successDot ?? this.successDot,
      warningSurface: warningSurface ?? this.warningSurface,
      warningBorder: warningBorder ?? this.warningBorder,
      warningText: warningText ?? this.warningText,
      warningDot: warningDot ?? this.warningDot,
      dangerSurface: dangerSurface ?? this.dangerSurface,
      dangerBorder: dangerBorder ?? this.dangerBorder,
      dangerText: dangerText ?? this.dangerText,
      dangerDot: dangerDot ?? this.dangerDot,
      neutralSurface: neutralSurface ?? this.neutralSurface,
      neutralBorder: neutralBorder ?? this.neutralBorder,
      neutralText: neutralText ?? this.neutralText,
      neutralDot: neutralDot ?? this.neutralDot,
      consoleSurface: consoleSurface ?? this.consoleSurface,
      consoleBorder: consoleBorder ?? this.consoleBorder,
      consoleText: consoleText ?? this.consoleText,
    );
  }

  @override
  P2WlanColors lerp(ThemeExtension<P2WlanColors>? other, double t) {
    if (other is! P2WlanColors) return this;
    return P2WlanColors(
      textPrimary: Color.lerp(textPrimary, other.textPrimary, t)!,
      textSecondary: Color.lerp(textSecondary, other.textSecondary, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      border: Color.lerp(border, other.border, t)!,
      borderStrong: Color.lerp(borderStrong, other.borderStrong, t)!,
      divider: Color.lerp(divider, other.divider, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      surfaceElevated: Color.lerp(surfaceElevated, other.surfaceElevated, t)!,
      surfaceMuted: Color.lerp(surfaceMuted, other.surfaceMuted, t)!,
      selectedSurface: Color.lerp(selectedSurface, other.selectedSurface, t)!,
      hoverSurface: Color.lerp(hoverSurface, other.hoverSurface, t)!,
      direct: Color.lerp(direct, other.direct, t)!,
      relay: Color.lerp(relay, other.relay, t)!,
      probing: Color.lerp(probing, other.probing, t)!,
      offline: Color.lerp(offline, other.offline, t)!,
      successSurface: Color.lerp(successSurface, other.successSurface, t)!,
      successBorder: Color.lerp(successBorder, other.successBorder, t)!,
      successText: Color.lerp(successText, other.successText, t)!,
      successDot: Color.lerp(successDot, other.successDot, t)!,
      warningSurface: Color.lerp(warningSurface, other.warningSurface, t)!,
      warningBorder: Color.lerp(warningBorder, other.warningBorder, t)!,
      warningText: Color.lerp(warningText, other.warningText, t)!,
      warningDot: Color.lerp(warningDot, other.warningDot, t)!,
      dangerSurface: Color.lerp(dangerSurface, other.dangerSurface, t)!,
      dangerBorder: Color.lerp(dangerBorder, other.dangerBorder, t)!,
      dangerText: Color.lerp(dangerText, other.dangerText, t)!,
      dangerDot: Color.lerp(dangerDot, other.dangerDot, t)!,
      neutralSurface: Color.lerp(neutralSurface, other.neutralSurface, t)!,
      neutralBorder: Color.lerp(neutralBorder, other.neutralBorder, t)!,
      neutralText: Color.lerp(neutralText, other.neutralText, t)!,
      neutralDot: Color.lerp(neutralDot, other.neutralDot, t)!,
      consoleSurface: Color.lerp(consoleSurface, other.consoleSurface, t)!,
      consoleBorder: Color.lerp(consoleBorder, other.consoleBorder, t)!,
      consoleText: Color.lerp(consoleText, other.consoleText, t)!,
    );
  }
}
