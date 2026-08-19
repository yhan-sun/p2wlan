import 'package:flutter/material.dart';

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

  // Connection path semantics: Direct is ideal, Relay is a normal usable path
  // (never a warning), Probing is attention, Offline is neutral.
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

  static const light = P2WlanColors(
    textPrimary: Color(0xFF151A1D),
    textSecondary: Color(0xFF48535A),
    textMuted: Color(0xFF68757B),
    border: Color(0xFFDDE4E1),
    borderStrong: Color(0xFFC6D2CE),
    divider: Color(0xFFE9EEEB),
    surface: Color(0xFFFEFEFC),
    surfaceElevated: Color(0xFFFFFFFF),
    surfaceMuted: Color(0xFFF7F8F6),
    selectedSurface: Color(0xFFE7F1EF),
    hoverSurface: Color(0xFFF1F5F3),
    direct: Color(0xFF276044),
    relay: Color(0xFF173E3C),
    probing: Color(0xFF755622),
    offline: Color(0xFF4C585D),
    successSurface: Color(0xFFF2FAF5),
    successBorder: Color(0xFFB9DFC9),
    successText: Color(0xFF276044),
    successDot: Color(0xFF276044),
    warningSurface: Color(0xFFFCF7EA),
    warningBorder: Color(0xFFE6CD8F),
    warningText: Color(0xFF755622),
    warningDot: Color(0xFF755622),
    dangerSurface: Color(0xFFFCF3F1),
    dangerBorder: Color(0xFFE7B8AE),
    dangerText: Color(0xFF8B372D),
    dangerDot: Color(0xFF8B372D),
    neutralSurface: Color(0xFFF1F4F3),
    neutralBorder: Color(0xFFD3DCDA),
    neutralText: Color(0xFF4C585D),
    neutralDot: Color(0xFF4C585D),
    consoleSurface: Color(0xFF111817),
    consoleBorder: Color(0xFF26312F),
    consoleText: Color(0xFFE5ECE8),
  );

  static const dark = P2WlanColors(
    textPrimary: Color(0xFFEDF2F0),
    textSecondary: Color(0xFFA1AFAC),
    textMuted: Color(0xFF758582),
    border: Color(0xFF2E3D3A),
    borderStrong: Color(0xFF3A4A47),
    divider: Color(0xFF263330),
    surface: Color(0xFF182220),
    surfaceElevated: Color(0xFF22302D),
    surfaceMuted: Color(0xFF1F2B29),
    selectedSurface: Color(0xFF213532),
    hoverSurface: Color(0xFF24322F),
    direct: Color(0xFF8DE2B1),
    relay: Color(0xFF35B5AD),
    probing: Color(0xFFF1C96A),
    offline: Color(0xFFB8C7C4),
    successSurface: Color(0xFF10241D),
    successBorder: Color(0xFF2F7A4F),
    successText: Color(0xFF8DE2B1),
    successDot: Color(0xFF35C46F),
    warningSurface: Color(0xFF2A2112),
    warningBorder: Color(0xFF7A5D24),
    warningText: Color(0xFFF1C96A),
    warningDot: Color(0xFFE3A92F),
    dangerSurface: Color(0xFF2B1716),
    dangerBorder: Color(0xFF8E423D),
    dangerText: Color(0xFFFFA39A),
    dangerDot: Color(0xFFEF5D54),
    neutralSurface: Color(0xFF1D2927),
    neutralBorder: Color(0xFF3A4A47),
    neutralText: Color(0xFFB8C7C4),
    neutralDot: Color(0xFF81918E),
    consoleSurface: Color(0xFF111817),
    consoleBorder: Color(0xFF26312F),
    consoleText: Color(0xFFE5ECE8),
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
