import 'package:flutter/material.dart';

import 'app_tokens.dart';
import 'p2wlan_colors.dart';

abstract final class AppTheme {
  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,
      fontFamily: AppTokens.primaryFontFamily,
      fontFamilyFallback: AppTokens.fontFamilyFallback,
      scaffoldBackgroundColor: AppTokens.colorBg,
      colorScheme: const ColorScheme.light(
        surface: AppTokens.colorSurface,
        onSurface: AppTokens.colorTextPrimary,
        onSurfaceVariant: AppTokens.colorTextSecondary,
        outline: AppTokens.colorBorder,
        outlineVariant: AppTokens.colorBorderSubtle,
        primary: AppTokens.colorAccent,
        onPrimary: AppTokens.colorSurface,
        secondary: AppTokens.colorAccent,
        onSecondary: AppTokens.colorSurface,
        secondaryContainer: Color(0xFFEAF1FF),
        onSecondaryContainer: AppTokens.colorAccentMuted,
        error: AppTokens.colorBadText,
        surfaceContainerHighest: AppTokens.colorNeutralBg,
      ),
      extensions: const [P2WlanColors.light],
      hoverColor: P2WlanColors.light.hoverSurface,
      focusColor: Color(0x1A2563EB),
      appBarTheme: const AppBarTheme(
        backgroundColor: AppTokens.colorSurface,
        foregroundColor: AppTokens.colorTextPrimary,
        elevation: 0,
        surfaceTintColor: Colors.transparent,
        titleSpacing: 16,
        titleTextStyle: TextStyle(
          color: AppTokens.colorTextPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w700,
          letterSpacing: 0,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppTokens.colorSurface,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: AppTokens.space14,
          vertical: AppTokens.space12,
        ),
        labelStyle: TextStyle(
          color: AppTokens.colorTextSecondary,
          fontSize: 13,
        ),
        hintStyle: const TextStyle(
          color: AppTokens.colorTextMuted,
          fontSize: 13,
        ),
        helperStyle: const TextStyle(
          color: AppTokens.colorTextMuted,
          fontSize: 12,
        ),
        errorStyle: const TextStyle(
          color: AppTokens.colorBadText,
          fontSize: 12,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(color: AppTokens.colorBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(color: AppTokens.colorBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(
            color: AppTokens.colorAccent,
            width: 1.5,
          ),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(color: AppTokens.colorBadBorder),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: AppTokens.colorAccent,
          foregroundColor: AppTokens.colorSurface,
          disabledBackgroundColor: AppTokens.colorBorder,
          disabledForegroundColor: AppTokens.colorTextMuted,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space16,
            vertical: AppTokens.space10,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppTokens.colorTextPrimary,
          disabledForegroundColor: AppTokens.colorTextMuted,
          disabledBackgroundColor: Colors.transparent,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space14,
            vertical: AppTokens.space10,
          ),
          side: const BorderSide(color: AppTokens.colorBorder),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          foregroundColor: AppTokens.colorTextSecondary,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
        ),
      ),
      chipTheme: _lightChipTheme,
      dialogTheme: DialogThemeData(
        backgroundColor: P2WlanColors.light.surfaceElevated,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusLg),
          side: const BorderSide(color: AppTokens.colorBorder),
        ),
      ),
      switchTheme: SwitchThemeData(
        mouseCursor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.disabled)) {
            return SystemMouseCursors.basic;
          }
          return SystemMouseCursors.click;
        }),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: AppTokens.colorConsoleBg,
        contentTextStyle: const TextStyle(
          color: AppTokens.colorConsoleText,
          fontSize: 13,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: AppTokens.colorSurface,
        elevation: 0,
        indicatorColor: P2WlanColors.light.selectedSurface,
        height: 64,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w700,
              color: AppTokens.colorAccent,
            );
          }
          return const TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w500,
            color: AppTokens.colorTextSecondary,
          );
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return const IconThemeData(color: AppTokens.colorAccent, size: 22);
          }
          return const IconThemeData(
            color: AppTokens.colorTextSecondary,
            size: 22,
          );
        }),
      ),
      dividerTheme: const DividerThemeData(
        color: AppTokens.colorBorder,
        thickness: 1,
        space: 1,
      ),
    );
  }

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      fontFamily: AppTokens.primaryFontFamily,
      fontFamilyFallback: AppTokens.fontFamilyFallback,
      scaffoldBackgroundColor: AppTokens.colorDarkBg,
      colorScheme: const ColorScheme.dark(
        surface: AppTokens.colorDarkSurface,
        onSurface: AppTokens.colorDarkTextPrimary,
        onSurfaceVariant: AppTokens.colorDarkTextSecondary,
        outline: AppTokens.colorDarkBorder,
        outlineVariant: AppTokens.colorDarkBorderSubtle,
        primary: AppTokens.colorDarkAccent,
        onPrimary: AppTokens.colorDarkBg,
        secondary: AppTokens.colorDarkAccent,
        onSecondary: AppTokens.colorDarkBg,
        secondaryContainer: Color(0xFF1E3A8A),
        onSecondaryContainer: Color(0xFFDBEAFE),
        error: AppTokens.colorDarkBadText,
        surfaceContainerHighest: AppTokens.colorDarkSurfaceSubtle,
      ),
      extensions: const [P2WlanColors.dark],
      hoverColor: P2WlanColors.dark.hoverSurface,
      focusColor: Color(0x4060A5FA),
      appBarTheme: const AppBarTheme(
        backgroundColor: AppTokens.colorDarkSurface,
        foregroundColor: AppTokens.colorDarkTextPrimary,
        elevation: 0,
        surfaceTintColor: Colors.transparent,
        titleSpacing: 16,
        titleTextStyle: TextStyle(
          color: AppTokens.colorDarkTextPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w700,
          letterSpacing: 0,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppTokens.colorDarkSurface,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: AppTokens.space14,
          vertical: AppTokens.space12,
        ),
        labelStyle: TextStyle(
          color: AppTokens.colorDarkTextSecondary,
          fontSize: 13,
        ),
        hintStyle: const TextStyle(
          color: AppTokens.colorDarkTextMuted,
          fontSize: 13,
        ),
        helperStyle: const TextStyle(
          color: AppTokens.colorDarkTextMuted,
          fontSize: 12,
        ),
        errorStyle: const TextStyle(
          color: AppTokens.colorDarkBadText,
          fontSize: 12,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(color: AppTokens.colorDarkBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(color: AppTokens.colorDarkBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(
            color: AppTokens.colorDarkAccent,
            width: 1.5,
          ),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: const BorderSide(color: AppTokens.colorDarkBadBorder),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: AppTokens.colorDarkAccent,
          foregroundColor: AppTokens.colorDarkBg,
          disabledBackgroundColor: AppTokens.colorDarkBorder,
          disabledForegroundColor: AppTokens.colorDarkTextMuted,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space16,
            vertical: AppTokens.space10,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppTokens.colorDarkTextPrimary,
          disabledForegroundColor: AppTokens.colorDarkTextMuted,
          disabledBackgroundColor: Colors.transparent,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space14,
            vertical: AppTokens.space10,
          ),
          side: const BorderSide(color: AppTokens.colorDarkBorder),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          foregroundColor: AppTokens.colorDarkTextSecondary,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
        ),
      ),
      chipTheme: _darkChipTheme,
      dialogTheme: DialogThemeData(
        backgroundColor: P2WlanColors.dark.surfaceElevated,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusLg),
          side: const BorderSide(color: AppTokens.colorDarkBorder),
        ),
      ),
      switchTheme: SwitchThemeData(
        mouseCursor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.disabled)) {
            return SystemMouseCursors.basic;
          }
          return SystemMouseCursors.click;
        }),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: AppTokens.colorConsoleBg,
        contentTextStyle: const TextStyle(
          color: AppTokens.colorConsoleText,
          fontSize: 13,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: AppTokens.colorDarkSurface,
        elevation: 0,
        indicatorColor: P2WlanColors.dark.selectedSurface,
        height: 64,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w700,
              color: AppTokens.colorDarkAccent,
            );
          }
          return const TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w500,
            color: AppTokens.colorDarkTextSecondary,
          );
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return const IconThemeData(
              color: AppTokens.colorDarkAccent,
              size: 22,
            );
          }
          return const IconThemeData(
            color: AppTokens.colorDarkTextSecondary,
            size: 22,
          );
        }),
      ),
      dividerTheme: const DividerThemeData(
        color: AppTokens.colorDarkBorder,
        thickness: 1,
        space: 1,
      ),
    );
  }
}

final _lightChipTheme = ChipThemeData(
  backgroundColor: P2WlanColors.light.surfaceMuted,
  selectedColor: P2WlanColors.light.selectedSurface,
  secondarySelectedColor: P2WlanColors.light.selectedSurface,
  side: BorderSide(color: P2WlanColors.light.border),
  shape: RoundedRectangleBorder(
    borderRadius: BorderRadius.circular(AppTokens.radiusMd),
  ),
  labelStyle: TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w600,
    color: P2WlanColors.light.textPrimary,
  ),
  secondaryLabelStyle: TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w600,
    color: P2WlanColors.light.relay,
  ),
  checkmarkColor: P2WlanColors.light.relay,
  padding: const EdgeInsets.symmetric(horizontal: AppTokens.space10),
);

final _darkChipTheme = ChipThemeData(
  backgroundColor: P2WlanColors.dark.surfaceMuted,
  selectedColor: P2WlanColors.dark.selectedSurface,
  secondarySelectedColor: P2WlanColors.dark.selectedSurface,
  side: BorderSide(color: P2WlanColors.dark.border),
  shape: RoundedRectangleBorder(
    borderRadius: BorderRadius.circular(AppTokens.radiusMd),
  ),
  labelStyle: TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w600,
    color: P2WlanColors.dark.textPrimary,
  ),
  secondaryLabelStyle: TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w600,
    color: P2WlanColors.dark.relay,
  ),
  checkmarkColor: P2WlanColors.dark.relay,
  padding: const EdgeInsets.symmetric(horizontal: AppTokens.space10),
);
