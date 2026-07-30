import 'package:flutter/material.dart';
import 'app_tokens.dart';

abstract final class AppTheme {
  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,
      scaffoldBackgroundColor: AppTokens.colorBg,
      colorScheme: const ColorScheme.light(
        surface: AppTokens.colorSurface,
        onSurface: AppTokens.colorTextPrimary,
        onSurfaceVariant: AppTokens.colorTextSecondary,
        outline: AppTokens.colorBorder,
        outlineVariant: AppTokens.colorBorderSubtle,
        primary: AppTokens.colorAccent,
        onPrimary: Colors.white,
        error: AppTokens.colorBadText,
        surfaceContainerHighest: AppTokens.colorNeutralBg,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: AppTokens.colorBg,
        foregroundColor: AppTokens.colorTextPrimary,
        elevation: 0,
        surfaceTintColor: Colors.transparent,
        titleSpacing: 16,
        titleTextStyle: TextStyle(
          color: AppTokens.colorTextPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.2,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppTokens.colorSurface,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 14,
          vertical: 12,
        ),
        labelStyle: const TextStyle(
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
          foregroundColor: Colors.white,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppTokens.colorTextPrimary,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          side: const BorderSide(color: AppTokens.colorBorder),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(
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
        indicatorColor: AppTokens.colorNeutralBg,
        height: 60,
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
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: AppTokens.colorSurface,
        indicatorColor: AppTokens.colorNeutralBg,
        elevation: 0,
        unselectedLabelTextStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w500,
          color: AppTokens.colorTextSecondary,
        ),
        selectedLabelTextStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w700,
          color: AppTokens.colorAccent,
        ),
        unselectedIconTheme: const IconThemeData(
          color: AppTokens.colorTextSecondary,
          size: 20,
        ),
        selectedIconTheme: const IconThemeData(
          color: AppTokens.colorAccent,
          size: 20,
        ),
      ),
      dividerTheme: const DividerThemeData(
        color: AppTokens.colorBorder,
        thickness: 1,
        space: 1,
      ),
    );
  }
}
