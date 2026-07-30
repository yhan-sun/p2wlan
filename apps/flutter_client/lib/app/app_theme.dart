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
        onPrimary: AppTokens.colorSurface,
        error: AppTokens.colorBadText,
        surfaceContainerHighest: AppTokens.colorNeutralBg,
      ),
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
          foregroundColor: AppTokens.colorSurface,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppTokens.colorTextPrimary,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
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
        indicatorColor: AppTokens.colorSurfaceSubtle,
        height: 58,
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
        backgroundColor: AppTokens.colorSurfaceSubtle,
        indicatorColor: AppTokens.colorSurface,
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

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: AppTokens.colorDarkBg,
      colorScheme: const ColorScheme.dark(
        surface: AppTokens.colorDarkSurface,
        onSurface: AppTokens.colorDarkTextPrimary,
        onSurfaceVariant: AppTokens.colorDarkTextSecondary,
        outline: AppTokens.colorDarkBorder,
        outlineVariant: AppTokens.colorDarkBorderSubtle,
        primary: AppTokens.colorDarkAccent,
        onPrimary: AppTokens.colorDarkBg,
        error: AppTokens.colorBadText,
        surfaceContainerHighest: AppTokens.colorDarkSurfaceSubtle,
      ),
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
          horizontal: 14,
          vertical: 12,
        ),
        labelStyle: const TextStyle(
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
          color: AppTokens.colorBadText,
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
          borderSide: const BorderSide(color: AppTokens.colorBadBorder),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: AppTokens.colorDarkAccent,
          foregroundColor: AppTokens.colorDarkBg,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppTokens.colorDarkTextPrimary,
          enabledMouseCursor: SystemMouseCursors.click,
          disabledMouseCursor: SystemMouseCursors.basic,
          minimumSize: const Size(
            AppTokens.minTouchTarget,
            AppTokens.minTouchTarget,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
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
        indicatorColor: AppTokens.colorDarkSurfaceSubtle,
        height: 58,
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
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: AppTokens.colorDarkSurfaceSubtle,
        indicatorColor: AppTokens.colorDarkSurface,
        elevation: 0,
        unselectedLabelTextStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w500,
          color: AppTokens.colorDarkTextSecondary,
        ),
        selectedLabelTextStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w700,
          color: AppTokens.colorDarkAccent,
        ),
        unselectedIconTheme: const IconThemeData(
          color: AppTokens.colorDarkTextSecondary,
          size: 20,
        ),
        selectedIconTheme: const IconThemeData(
          color: AppTokens.colorDarkAccent,
          size: 20,
        ),
      ),
      dividerTheme: const DividerThemeData(
        color: AppTokens.colorDarkBorder,
        thickness: 1,
        space: 1,
      ),
    );
  }
}
