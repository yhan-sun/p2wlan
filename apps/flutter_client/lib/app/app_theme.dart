import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'app_tokens.dart';
import 'p2wlan_colors.dart';

abstract final class AppTheme {
  static ThemeData get lightTheme => _theme(Brightness.light);
  static ThemeData get darkTheme => _theme(Brightness.dark);

  static ThemeData _theme(Brightness brightness) {
    final dark = brightness == Brightness.dark;
    final desktop = AppTokens.isDesktopPlatform(defaultTargetPlatform);
    final colors = dark ? P2WlanColors.dark : P2WlanColors.light;
    final canvas = dark ? AppTokens.colorDarkBg : AppTokens.colorBg;
    final primary = dark ? AppTokens.colorDarkAccent : AppTokens.colorAccent;
    final onPrimary = dark ? canvas : colors.surfaceElevated;
    final scheme = ColorScheme(
      brightness: brightness,
      surface: colors.surface,
      onSurface: colors.textPrimary,
      onSurfaceVariant: colors.textSecondary,
      outline: colors.border,
      outlineVariant: colors.divider,
      primary: primary,
      onPrimary: onPrimary,
      primaryContainer: colors.selectedSurface,
      onPrimaryContainer: colors.textPrimary,
      secondary: primary,
      onSecondary: onPrimary,
      secondaryContainer: colors.selectedSurface,
      onSecondaryContainer: colors.textPrimary,
      error: colors.dangerText,
      onError: dark ? canvas : colors.surfaceElevated,
      surfaceContainerHighest: colors.surfaceMuted,
      surfaceContainerHigh: colors.surfaceElevated,
      surfaceContainer: colors.surface,
      surfaceContainerLow: canvas,
      surfaceContainerLowest: canvas,
    );
    final radius = BorderRadius.circular(AppTokens.radiusSm);
    final shape = RoundedRectangleBorder(borderRadius: radius);
    final controlHeight = desktop
        ? AppTokens.desktopControlHeight
        : AppTokens.minTouchTarget;
    final controlText = TextStyle(
      fontSize: desktop ? 13 : 14,
      fontWeight: desktop ? FontWeight.w500 : FontWeight.w600,
    );

    ButtonStyle button({
      required Color foreground,
      Color? background,
      Color? disabledBackground,
      Color? focus,
      bool outlined = false,
      bool icon = false,
    }) {
      final resting = outlined
          ? BorderSide(color: colors.border)
          : BorderSide.none;
      return ButtonStyle(
        foregroundColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.disabled)
              ? colors.textMuted
              : foreground,
        ),
        backgroundColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.disabled)
              ? disabledBackground
              : background,
        ),
        mouseCursor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.disabled)
              ? SystemMouseCursors.basic
              : SystemMouseCursors.click,
        ),
        side: WidgetStateProperty.resolveWith(
          (states) =>
              states.contains(WidgetState.focused) &&
                  !states.contains(WidgetState.disabled)
              ? BorderSide(color: focus ?? primary, width: 2)
              : resting,
        ),
        overlayColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.disabled)) return Colors.transparent;
          if (states.contains(WidgetState.pressed)) {
            return foreground.withValues(alpha: .12);
          }
          if (states.contains(WidgetState.hovered) ||
              states.contains(WidgetState.focused)) {
            return foreground.withValues(alpha: .08);
          }
          return Colors.transparent;
        }),
        minimumSize: WidgetStatePropertyAll(Size.square(controlHeight)),
        padding: WidgetStatePropertyAll(
          icon
              ? const EdgeInsets.all(AppTokens.space8)
              : EdgeInsets.symmetric(
                  horizontal: AppTokens.space12,
                  vertical: desktop ? AppTokens.space8 : AppTokens.space10,
                ),
        ),
        tapTargetSize: desktop ? MaterialTapTargetSize.shrinkWrap : null,
        visualDensity: desktop ? VisualDensity.standard : null,
        textStyle: WidgetStatePropertyAll(controlText),
        shape: WidgetStatePropertyAll(shape),
        animationDuration: AppTokens.durationFast,
        splashFactory: desktop ? NoSplash.splashFactory : null,
      );
    }

    OutlineInputBorder inputBorder(
      Color color, {
      double width = AppTokens.borderWidth,
    }) => OutlineInputBorder(
      borderRadius: radius,
      borderSide: BorderSide(color: color, width: width),
    );

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      fontFamily: AppTokens.primaryFontFamily,
      fontFamilyFallback: AppTokens.fontFamilyFallback,
      scaffoldBackgroundColor: canvas,
      colorScheme: scheme,
      textTheme: desktop ? _desktopTypography : null,
      extensions: [colors],
      hoverColor: colors.hoverSurface,
      splashFactory: desktop ? NoSplash.splashFactory : null,
      highlightColor: primary.withValues(alpha: .08),
      focusColor: primary.withValues(alpha: .15),
      appBarTheme: AppBarTheme(
        backgroundColor: colors.surface,
        foregroundColor: colors.textPrimary,
        elevation: AppTokens.elevationFlat,
        scrolledUnderElevation: AppTokens.elevationFlat,
        surfaceTintColor: Colors.transparent,
        titleSpacing: AppTokens.space16,
        titleTextStyle: TextStyle(
          color: colors.textPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w600,
          letterSpacing: 0,
          fontFamily: AppTokens.primaryFontFamily,
          fontFamilyFallback: AppTokens.fontFamilyFallback,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: colors.surface,
        isDense: desktop,
        contentPadding: EdgeInsets.symmetric(
          horizontal: AppTokens.space12,
          vertical: desktop ? AppTokens.space8 : AppTokens.space12,
        ),
        labelStyle: TextStyle(
          color: colors.textSecondary,
          fontSize: desktop ? 13 : 14,
        ),
        hintStyle: TextStyle(
          color: colors.textMuted,
          fontSize: desktop ? 13 : 14,
        ),
        helperStyle: TextStyle(color: colors.textMuted, fontSize: 12),
        errorStyle: TextStyle(color: colors.dangerText, fontSize: 12),
        border: inputBorder(colors.border),
        enabledBorder: inputBorder(colors.border),
        focusedBorder: inputBorder(primary, width: 1.5),
        errorBorder: inputBorder(colors.dangerText),
        focusedErrorBorder: inputBorder(colors.dangerText, width: 1.5),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: button(
          foreground: onPrimary,
          background: primary,
          disabledBackground: colors.border,
          focus: onPrimary,
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: button(foreground: colors.textPrimary, outlined: true),
      ),
      textButtonTheme: TextButtonThemeData(style: button(foreground: primary)),
      iconButtonTheme: IconButtonThemeData(
        style: button(foreground: colors.textSecondary, icon: true),
      ),
      segmentedButtonTheme: SegmentedButtonThemeData(
        style: button(foreground: colors.textPrimary, outlined: true).copyWith(
          backgroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected)
                ? colors.selectedSurface
                : null,
          ),
        ),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: colors.surfaceMuted,
        selectedColor: colors.selectedSurface,
        secondarySelectedColor: colors.selectedSurface,
        side: BorderSide(color: colors.border),
        shape: shape,
        labelStyle: TextStyle(fontSize: 12, color: colors.textPrimary),
        secondaryLabelStyle: TextStyle(fontSize: 12, color: primary),
        checkmarkColor: primary,
        padding: const EdgeInsets.symmetric(horizontal: AppTokens.space8),
      ),
      dialogTheme: DialogThemeData(
        elevation: AppTokens.elevationDialog,
        backgroundColor: colors.surfaceElevated,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusLg),
          side: BorderSide(color: colors.border),
        ),
      ),
      popupMenuTheme: PopupMenuThemeData(
        color: colors.surfaceElevated,
        elevation: AppTokens.elevationMenu,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: radius,
          side: BorderSide(color: colors.border),
        ),
      ),
      switchTheme: SwitchThemeData(
        mouseCursor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.disabled)
              ? SystemMouseCursors.basic
              : SystemMouseCursors.click,
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: colors.consoleSurface,
        contentTextStyle: TextStyle(color: colors.consoleText, fontSize: 13),
        shape: shape,
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: colors.surface,
        elevation: AppTokens.elevationFlat,
        indicatorColor: colors.selectedSurface,
        height: 64,
        labelTextStyle: WidgetStateProperty.resolveWith(
          (states) => TextStyle(
            fontSize: 12,
            fontWeight: states.contains(WidgetState.selected)
                ? FontWeight.w600
                : FontWeight.w500,
            color: states.contains(WidgetState.selected)
                ? primary
                : colors.textSecondary,
          ),
        ),
        iconTheme: WidgetStateProperty.resolveWith(
          (states) => IconThemeData(
            color: states.contains(WidgetState.selected)
                ? primary
                : colors.textSecondary,
            size: 22,
          ),
        ),
      ),
      dividerTheme: DividerThemeData(
        color: colors.divider,
        thickness: AppTokens.borderWidth,
        space: AppTokens.borderWidth,
      ),
    );
  }

  static const _desktopTypography = TextTheme(
    headlineSmall: TextStyle(
      fontSize: 24,
      height: 1.25,
      fontWeight: FontWeight.w600,
      letterSpacing: -.35,
    ),
    titleLarge: TextStyle(
      fontSize: 20,
      height: 1.3,
      fontWeight: FontWeight.w600,
      letterSpacing: -.2,
    ),
    titleMedium: TextStyle(
      fontSize: 15,
      height: 1.35,
      fontWeight: FontWeight.w600,
      letterSpacing: 0,
    ),
    titleSmall: TextStyle(
      fontSize: 13,
      height: 1.35,
      fontWeight: FontWeight.w600,
      letterSpacing: 0,
    ),
    bodyLarge: TextStyle(fontSize: 14, height: 1.45, letterSpacing: 0),
    bodyMedium: TextStyle(fontSize: 13, height: 1.45, letterSpacing: 0),
    bodySmall: TextStyle(fontSize: 12, height: 1.4, letterSpacing: 0),
    labelLarge: TextStyle(
      fontSize: 13,
      height: 1.35,
      fontWeight: FontWeight.w500,
      letterSpacing: 0,
    ),
    labelMedium: TextStyle(
      fontSize: 12,
      height: 1.35,
      fontWeight: FontWeight.w500,
      letterSpacing: 0,
    ),
    labelSmall: TextStyle(
      fontSize: 11,
      height: 1.35,
      fontWeight: FontWeight.w500,
      letterSpacing: .1,
    ),
  );
}
