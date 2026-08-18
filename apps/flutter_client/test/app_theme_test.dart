import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/app_tokens.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_colors.dart';

/// HSL hue of a color (0..360). Used to lock the brand to a single hue family
/// across light and dark without brittle exact-RGB tests.
double _hue(Color color) {
  final r = color.r;
  final g = color.g;
  final b = color.b;
  final max = [r, g, b].reduce((a, b) => a > b ? a : b);
  final min = [r, g, b].reduce((a, b) => a < b ? a : b);
  final delta = max - min;
  if (delta == 0) return 0;
  double h;
  if (max == r) {
    h = 60 * (((g - b) / delta) % 6);
  } else if (max == g) {
    h = 60 * ((b - r) / delta + 2);
  } else {
    h = 60 * ((r - g) / delta + 4);
  }
  return h < 0 ? h + 360 : h;
}

double _luminance(Color color) {
  double lin(double c) {
    final v = c <= 0.03928
        ? c / 12.92
        : math.pow((c + 0.055) / 1.055, 2.4).toDouble();
    return v;
  }

  return 0.2126 * lin(color.r) + 0.7152 * lin(color.g) + 0.0722 * lin(color.b);
}

double _contrast(Color a, Color b) {
  final l1 = _luminance(a);
  final l2 = _luminance(b);
  final hi = l1 > l2 ? l1 : l2;
  final lo = l1 > l2 ? l2 : l1;
  return (hi + 0.05) / (lo + 0.05);
}

double _hueDistance(double a, double b) {
  final d = (a - b).abs();
  return d > 180 ? 360 - d : d;
}

void main() {
  group('brand', () {
    test('light and dark primary belong to the same hue family', () {
      final lightHue = _hue(AppTokens.colorAccent);
      final darkHue = _hue(AppTokens.colorDarkAccent);
      // Same teal hue family; dark only lightens for contrast, never shifts to
      // a different brand (this was previously a sky blue).
      expect(_hueDistance(lightHue, darkHue), lessThan(20));
    });

    test('light primary is a darker shade than dark primary (same hue)', () {
      final light = AppTokens.colorAccent;
      final dark = AppTokens.colorDarkAccent;
      expect(light.computeLuminance(), lessThan(dark.computeLuminance()));
    });
  });

  group('P2WlanColors palette', () {
    for (final (name, palette) in [
      ('light', P2WlanColors.light),
      ('dark', P2WlanColors.dark),
    ]) {
      test('$name: path semantics are distinct and never collapse', () {
        expect(palette.direct, isNot(equals(palette.relay)));
        expect(palette.relay, isNot(equals(palette.probing)));
        expect(palette.probing, isNot(equals(palette.offline)));
        // Relay is a normal usable path, never a warning.
        expect(palette.relay, isNot(equals(palette.warningText)));
      });

      test('$name: warning and danger are distinct severities', () {
        expect(palette.warningText, isNot(equals(palette.dangerText)));
        expect(palette.warningSurface, isNot(equals(palette.dangerSurface)));
      });

      test('$name: console surface differs from the background', () {
        final background = name == 'light'
            ? AppTokens.colorBg
            : AppTokens.colorDarkBg;
        expect(palette.consoleSurface, isNot(equals(background)));
        expect(palette.consoleText, isNot(equals(palette.consoleSurface)));
      });

      test('$name: selected/hover surfaces exist and differ from surface', () {
        expect(palette.selectedSurface, isNot(equals(palette.surface)));
        expect(palette.hoverSurface, isNot(equals(palette.surface)));
      });

      test('$name: semantic text hierarchy is monotonic', () {
        expect(palette.textPrimary, isNot(equals(palette.textSecondary)));
        expect(palette.textSecondary, isNot(equals(palette.textMuted)));
      });
    }

    test(
      'light and dark palettes resolve every field to a non-transparent color',
      () {
        for (final palette in [P2WlanColors.light, P2WlanColors.dark]) {
          final fields = <Color>[
            palette.textPrimary,
            palette.textSecondary,
            palette.textMuted,
            palette.border,
            palette.borderStrong,
            palette.divider,
            palette.surface,
            palette.surfaceElevated,
            palette.surfaceMuted,
            palette.selectedSurface,
            palette.hoverSurface,
            palette.direct,
            palette.relay,
            palette.probing,
            palette.offline,
            palette.successSurface,
            palette.successBorder,
            palette.successText,
            palette.successDot,
            palette.warningSurface,
            palette.warningBorder,
            palette.warningText,
            palette.warningDot,
            palette.dangerSurface,
            palette.dangerBorder,
            palette.dangerText,
            palette.dangerDot,
            palette.neutralSurface,
            palette.neutralBorder,
            palette.neutralText,
            palette.neutralDot,
            palette.consoleSurface,
            palette.consoleBorder,
            palette.consoleText,
          ];
          expect(
            fields.every((c) => c.a > 0),
            isTrue,
            reason: 'no field may be fully transparent',
          );
        }
      },
    );
  });

  group('theme wiring', () {
    test('both themes expose the P2WlanColors extension', () {
      expect(AppTheme.lightTheme.extension<P2WlanColors>(), P2WlanColors.light);
      expect(AppTheme.darkTheme.extension<P2WlanColors>(), P2WlanColors.dark);
    });

    test('primary text keeps readable contrast on its surface', () {
      expect(
        _contrast(
          AppTheme.lightTheme.colorScheme.onSurface,
          AppTheme.lightTheme.colorScheme.surface,
        ),
        greaterThan(3),
      );
      expect(
        _contrast(
          AppTheme.darkTheme.colorScheme.onSurface,
          AppTheme.darkTheme.colorScheme.surface,
        ),
        greaterThan(3),
      );
    });

    test('light and dark share the same primary hue via ColorScheme', () {
      final lightHue = _hue(AppTheme.lightTheme.colorScheme.primary);
      final darkHue = _hue(AppTheme.darkTheme.colorScheme.primary);
      expect(_hueDistance(lightHue, darkHue), lessThan(20));
    });
  });
}
