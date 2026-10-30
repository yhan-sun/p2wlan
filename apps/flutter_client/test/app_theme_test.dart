import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
      // Same blue hue family; dark only lightens for contrast.
      expect(_hueDistance(lightHue, darkHue), lessThan(20));
    });

    test('light primary matches the approved UI reference', () {
      expect(AppTokens.colorAccent, const Color(0xFF2563EB));
      expect(AppTokens.colorBg, const Color(0xFFF5F7FB));
      expect(AppTokens.colorSurface, const Color(0xFFFFFFFF));
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

  for (final theme in [AppTheme.lightTheme, AppTheme.darkTheme]) {
    final mode = theme.brightness.name;
    testWidgets('$mode buttons support Tab, Enter and visible focus', (
      tester,
    ) async {
      final nodes = List.generate(5, (_) => FocusNode());
      for (final node in nodes) {
        addTearDown(node.dispose);
      }
      final activated = <int>[];
      final buttons = <Widget>[
        FilledButton(
          key: const Key('filled'),
          focusNode: nodes[0],
          onPressed: () => activated.add(0),
          child: const Text('Save'),
        ),
        OutlinedButton(
          key: const Key('outlined'),
          focusNode: nodes[1],
          onPressed: () => activated.add(1),
          child: const Text('Configure'),
        ),
        TextButton(
          key: const Key('text'),
          focusNode: nodes[2],
          onPressed: () => activated.add(2),
          child: const Text('Cancel'),
        ),
        IconButton(
          key: const Key('icon'),
          focusNode: nodes[3],
          onPressed: () => activated.add(3),
          tooltip: 'Refresh',
          icon: const Icon(Icons.refresh),
        ),
      ];
      await tester.pumpWidget(
        MaterialApp(
          theme: theme,
          home: Scaffold(
            body: Column(
              children: [
                Row(children: buttons),
                const Row(
                  children: [
                    FilledButton(onPressed: null, child: Text('Disabled save')),
                    OutlinedButton(
                      onPressed: null,
                      child: Text('Disabled outline'),
                    ),
                    TextButton(onPressed: null, child: Text('Disabled text')),
                    IconButton(onPressed: null, icon: Icon(Icons.block)),
                  ],
                ),
                TextButton(
                  focusNode: nodes[4],
                  onPressed: () => activated.add(4),
                  child: const Text('After disabled buttons'),
                ),
              ],
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      for (var index = 0; index < 4; index += 1) {
        await tester.sendKeyEvent(LogicalKeyboardKey.tab);
        await tester.pumpAndSettle();
        expect(nodes[index].hasFocus, isTrue);
        final target = find.byKey(
          Key(['filled', 'outlined', 'text', 'icon'][index]),
        );
        final material = tester.widget<Material>(
          find.descendant(of: target, matching: find.byType(Material)).first,
        );
        final side = (material.shape! as OutlinedBorder).side;
        expect(side.width, 2);
        expect(
          _contrast(
            side.color,
            index == 0 ? theme.colorScheme.primary : theme.colorScheme.surface,
          ),
          greaterThanOrEqualTo(3),
        );
        await tester.sendKeyEvent(LogicalKeyboardKey.enter);
        await tester.pumpAndSettle();
        expect(activated, List.generate(index + 1, (value) => value));
      }
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      expect(nodes[4].hasFocus, isTrue);
      for (final text in [
        'Disabled save',
        'Disabled outline',
        'Disabled text',
      ]) {
        await tester.tap(find.text(text));
      }
      expect(activated, [0, 1, 2, 3]);
      expect(
        tester.getSize(find.byKey(const Key('text'))).height,
        greaterThanOrEqualTo(44),
      );
      expect(tester.takeException(), isNull);
    });

    testWidgets('$mode button theme preserves a local style override', (
      tester,
    ) async {
      final focus = FocusNode();
      addTearDown(focus.dispose);
      final customColor = theme.colorScheme.error;
      await tester.pumpWidget(
        MaterialApp(
          theme: theme,
          home: Scaffold(
            body: OutlinedButton(
              focusNode: focus,
              onPressed: () {},
              style: OutlinedButton.styleFrom(
                foregroundColor: customColor,
                side: BorderSide(color: customColor, width: 3),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(20),
                ),
              ),
              child: const Text('Custom action'),
            ),
          ),
        ),
      );
      focus.requestFocus();
      await tester.pumpAndSettle();
      final material = tester.widget<Material>(
        find
            .descendant(
              of: find.byType(OutlinedButton),
              matching: find.byType(Material),
            )
            .first,
      );
      final shape = material.shape! as RoundedRectangleBorder;
      expect(shape.side, BorderSide(color: customColor, width: 3));
      expect(shape.borderRadius, BorderRadius.circular(20));
      expect(tester.takeException(), isNull);
    });

    test(
      '$mode text buttons share geometry and disabled feedback stays quiet',
      () {
        final text = theme.textButtonTheme.style!;
        expect(text.minimumSize!.resolve({}), const Size(44, 44));
        expect(
          text.padding!.resolve({}),
          const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        );
        expect(
          (text.shape!.resolve({})! as RoundedRectangleBorder).borderRadius,
          BorderRadius.circular(8),
        );
        expect(text.textStyle!.resolve({})!.fontSize, 14);
        expect(text.textStyle!.resolve({})!.fontWeight, FontWeight.w600);
        for (final style in [
          theme.filledButtonTheme.style!,
          theme.outlinedButtonTheme.style!,
          text,
          theme.iconButtonTheme.style!,
        ]) {
          const disabled = {
            WidgetState.disabled,
            WidgetState.focused,
            WidgetState.hovered,
          };
          expect(style.side!.resolve(disabled)!.width, lessThan(2));
          expect(style.overlayColor!.resolve(disabled), Colors.transparent);
        }
      },
    );
  }
}
