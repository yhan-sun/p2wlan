import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/shared/layout/app_breakpoints.dart';

void main() {
  group('AppBreakpoints.of — window size classes', () {
    const cases = <(double, AppBreakpoint)>[
      (0, AppBreakpoint.compact),
      (599, AppBreakpoint.compact),
      (600, AppBreakpoint.medium),
      (1023, AppBreakpoint.medium),
      (1024, AppBreakpoint.expanded),
      (1920, AppBreakpoint.expanded),
    ];

    for (final (width, expected) in cases) {
      test('$width → ${expected.name}', () {
        expect(AppBreakpoints.of(width), expected);
      });
    }
  });

  group('AppBreakpoints boundary constants', () {
    test('compact sits strictly below 600', () {
      expect(AppBreakpoints.compactMaxWidth, 600);
    });

    test('desktop sidebar starts at 800', () {
      expect(AppBreakpoints.desktopSidebarMinWidth, 800);
    });

    test('expanded starts at 1024', () {
      expect(AppBreakpoints.expandedMinWidth, 1024);
    });

    test('the three classes partition the width axis', () {
      final classes = [
        for (var w = 0; w <= 2048; w += 8) AppBreakpoints.of(w.toDouble()),
      ];
      expect(classes, contains(AppBreakpoint.compact));
      expect(classes, contains(AppBreakpoint.medium));
      expect(classes, contains(AppBreakpoint.expanded));
    });
  });
}
