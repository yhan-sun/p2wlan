import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/navigation_model.dart';

void main() {
  group('P2WlanSection — primary IA', () {
    test('primary user-level destinations are Home, Devices, Settings', () {
      expect(P2WlanSection.primary, [
        P2WlanSection.home,
        P2WlanSection.devices,
        P2WlanSection.settings,
      ]);
    });

    test('there is no separate tunnels section', () {
      // Phase 5: Tunnels was fully absorbed into Troubleshooting → Advanced.
      for (final section in P2WlanSection.values) {
        expect(section.name, isNot('tunnels'));
      }
    });

    test('every primary section has a sidebar group slot', () {
      final grouped = P2WlanSection.sidebarGroups.expand((g) => g).toList();
      expect(grouped, P2WlanSection.primary);
    });

    test('sidebar groups match the desktop model', () {
      expect(P2WlanSection.sidebarGroups, [
        [P2WlanSection.home, P2WlanSection.devices],
        [P2WlanSection.settings],
      ]);
    });
  });

  group('P2WlanSection — mobile model', () {
    test(
      'permanent bottom-bar destinations are exactly Home, Devices, Settings',
      () {
        expect(P2WlanSection.mobilePrimary, [
          P2WlanSection.home,
          P2WlanSection.devices,
          P2WlanSection.settings,
        ]);
      },
    );

    test('troubleshooting is not a permanent mobile tab', () {
      expect(
        P2WlanSection.mobilePrimary,
        isNot(contains(P2WlanSection.troubleshooting)),
      );
    });

    test('troubleshooting stays routable without a permanent nav item', () {
      expect(P2WlanSection.values, contains(P2WlanSection.troubleshooting));
      expect(
        P2WlanSection.primary,
        isNot(contains(P2WlanSection.troubleshooting)),
      );
      expect(
        P2WlanSection.sidebarGroups.expand((group) => group),
        isNot(contains(P2WlanSection.troubleshooting)),
      );
    });

    test('primary covers every visible section exactly once', () {
      expect(
        P2WlanSection.primary.toSet().length,
        P2WlanSection.primary.length,
      );
      expect(
        P2WlanSection.primary,
        containsAll([
          P2WlanSection.home,
          P2WlanSection.devices,
          P2WlanSection.settings,
        ]),
      );
    });
  });

  group('P2WlanSection labels', () {
    test('desktop labels resolve in both locales', () {
      for (final section in P2WlanSection.primary) {
        final zh = AppStrings.fromCode('zh-Hans').sectionLabel(section.name);
        final en = AppStrings.fromCode('en').sectionLabel(section.name);
        expect(
          zh.trim(),
          isNotEmpty,
          reason: 'missing zh label for ${section.name}',
        );
        expect(
          en.trim(),
          isNotEmpty,
          reason: 'missing en label for ${section.name}',
        );
      }
    });

    test('home and troubleshooting have dedicated labels', () {
      final zh = AppStrings.fromCode('zh-Hans');
      final en = AppStrings.fromCode('en');
      expect(zh.home, '首页');
      expect(en.home, 'Home');
      expect(zh.troubleshooting, '故障排查');
      expect(en.troubleshooting, 'Troubleshooting');
    });
  });
}
