import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/navigation.dart';

void main() {
  group('P2WlanSection — primary IA', () {
    test(
      'primary user-level destinations are Home, Devices, Troubleshooting, Settings',
      () {
        expect(P2WlanSection.primary, [
          P2WlanSection.home,
          P2WlanSection.devices,
          P2WlanSection.troubleshooting,
          P2WlanSection.settings,
        ]);
      },
    );

    test('tunnels is secondary, never primary', () {
      expect(P2WlanSection.secondary, [P2WlanSection.tunnels]);
      expect(P2WlanSection.primary, isNot(contains(P2WlanSection.tunnels)));
    });

    test('every primary section has a sidebar group slot', () {
      final grouped = P2WlanSection.sidebarGroups.expand((g) => g).toList();
      expect(grouped, P2WlanSection.primary);
    });

    test('sidebar groups match the desktop model', () {
      expect(P2WlanSection.sidebarGroups, [
        [P2WlanSection.home, P2WlanSection.devices],
        [P2WlanSection.troubleshooting],
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

    test('troubleshooting stays a primary (routable) section on mobile', () {
      expect(P2WlanSection.primary, contains(P2WlanSection.troubleshooting));
    });

    test('primary plus secondary covers every section exactly once', () {
      final covered = [...P2WlanSection.primary, ...P2WlanSection.secondary];
      expect(covered.toSet().length, covered.length);
      expect(covered, containsAll(P2WlanSection.primary));
      expect(covered, containsAll(P2WlanSection.secondary));
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
