import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';

void main() {
  group('supported languages', () {
    test('zh-Hans and en both construct', () {
      expect(AppStrings.fromCode('zh-Hans').isZh, isTrue);
      expect(AppStrings.fromCode('en').isZh, isFalse);
    });
  });

  group('terminology consistency', () {
    test('path terms are stable across locales', () {
      final zh = AppStrings.fromCode('zh-Hans');
      final en = AppStrings.fromCode('en');
      expect(zh.direct, '直连');
      expect(en.direct, 'Direct');
      expect(zh.relay, '中继');
      expect(en.relay, 'Relay');
      expect(zh.probing, '探测中');
      expect(en.probing.toLowerCase(), 'probing');
      expect(zh.offline, '离线');
      expect(en.offline, 'Offline');
    });

    test('navigation labels are consistent', () {
      final zh = AppStrings.fromCode('zh-Hans');
      final en = AppStrings.fromCode('en');
      expect(zh.dashboard, '仪表盘');
      expect(en.dashboard, 'Dashboard');
      expect(zh.nodes, '节点');
      expect(en.nodes, 'Nodes');
      expect(zh.settings, isNotEmpty);
      expect(en.settings, isNotEmpty);
      expect(zh.diagnostics, isNotEmpty);
      expect(en.diagnostics, isNotEmpty);
    });
  });

  group('key user-facing getters are present', () {
    test('core copy is non-empty for both locales', () {
      for (final code in ['zh-Hans', 'en']) {
        final s = AppStrings.fromCode(code);
        expect(s.signIn.trim(), isNotEmpty);
        expect(s.createAccount.trim(), isNotEmpty);
        expect(s.diagnosticsSubtitle.trim(), isNotEmpty);
        expect(s.onboardingTitle.trim(), isNotEmpty);
        expect(s.tunnelsSubtitle.trim(), isNotEmpty);
        expect(s.overviewHealthyTitle.trim(), isNotEmpty);
        expect(s.loginErrorUnknownTitle.trim(), isNotEmpty);
        expect(s.settingsSaveFailed.trim(), isNotEmpty);
      }
    });
  });

  group('plural handling (English)', () {
    test('device count uses singular for 1', () {
      final en = AppStrings.fromCode('en');
      expect(en.deviceCountSummary(1, 1), '1 device · 1 online');
      expect(en.deviceCountSummary(2, 1), '2 devices · 1 online');
      expect(en.devicesNeedPathReview(1), '1 device needs path review');
      expect(en.devicesNeedPathReview(2), '2 devices need path review');
      expect(en.moreDevices(1), startsWith('1 more device'));
      expect(en.moreDevices(2), startsWith('2 more devices'));
    });

    test('Chinese does not inflect', () {
      final zh = AppStrings.fromCode('zh-Hans');
      expect(zh.deviceCountSummary(1, 1), '1 台设备 · 1 在线');
      expect(zh.deviceCountSummary(2, 1), '2 台设备 · 1 在线');
      expect(zh.devicesNeedPathReview(1), '1 台设备的连接路径需要检查');
    });
  });

  group('dynamic copy stays per-locale', () {
    test('device count phrasing is locale independent, not spliced', () {
      final zh = AppStrings.fromCode('zh-Hans');
      final en = AppStrings.fromCode('en');
      expect(zh.devicesOnlineOk(3), contains('台在线'));
      expect(en.devicesOnlineOk(3), '3 online, no path anomalies');
    });
  });
}
