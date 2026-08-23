import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/main.dart';

void main() {
  group('autoStartDaemonForEnvironment', () {
    test('defaults to disabled', () {
      expect(autoStartDaemonForEnvironment({}), isFalse);
    });

    test('enables only for explicit true-like values', () {
      for (final value in ['1', 'true', 'yes', 'on', ' TRUE ']) {
        expect(
          autoStartDaemonForEnvironment({'P2WLAN_AUTO_START_DAEMON': value}),
          isTrue,
        );
      }
      for (final value in ['', '0', 'false', 'no', 'off', 'unexpected']) {
        expect(
          autoStartDaemonForEnvironment({'P2WLAN_AUTO_START_DAEMON': value}),
          isFalse,
        );
      }
    });
  });

  group('enableFlutterTrayForEnvironment', () {
    test(
      'defaults to enabled because the Flutter tray is bundled in releases',
      () {
        expect(enableFlutterTrayForEnvironment({}), isTrue);
      },
    );

    test('disables tray for explicit false-like values', () {
      for (final value in ['0', 'false', 'no', 'off']) {
        expect(
          enableFlutterTrayForEnvironment({
            'P2WLAN_ENABLE_FLUTTER_TRAY': value,
          }),
          isFalse,
        );
      }
    });

    test('enables tray for explicit true-like value', () {
      expect(
        enableFlutterTrayForEnvironment({'P2WLAN_ENABLE_FLUTTER_TRAY': '1'}),
        isTrue,
      );
    });
  });
}
