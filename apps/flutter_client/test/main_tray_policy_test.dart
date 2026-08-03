import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/main.dart';

void main() {
  group('enableFlutterTrayForEnvironment', () {
    test('defaults to enabled when environment is empty', () {
      expect(enableFlutterTrayForEnvironment({}), isTrue);
    });

    test('disables tray for explicit false-like values', () {
      for (final value in ['0', 'false', 'no', 'off']) {
        expect(
          enableFlutterTrayForEnvironment({'P2WLAN_ENABLE_FLUTTER_TRAY': value}),
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
