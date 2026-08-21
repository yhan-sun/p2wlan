import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/desktop_window_operations.dart';

void main() {
  test('serializes native window operations', () async {
    final events = <String>[];
    final firstStarted = Completer<void>();
    final releaseFirst = Completer<void>();

    final first = DesktopWindowOperations.run(() async {
      events.add('first-start');
      firstStarted.complete();
      await releaseFirst.future;
      events.add('first-end');
      return 1;
    });
    await firstStarted.future;

    final second = DesktopWindowOperations.run(() async {
      events.add('second-start');
      return 2;
    });

    await Future<void>.delayed(Duration.zero);
    expect(events, ['first-start']);

    releaseFirst.complete();
    expect(await first, 1);
    expect(await second, 2);
    expect(events, ['first-start', 'first-end', 'second-start']);
  });
}
