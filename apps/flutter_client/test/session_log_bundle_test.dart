import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/session_log_bundle.dart';

void main() {
  test('collects current files and never reads rotated logs', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_session_logs_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    final client = File('${directory.path}/p2wlan-client.log');
    await daemon.writeAsString('Bearer live-token\nprobe ok\n');
    await client.writeAsString('startup ok\n');
    await File('${daemon.path}.1').writeAsString('old startup\n');

    final bundle = await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: client.path,
    );

    expect(bundle.files.map((file) => file.name), [
      'p2wlan-daemon.log',
      'p2wlan-client.log',
    ]);
    expect(bundle.files.first.content, contains('Bearer <redacted>'));
    expect(bundle.files.first.content, isNot(contains('live-token')));
    expect(bundle.files.first.content, isNot(contains('old startup')));
  });

  test('keeps only the tail when a current file exceeds the bound', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_session_logs_tail_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    await daemon.writeAsString('first line\nsecond line\n');

    final bundle = await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: '${directory.path}/missing-client.log',
      maxBytesPerFile: 8,
    );

    expect(bundle.files.single.content, contains('showing its tail only'));
    expect(bundle.files.single.content, contains('line\n'));
    expect(bundle.files.single.content, isNot(contains('first line')));
  });
}
