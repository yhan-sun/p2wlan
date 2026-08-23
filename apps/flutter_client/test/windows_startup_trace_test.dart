import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/build_info.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';

void main() {
  test(
    'Windows startup trace records ordered redacted handoff stages',
    () async {
      final root = await Directory.systemTemp.createTemp(
        'p2wlan startup trace ',
      );
      addTearDown(() async {
        try {
          await root.delete(recursive: true);
        } catch (_) {}
      });

      final trace = WindowsStartupTrace(
        root,
        clientBuild: const ClientBuildInfo(
          appVersion: '0.1.134',
          gitCommit: 'abc',
          buildId: 'abc',
          dirtyValue: 'false',
          diffHash: '',
          profile: 'release',
        ),
      );
      await trace.open();
      await trace.startRequested();
      await trace.stageStart(1, 'resolve_daemon');
      await trace.stageOk(1, 'resolve_daemon');
      await trace.stageAccepted(8, 'uac');
      await trace.childPid(4242);
      await trace.daemonAlive();
      await trace.stageStart(11, 'health_wait');
      await trace.failure(11, 'DAEMON_EXITED_DURING_STARTUP');

      final contents = await trace.file.readAsString();
      expect(contents, contains('client build identity'));
      expect(contents, contains('[windows-startup] 09 child_pid PID=4242'));
      expect(
        contents,
        contains(
          '[windows-startup] FAIL stage=11 code=DAEMON_EXITED_DURING_STARTUP',
        ),
      );
      expect(contents, isNot(contains('authToken')));
      expect(
        contents.indexOf('[windows-startup] 08 uac ACCEPTED'),
        lessThan(contents.indexOf('[windows-startup] 09 child_pid')),
      );
      expect(
        contents.indexOf('[windows-startup] 10 daemon_alive OK'),
        lessThan(contents.indexOf('[windows-startup] 11 health_wait START')),
      );
    },
  );
}
