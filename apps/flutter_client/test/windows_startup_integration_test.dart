import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';

void main() {
  test(
    'Windows PowerShell PID producer output is consumed by the Dart parser',
    () async {
      final root = await Directory.systemTemp.createTemp(
        'p2wlan windows producer space 中文',
      );
      addTearDown(() async {
        try {
          await root.delete(recursive: true);
        } catch (_) {}
      });
      final script = File('${root.path}${Platform.pathSeparator}producer.ps1');
      await script.writeAsString(r'''
$ErrorActionPreference = 'Stop'
$child = [pscustomobject]@{Id=12345}
Write-Output ('__P2WLAN_CHILD_PID__=' + [string]$child.Id)
''');

      if (!Platform.isWindows) return;
      final windir = Platform.environment['WINDIR']?.trim();
      final powershell = windir == null || windir.isEmpty
          ? 'powershell.exe'
          : '$windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
      final result = await Process.run(powershell, [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        script.path,
      ], workingDirectory: root.path);
      expect(result.exitCode, 0, reason: result.stderr.toString());
      expect(parseWindowsChildPidMarker(result.stdout.toString()), 12345);
    },
  );
}
