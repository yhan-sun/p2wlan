import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';

void main() {
  test('trusted Windows daemon identity is limited to sourced PIDs', () {
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: 4242,
        authenticatedProcessId: null,
        processName: 'p2wlan-daemon.exe',
      ),
      isTrue,
    );
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: null,
        authenticatedProcessId: 4242,
        processName: 'P2WLAN-DAEMON.EXE',
      ),
      isTrue,
    );
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: 1000,
        authenticatedProcessId: 2000,
        processName: 'p2wlan-daemon.exe',
      ),
      isFalse,
    );
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: 4242,
        authenticatedProcessId: null,
        processName: 'powershell.exe',
      ),
      isFalse,
    );
  });

  test('Windows PowerShell helper preserves Unicode output', () async {
    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);
    final result = await controller.runWindowsPowerShellForTesting(
      "Write-Output 'P2WLAN-中文路径-✓'",
    );
    expect(result.exitCode, 0, reason: result.stderr.toString());
    expect(result.stdout.toString().trim(), 'P2WLAN-中文路径-✓');
  }, skip: !Platform.isWindows);
}
