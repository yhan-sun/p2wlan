import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/platform/windows_startup_registration.dart';

void main() {
  const registryKey = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  const executable = r'C:\Program Files\P2WLAN\p2wlan.exe';
  const expectedCommand =
      r'"C:\Program Files\P2WLAN\p2wlan.exe" --p2wlan-login-startup';
  const staleCommand = r'"C:\Old\p2wlan.exe" --p2wlan-login-startup';

  test('reports only the current executable registration as enabled', () async {
    final calls = <(String, List<String>)>[];
    final registration = WindowsStartupRegistration(
      executablePath: executable,
      isSupportedOverride: true,
      processRunner: (command, arguments) async {
        calls.add((command, arguments));
        return ProcessResult(
          0,
          0,
          'P2WLAN    REG_SZ    $expectedCommand',
          '',
        );
      },
    );

    expect(await registration.isEnabled(), isTrue);
    expect(calls, [
      ('reg.exe', ['query', registryKey, '/v', 'P2WLAN']),
    ]);
  });

  test(
    'stale Windows executable registration is not reported enabled',
    () async {
      final registration = WindowsStartupRegistration(
        executablePath: executable,
        isSupportedOverride: true,
        processRunner: (_, _) async => ProcessResult(
          0,
          0,
          'P2WLAN REG_SZ $staleCommand',
          '',
        ),
      );

      expect(await registration.isEnabled(), isFalse);
    },
  );

  test(
    'writes a quoted application command when enabling login startup',
    () async {
      final calls = <(String, List<String>)>[];
      final registration = WindowsStartupRegistration(
        executablePath: executable,
        isSupportedOverride: true,
        processRunner: (command, arguments) async {
          calls.add((command, arguments));
          return ProcessResult(0, 0, '', '');
        },
      );

      await registration.setEnabled(true);

      expect(calls, [
        (
          'reg.exe',
          [
            'add',
            registryKey,
            '/v',
            'P2WLAN',
            '/t',
            'REG_SZ',
            '/d',
            expectedCommand,
            '/f',
          ],
        ),
      ]);
    },
  );

  test('removes the P2WLAN login-startup value when disabling', () async {
    final calls = <(String, List<String>)>[];
    final registration = WindowsStartupRegistration(
      isSupportedOverride: true,
      processRunner: (command, arguments) async {
        calls.add((command, arguments));
        return ProcessResult(0, 0, '', '');
      },
    );

    await registration.setEnabled(false);

    expect(calls, [
      ('reg.exe', ['delete', registryKey, '/v', 'P2WLAN', '/f']),
    ]);
  });

  test(
    'rejects ambiguous executable paths and failed registry writes',
    () async {
      expect(
        () => startupCommandForExecutable(
          r'C:\bad"path\p2wlan.exe',
          loginStartupArgument: loginStartupArgument,
        ),
        throwsArgumentError,
      );
      final registration = WindowsStartupRegistration(
        isSupportedOverride: true,
        processRunner: (_, _) async => ProcessResult(0, 1, '', 'denied'),
      );

      await expectLater(
        registration.setEnabled(true),
        throwsA(isA<StartupRegistrationException>()),
      );
    },
  );

  test('login startup connects only after safe desktop bootstrap', () {
    expect(isLoginStartupInvocation([loginStartupArgument]), isTrue);
    expect(isLoginStartupInvocation(const []), isFalse);
    expect(
      shouldConnectAfterLoginStartup(
        wasLaunchedAtLogin: true,
        hasValidSession: true,
        onboardingComplete: true,
        canActAsLocalVpnNode: true,
      ),
      isTrue,
    );
    expect(
      shouldConnectAfterLoginStartup(
        wasLaunchedAtLogin: true,
        hasValidSession: false,
        onboardingComplete: true,
        canActAsLocalVpnNode: true,
      ),
      isFalse,
    );
    expect(
      shouldConnectAfterLoginStartup(
        wasLaunchedAtLogin: false,
        hasValidSession: true,
        onboardingComplete: true,
        canActAsLocalVpnNode: true,
      ),
      isFalse,
    );
  });
}
