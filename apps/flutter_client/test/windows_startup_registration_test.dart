import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/platform/windows_startup_registration.dart';

void main() {
  const registryKey = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';

  test('reports whether the P2WLAN login-startup value exists', () async {
    final calls = <(String, List<String>)>[];
    final registration = WindowsStartupRegistration(
      executablePath: r'C:\Program Files\P2WLAN\p2wlan.exe',
      isSupportedOverride: true,
      processRunner: (executable, arguments) async {
        calls.add((executable, arguments));
        return ProcessResult(
          0,
          0,
          r'P2WLAN    REG_SZ    "C:\Program Files\P2WLAN\p2wlan.exe" --p2wlan-login-startup',
          '',
        );
      },
    );

    expect(await registration.isEnabled(), isTrue);
    expect(calls, [
      ('reg.exe', ['query', registryKey, '/v', 'P2WLAN']),
    ]);
  });

  test('writes a quoted application command when enabling login startup',
      () async {
    final calls = <(String, List<String>)>[];
    final registration = WindowsStartupRegistration(
      executablePath: r'C:\Program Files\P2WLAN\p2wlan.exe',
      isSupportedOverride: true,
      processRunner: (executable, arguments) async {
        calls.add((executable, arguments));
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
          r'"C:\Program Files\P2WLAN\p2wlan.exe" --p2wlan-login-startup',
          '/f',
        ],
      ),
    ]);
  });

  test('removes the P2WLAN login-startup value when disabling', () async {
    final calls = <(String, List<String>)>[];
    final registration = WindowsStartupRegistration(
      isSupportedOverride: true,
      processRunner: (executable, arguments) async {
        calls.add((executable, arguments));
        return ProcessResult(0, 0, '', '');
      },
    );

    await registration.setEnabled(false);

    expect(calls, [
      ('reg.exe', ['delete', registryKey, '/v', 'P2WLAN', '/f']),
    ]);
  });

  test('rejects ambiguous executable paths and failed registry writes', () async {
    expect(
      () => startupCommandForExecutable(
        r'C:\bad"path\p2wlan.exe',
        loginStartupArgument: WindowsStartupRegistration.loginStartupArgument,
      ),
      throwsArgumentError,
    );
    final registration = WindowsStartupRegistration(
      isSupportedOverride: true,
      processRunner: (_, __) async => ProcessResult(0, 1, '', 'denied'),
    );

    await expectLater(
      registration.setEnabled(true),
      throwsA(isA<StartupRegistrationException>()),
    );
  });

  test('only the login-startup command line requests an automatic connection',
      () {
    expect(
      isWindowsLoginStartupInvocation(
        [WindowsStartupRegistration.loginStartupArgument],
      ),
      isTrue,
    );
    expect(isWindowsLoginStartupInvocation(const []), isFalse);
    expect(
      shouldConnectAfterWindowsLoginStartup(
        wasLaunchedAtLogin: true,
        hasValidSession: true,
        onboardingComplete: true,
        canActAsLocalVpnNode: true,
      ),
      isTrue,
    );
    expect(
      shouldConnectAfterWindowsLoginStartup(
        wasLaunchedAtLogin: true,
        hasValidSession: false,
        onboardingComplete: true,
        canActAsLocalVpnNode: true,
      ),
      isFalse,
    );
    expect(
      shouldConnectAfterWindowsLoginStartup(
        wasLaunchedAtLogin: false,
        hasValidSession: true,
        onboardingComplete: true,
        canActAsLocalVpnNode: true,
      ),
      isFalse,
    );
  });
}
