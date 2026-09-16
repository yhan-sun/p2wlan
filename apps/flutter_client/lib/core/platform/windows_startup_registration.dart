import 'dart:async';
import 'dart:io';

/// A small, bounded wrapper around the current user's Windows login-startup
/// registration. It launches the desktop application with a dedicated flag;
/// the app accepts that flag only after its authenticated bootstrap completes.
abstract interface class StartupRegistration {
  bool get isSupported;

  Future<bool> isEnabled();

  Future<void> setEnabled(bool enabled);
}

typedef StartupProcessRunner =
    Future<ProcessResult> Function(String executable, List<String> arguments);

class WindowsStartupRegistration implements StartupRegistration {
  WindowsStartupRegistration({
    StartupProcessRunner? processRunner,
    String? executablePath,
    bool? isSupportedOverride,
  }) : _processRunner = processRunner ?? _runProcess,
       _executablePath = executablePath ?? Platform.resolvedExecutable,
       _isSupported = isSupportedOverride ?? Platform.isWindows;

  static const _registryKey =
      r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  static const _valueName = 'P2WLAN';
  static const loginStartupArgument = '--p2wlan-login-startup';
  static const _commandTimeout = Duration(seconds: 3);

  final StartupProcessRunner _processRunner;
  final String _executablePath;
  final bool _isSupported;

  @override
  bool get isSupported => _isSupported;

  @override
  Future<bool> isEnabled() async {
    _ensureSupported();
    final result = await _query();
    return result.exitCode == 0 &&
        result.stdout.toString().contains(loginStartupArgument);
  }

  @override
  Future<void> setEnabled(bool enabled) async {
    _ensureSupported();
    final arguments = enabled
        ? [
            'add',
            _registryKey,
            '/v',
            _valueName,
            '/t',
            'REG_SZ',
            '/d',
            startupCommandForExecutable(
              _executablePath,
              loginStartupArgument: loginStartupArgument,
            ),
            '/f',
          ]
        : ['delete', _registryKey, '/v', _valueName, '/f'];
    final result = await _run(arguments);
    if (result.exitCode == 0) return;

    // A simultaneous cleanup can remove a value after the UI read it. Treat
    // that particular disable race as successful, but retain failures that
    // leave the registration enabled.
    if (!enabled && (await _query()).exitCode != 0) return;
    throw const StartupRegistrationException();
  }

  Future<ProcessResult> _query() => _run([
    'query',
    _registryKey,
    '/v',
    _valueName,
  ]);

  Future<ProcessResult> _run(List<String> arguments) async {
    try {
      return await _processRunner(
        'reg.exe',
        arguments,
      ).timeout(_commandTimeout);
    } on TimeoutException {
      throw const StartupRegistrationException();
    } on ProcessException {
      throw const StartupRegistrationException();
    }
  }

  void _ensureSupported() {
    if (!isSupported) {
      throw UnsupportedError(
        'Windows startup registration is unavailable on this platform.',
      );
    }
  }

  static Future<ProcessResult> _runProcess(
    String executable,
    List<String> arguments,
  ) => Process.run(executable, arguments);
}

/// The registry stores one command-line string. Windows paths cannot contain
/// a double quote, so reject one rather than building an ambiguous command.
String startupCommandForExecutable(
  String executablePath, {
  required String loginStartupArgument,
}) {
  final path = executablePath.trim();
  final argument = loginStartupArgument.trim();
  if (path.isEmpty ||
      path.contains('"') ||
      argument.isEmpty ||
      argument.contains(RegExp(r'[\s"]'))) {
    throw ArgumentError.value(executablePath, 'executablePath');
  }
  return '"$path" $argument';
}

bool isWindowsLoginStartupInvocation(Iterable<String> executableArguments) =>
    executableArguments.contains(WindowsStartupRegistration.loginStartupArgument);

bool shouldConnectAfterWindowsLoginStartup({
  required bool wasLaunchedAtLogin,
  required bool hasValidSession,
  required bool onboardingComplete,
  required bool canActAsLocalVpnNode,
}) =>
    wasLaunchedAtLogin &&
    hasValidSession &&
    onboardingComplete &&
    canActAsLocalVpnNode;

class StartupRegistrationException implements Exception {
  const StartupRegistrationException();
}
