import 'dart:async';
import 'dart:io';

typedef StartupProcessRunner =
    Future<ProcessResult> Function(String executable, List<String> arguments);

enum DesktopStartupPlatform { windows, macos, linux, unsupported }

const loginStartupArgument = '--p2wlan-login-startup';

/// Per-user desktop login registration.
///
/// The registration only launches the Flutter desktop application with
/// [loginStartupArgument]. Whether the daemon/network may start is decided
/// later by the authenticated application bootstrap.
abstract interface class StartupRegistration {
  bool get isSupported;

  Future<bool> isEnabled();

  Future<void> setEnabled(bool enabled);
}

class DesktopStartupRegistration implements StartupRegistration {
  DesktopStartupRegistration({
    StartupProcessRunner? processRunner,
    String? executablePath,
    this._homeDirectoryPath,
    Map<String, String>? environment,
    DesktopStartupPlatform? platformOverride,
  })
    : _processRunner = processRunner ?? _runProcess,
      _executablePath = executablePath ?? Platform.resolvedExecutable,
      _environment = environment ?? Platform.environment,
      _platform = platformOverride ?? _currentPlatform();

  static const _registryKey =
      r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  static const _registryValueName = 'P2WLAN';
  static const _launchAgentLabel = 'io.p2wlan.desktop.login-startup';
  static const _linuxDesktopFileName = 'p2wlan.desktop';
  static const _commandTimeout = Duration(seconds: 3);

  final StartupProcessRunner _processRunner;
  final String _executablePath;
  final String? _homeDirectoryPath;
  final Map<String, String> _environment;
  final DesktopStartupPlatform _platform;

  @override
  bool get isSupported => _platform != DesktopStartupPlatform.unsupported;

  @override
  Future<bool> isEnabled() async {
    _ensureSupported();
    return switch (_platform) {
      DesktopStartupPlatform.windows => _isWindowsEnabled(),
      DesktopStartupPlatform.macos => _isFileRegistrationCurrent(
        _macosLaunchAgentFile,
        _macosLaunchAgentContents,
      ),
      DesktopStartupPlatform.linux => _isFileRegistrationCurrent(
        _linuxAutostartFile,
        _linuxDesktopEntryContents,
      ),
      DesktopStartupPlatform.unsupported => false,
    };
  }

  @override
  Future<void> setEnabled(bool enabled) async {
    _ensureSupported();
    switch (_platform) {
      case DesktopStartupPlatform.windows:
        await _setWindowsEnabled(enabled);
        return;
      case DesktopStartupPlatform.macos:
        await _setFileRegistration(
          _macosLaunchAgentFile,
          _macosLaunchAgentContents,
          enabled,
        );
        return;
      case DesktopStartupPlatform.linux:
        await _setFileRegistration(
          _linuxAutostartFile,
          _linuxDesktopEntryContents,
          enabled,
        );
        return;
      case DesktopStartupPlatform.unsupported:
        throw const StartupRegistrationException();
    }
  }

  Future<bool> _isWindowsEnabled() async {
    final result = await _runWindows([
      'query',
      _registryKey,
      '/v',
      _registryValueName,
    ]);
    if (result.exitCode != 0) return false;
    final expected = startupCommandForExecutable(
      _executablePath,
      loginStartupArgument: loginStartupArgument,
    );
    return result.stdout.toString().contains(expected);
  }

  Future<void> _setWindowsEnabled(bool enabled) async {
    final arguments = enabled
        ? [
            'add',
            _registryKey,
            '/v',
            _registryValueName,
            '/t',
            'REG_SZ',
            '/d',
            startupCommandForExecutable(
              _executablePath,
              loginStartupArgument: loginStartupArgument,
            ),
            '/f',
          ]
        : ['delete', _registryKey, '/v', _registryValueName, '/f'];
    final result = await _runWindows(arguments);
    if (result.exitCode == 0) return;

    if (!enabled && !await _isWindowsEnabled()) return;
    throw const StartupRegistrationException();
  }

  Future<ProcessResult> _runWindows(List<String> arguments) async {
    try {
      final process = _processRunner('reg.exe', arguments);
      return await process.timeout(_commandTimeout);
    } on TimeoutException {
      throw const StartupRegistrationException();
    } on ProcessException {
      throw const StartupRegistrationException();
    }
  }

  File get _macosLaunchAgentFile {
    final path =
        '${_homeDirectory.path}/Library/LaunchAgents/$_launchAgentLabel.plist';
    return File(path);
  }

  String get _macosLaunchAgentContents {
    final executable = xmlEscape(_validatedExecutablePath);
    return '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$_launchAgentLabel</string>
  <key>ProgramArguments</key>
  <array>
    <string>$executable</string>
    <string>$loginStartupArgument</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
''';
  }

  File get _linuxAutostartFile {
    final configured = _environment['XDG_CONFIG_HOME']?.trim();
    String configRoot;
    final configuredIsAbsolute =
        configured != null &&
        configured.isNotEmpty &&
        configured.startsWith('/');
    if (configuredIsAbsolute) {
      configRoot = _requireSafePath(configured, 'XDG_CONFIG_HOME');
    } else {
      configRoot = '${_homeDirectory.path}/.config';
    }
    return File('$configRoot/autostart/$_linuxDesktopFileName');
  }

  String get _linuxDesktopEntryContents {
    final executable = desktopEntryQuoteArgument(_validatedExecutablePath);
    return '''[Desktop Entry]
Type=Application
Version=1.0
Name=P2WLAN
Comment=Start P2WLAN and reconnect the configured network after desktop login
Exec=$executable $loginStartupArgument
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
''';
  }

  Future<bool> _isFileRegistrationCurrent(
    File file,
    String expectedContents,
  ) async {
    try {
      if (!await file.exists()) return false;
      return await file.readAsString() == expectedContents;
    } on FileSystemException {
      throw const StartupRegistrationException();
    }
  }

  Future<void> _setFileRegistration(
    File file,
    String contents,
    bool enabled,
  ) async {
    try {
      if (!enabled) {
        if (await file.exists()) await file.delete();
        return;
      }
      await file.parent.create(recursive: true);
      await file.writeAsString(contents, flush: true);
    } on FileSystemException {
      throw const StartupRegistrationException();
    }
  }

  Directory get _homeDirectory {
    final override = _homeDirectoryPath?.trim();
    if (override != null && override.isNotEmpty) {
      return Directory(_requireSafePath(override, 'homeDirectoryPath'));
    }
    final home = _environment['HOME']?.trim();
    if (home == null || home.isEmpty) {
      throw const StartupRegistrationException();
    }
    return Directory(_requireSafePath(home, 'HOME'));
  }

  String get _validatedExecutablePath {
    return _requireSafePath(_executablePath, 'executablePath');
  }

  void _ensureSupported() {
    if (!isSupported) {
      throw UnsupportedError('Desktop login startup is unavailable.');
    }
  }

  static DesktopStartupPlatform _currentPlatform() {
    if (Platform.isWindows) return DesktopStartupPlatform.windows;
    if (Platform.isMacOS) return DesktopStartupPlatform.macos;
    if (Platform.isLinux) return DesktopStartupPlatform.linux;
    return DesktopStartupPlatform.unsupported;
  }

  static Future<ProcessResult> _runProcess(
    String executable,
    List<String> arguments,
  ) {
    return Process.run(executable, arguments);
  }
}

String startupCommandForExecutable(
  String executablePath, {
  required String loginStartupArgument,
}) {
  final path = _requireSafePath(executablePath, 'executablePath');
  final argument = loginStartupArgument.trim();
  if (path.contains('"') ||
      argument.isEmpty ||
      argument.contains(RegExp(r'[\s"]'))) {
    throw ArgumentError.value(executablePath, 'executablePath');
  }
  return '"$path" $argument';
}

String desktopEntryQuoteArgument(String value) {
  var escaped = _requireSafePath(value, 'argument');
  escaped = escaped.replaceAll('\\', r'\\');
  escaped = escaped.replaceAll('"', r'\"');
  escaped = escaped.replaceAll(r'$', r'\$');
  escaped = escaped.replaceAll('`', r'\`');
  return '"$escaped"';
}

String xmlEscape(String value) {
  var escaped = value.replaceAll('&', '&amp;');
  escaped = escaped.replaceAll('<', '&lt;');
  escaped = escaped.replaceAll('>', '&gt;');
  escaped = escaped.replaceAll('"', '&quot;');
  escaped = escaped.replaceAll("'", '&apos;');
  return escaped;
}

String _requireSafePath(String value, String argumentName) {
  final path = value.trim();
  if (path.isEmpty ||
      path.contains('\u0000') ||
      path.contains('\n') ||
      path.contains('\r')) {
    throw ArgumentError.value(value, argumentName);
  }
  return path;
}

bool isLoginStartupInvocation(Iterable<String> executableArguments) {
  return executableArguments.contains(loginStartupArgument);
}

bool shouldConnectAfterLoginStartup({
  required bool wasLaunchedAtLogin,
  required bool hasValidSession,
  required bool onboardingComplete,
  required bool canActAsLocalVpnNode,
}) {
  if (!wasLaunchedAtLogin) return false;
  if (!hasValidSession) return false;
  if (!onboardingComplete) return false;
  if (!canActAsLocalVpnNode) return false;
  return true;
}

class StartupRegistrationException implements Exception {
  const StartupRegistrationException();
}
