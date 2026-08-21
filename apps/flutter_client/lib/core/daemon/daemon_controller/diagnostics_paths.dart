part of '../daemon_controller.dart';

extension DaemonControllerDiagnosticsPaths on DaemonController {
  Future<bool> _waitForHealth(
    String diagnosticsUrl,
    Duration timeout,
    String logPath,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      // Fast-fail path: the daemon was launched (possibly elevated) and then
      // exited.  Waiting out the full 60 s macOS readiness window would make
      // a dead daemon look like a "TUN is not ready" timeout.  As soon as the
      // recorded PID is gone (or the log shows a definitive failure), stop
      // polling and let the caller classify the reason from the log.
      if (await _daemonExitedAfterLaunch(logPath)) return false;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  /// Whether the daemon launched by this controller already exited.
  ///
  /// The PID marker written right after launch is authoritative for a
  /// just-started daemon; a marker whose PID is no longer running (or was
  /// never written because the elevated launcher died first) means the
  /// daemon is down.
  Future<bool> _daemonExitedAfterLaunch(String logPath) async {
    if (Platform.isWindows) {
      final lastProbeAt = _lastLaunchExitProbeAt;
      final lastProbeResult = _lastLaunchExitProbeResult;
      if (lastProbeAt != null &&
          lastProbeResult != null &&
          DateTime.now().difference(lastProbeAt) < const Duration(seconds: 2)) {
        return lastProbeResult;
      }
    }
    final pid = await _readVerifiedPid();
    final exited =
        pid == null && await _logShowsPermanentAuthFailure(logPath) == true;
    if (pid != null) {
      if (Platform.isWindows) {
        _lastLaunchExitProbeAt = DateTime.now();
        _lastLaunchExitProbeResult = false;
      }
      return false;
    }
    final logFile = File(logPath);
    final result =
        await logFile.exists() &&
        (exited || await _logShowsWintunMissing(logPath));
    if (Platform.isWindows) {
      _lastLaunchExitProbeAt = DateTime.now();
      _lastLaunchExitProbeResult = result;
    }
    return result;
  }

  /// Whether the daemon log tail carries a permanent control auth failure
  /// (expired token / revoked credential).  The daemon exits after a
  /// permanent 401/403 instead of retrying, so a fresh start with a stale
  /// token never reaches diagnostics readiness.
  Future<bool> _logShowsPermanentAuthFailure(String logPath) {
    return logTailShowsPermanentAuthFailure(logPath);
  }

  Future<bool> _logShowsWintunMissing(String logPath) {
    return logTailShowsWintunMissing(logPath);
  }

  Future<bool> _waitForHealthDown(
    String diagnosticsUrl,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return !await _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  String _diagnosticsBindFromStatusUrl(String diagnosticsUrl) {
    final parsed = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    final host = parsed.host.contains(':') ? '[${parsed.host}]' : parsed.host;
    return '$host:${parsed.port}';
  }

  File _defaultConfigPath() {
    final override = Platform.environment['P2WLAN_CONFIG'];
    if (override != null && override.trim().isNotEmpty) {
      return File(override.trim());
    }
    return File(
      '${_configBaseDir().path}${Platform.pathSeparator}p2wlan-config.json',
    );
  }

  Directory _configBaseDir() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Application Support/p2wlan');
      }
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null && appData.isNotEmpty) {
        return Directory('$appData\\p2wlan');
      }
    }
    final xdg = Platform.environment['XDG_CONFIG_HOME'];
    if (xdg != null && xdg.isNotEmpty) return Directory('$xdg/p2wlan');
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.config/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
  }

  Directory _defaultLogDir() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Logs/p2wlan');
      }
    }
    if (Platform.isWindows) {
      final localAppData = Platform.environment['LOCALAPPDATA'];
      if (localAppData != null && localAppData.isNotEmpty) {
        return Directory('$localAppData\\p2wlan\\logs');
      }
    }
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.local/state/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
  }
}

/// Whether the daemon log tail carries a permanent control auth failure
/// (expired token / revoked credential).  The daemon exits after a permanent
/// 401/403 instead of retrying, so a fresh start with a stale token never
/// reaches diagnostics readiness and the GUI must surface "登录已过期，请重新
/// 登录" instead of a generic TUN-start timeout.
///
/// Public for direct unit testing; the daemon-controller start flow uses it
/// to fast-fail (well under the 60 s macOS readiness window) when the
/// elevated launch produced a daemon that immediately exited.
Future<bool> logTailShowsPermanentAuthFailure(String logPath) async {
  final logFile = File(logPath);
  if (!await logFile.exists()) return false;
  try {
    final length = await logFile.length();
    final start = length > _authFailureScanBytes
        ? length - _authFailureScanBytes
        : 0;
    final contents = await logFile
        .openRead(start)
        .fold<String>(
          '',
          (buffer, chunk) => buffer + utf8.decode(chunk, allowMalformed: true),
        );
    final lower = contents.toLowerCase();
    return const [
      'permanent auth failure',
      're-authentication required',
      'register request returned http 401',
      'list nodes request returned http 401',
      'list signals returned http 401',
    ].any(lower.contains);
  } catch (_) {
    return false;
  }
}

/// Whether the Windows daemon exited because its side-by-side Wintun runtime
/// could not be loaded. This is kept separate from permission failures: UAC
/// elevation cannot fix a missing DLL, and the UI should say so directly.
Future<bool> logTailShowsWintunMissing(String logPath) async {
  final logFile = File(logPath);
  if (!await logFile.exists()) return false;
  try {
    final length = await logFile.length();
    final start = length > _authFailureScanBytes
        ? length - _authFailureScanBytes
        : 0;
    final contents = await logFile
        .openRead(start)
        .fold<String>(
          '',
          (buffer, chunk) => buffer + utf8.decode(chunk, allowMalformed: true),
        );
    final lower = contents.toLowerCase();
    return lower.contains('wintun.dll not found or not loadable');
  } catch (_) {
    return false;
  }
}

const _authFailureScanBytes = 128 * 1024;
