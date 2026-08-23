part of '../daemon_controller.dart';

/// Best-effort launcher diagnostics for the Windows-only GUI -> UAC -> daemon
/// chain.  This file deliberately contains stage names and redacted identity
/// facts only; it never receives the daemon argument list or auth token.
class WindowsStartupTrace {
  WindowsStartupTrace(
    this.logDir, {
    this.clientBuild = ClientBuildInfo.current,
  });

  static const fileName = 'p2wlan-client.log';

  final Directory logDir;
  final ClientBuildInfo clientBuild;

  File get file => File('${logDir.path}${Platform.pathSeparator}$fileName');

  String get path => file.path;

  Future<void> open() async {
    try {
      await logDir.create(recursive: true);
      final previous = File('${file.path}.1');
      if (await previous.exists()) await previous.delete();
      if (await file.exists()) await file.rename(previous.path);
      await file.writeAsString('', flush: true);
    } catch (_) {
      // Client logging must never prevent a UAC attempt.  Every subsequent
      // write also remains best effort for the same reason.
    }
  }

  Future<void> startRequested() async {
    await _write('start requested');
    await _write(
      'client build identity app_version=${clientBuild.appVersion} '
      'git_commit=${clientBuild.gitCommit} build_id=${clientBuild.buildId} '
      'dirty=${clientBuild.dirtyLabel} diff_hash=${clientBuild.diffHash} '
      'profile=${clientBuild.profile}',
    );
  }

  Future<void> detail(String message) => _write(message);

  Future<void> stageStart(int number, String name) =>
      _write('${_stage(number)} $name START');

  Future<void> stageOk(int number, String name) =>
      _write('${_stage(number)} $name OK');

  Future<void> stageAccepted(int number, String name) =>
      _write('${_stage(number)} $name ACCEPTED');

  Future<void> stageSkipped(int number, String name) =>
      _write('${_stage(number)} $name SKIPPED');

  Future<void> childPid(int pid) => _write('${_stage(9)} child_pid PID=$pid');

  Future<void> daemonAlive() => _write('${_stage(10)} daemon_alive OK');

  Future<void> failure(int stage, String code) =>
      _write('FAIL stage=${stage.toString().padLeft(2, '0')} code=$code');

  String _stage(int number) =>
      '[windows-startup] ${number.toString().padLeft(2, '0')}';

  Future<void> _write(String message) async {
    final sanitized = message.replaceAll(RegExp(r'[\r\n]+'), ' ').trim();
    if (sanitized.isEmpty) return;
    final prefix = sanitized.startsWith('[windows-startup]')
        ? ''
        : '[windows-startup] ';
    try {
      await logDir.create(recursive: true);
      await file.writeAsString(
        '${DateTime.now().toIso8601String()} $prefix$sanitized\n',
        mode: FileMode.append,
        flush: true,
      );
    } catch (_) {}
  }
}
