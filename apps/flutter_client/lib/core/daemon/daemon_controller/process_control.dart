part of '../daemon_controller.dart';

/// Keep the current daemon log plus one previous startup log.  The caller
/// must invoke this after the previous daemon has stopped and before creating
/// the new current log.
Future<void> rotateP2wlanLogFiles(File currentLog) async {
  if (!await currentLog.exists()) return;

  final previousLog = File('${currentLog.path}.1');
  if (await previousLog.exists()) await previousLog.delete();
  await currentLog.rename(previousLog.path);
}

extension DaemonControllerProcessControl on DaemonController {
  bool get _supportsProcessControl {
    return Platform.isMacOS || Platform.isLinux || Platform.isWindows;
  }

  Future<File?> _resolveDaemonBinary() async {
    final envPath = Platform.environment[DaemonController.envDaemonBin];
    if (envPath != null && envPath.trim().isNotEmpty) {
      final file = File(envPath.trim());
      if (await file.exists()) return file;
    }

    final names = _binaryNames;
    final candidates = <File>[];
    final executable = File(Platform.resolvedExecutable);
    final exeDir = executable.parent;
    for (final name in names) {
      candidates.add(File('${exeDir.path}${Platform.pathSeparator}$name'));
      final contents = exeDir.parent;
      candidates.add(
        File(
          '${contents.path}${Platform.pathSeparator}Resources${Platform.pathSeparator}$name',
        ),
      );
    }

    var dir = Directory.current;
    for (var depth = 0; depth < 6; depth += 1) {
      for (final name in names) {
        candidates.add(
          File('${dir.path}${Platform.pathSeparator}target/debug/$name'),
        );
        candidates.add(
          File('${dir.path}${Platform.pathSeparator}target/release/$name'),
        );
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }

    for (final candidate in candidates) {
      if (await candidate.exists()) return candidate;
    }

    for (final name in names) {
      final found = await _which(name);
      if (found != null) return found;
    }
    return null;
  }

  /// Load the Windows daemon in its side-effect-free identity mode before
  /// asking UAC to start the real instance. Start-Process -Verb RunAs can
  /// report success even when Windows immediately rejects a missing DLL, so
  /// without this probe the UI waits for the health timeout and only shows a
  /// misleading generic permission error.
  Future<DaemonBinaryProbe> _probeWindowsDaemonBinary(File binary) async {
    if (!Platform.isWindows) return const DaemonBinaryProbe();
    return probeDaemonBinary(binary);
  }

  List<String> get _binaryNames {
    final extension = Platform.isWindows ? '.exe' : '';
    return ['${DaemonController.daemonBinaryName}$extension'];
  }

  Future<File?> _which(String name) async {
    final executable = Platform.isWindows ? 'where' : 'which';
    final result = await Process.run(executable, [name]);
    if (result.exitCode != 0) return null;
    final first = result.stdout.toString().split('\n').first.trim();
    if (first.isEmpty) return null;
    final file = File(first);
    return file.existsSync() ? file : null;
  }

  Future<Process> _startDetached({
    required File binary,
    required List<String> args,
    String? stdinToken,
  }) async {
    final process = await Process.start(
      binary.path,
      args,
      mode: stdinToken == null
          ? ProcessStartMode.detached
          : ProcessStartMode.detachedWithStdio,
      environment: {'P2WLAN_DAEMON_BIN': binary.path},
    );
    if (stdinToken != null) {
      process.stdin.write('$stdinToken\n');
      await process.stdin.close();
      unawaited(process.stdout.drain<void>());
      unawaited(process.stderr.drain<void>());
    }
    return process;
  }

  Future<void> _writePidMarker(String pidPath, int pid) async {
    try {
      final file = File(pidPath);
      await file.parent.create(recursive: true);
      await file.writeAsString('$pid', flush: true);
      final recordedPid = int.tryParse((await file.readAsString()).trim());
      if (recordedPid != pid) {
        throw StateError(
          'PID_MARKER_FAILED: canonical PID marker read back as $recordedPid, expected $pid',
        );
      }
      if (Platform.isWindows) await _restrictLaunchPath(pidPath);
    } catch (error) {
      if (Platform.isWindows) {
        throw StateError('PID_MARKER_FAILED: could not write $pidPath: $error');
      }
      // Best-effort only; stop() can still recover by diagnostics process id.
    }
  }
}

const _daemonBinaryProbeTimeout = Duration(seconds: 6);

/// Execute a daemon identity probe as a normal, short-lived child process.
///
/// This is intentionally separate from the detached process used for the
/// actual daemon launch. A detached process has no awaitable exit code in
/// dart:io, while this probe must consume stdout, stderr, and exitCode before
/// deciding whether the binary is executable.
Future<DaemonBinaryProbe> probeDaemonBinary(
  File binary, {
  List<String> arguments = const ['--build-info'],
  Duration timeout = _daemonBinaryProbeTimeout,
}) async {
  Process? process;
  try {
    process = await Process.start(
      binary.path,
      arguments,
      workingDirectory: binary.parent.path,
      mode: ProcessStartMode.normal,
    );

    final stdoutFuture = process.stdout
        .transform(systemEncoding.decoder)
        .join();
    final stderrFuture = process.stderr
        .transform(systemEncoding.decoder)
        .join();
    final exitCodeFuture = process.exitCode;

    final values = await Future.wait<Object>([
      stdoutFuture,
      stderrFuture,
      exitCodeFuture,
    ]).timeout(timeout);
    final stdout = values[0] as String;
    final stderr = values[1] as String;
    final exitCode = values[2] as int;

    if (exitCode == 0) {
      try {
        final decoded = jsonDecode(stdout.trim());
        if (decoded is Map<String, dynamic>) {
          final identity = DaemonBuildInfo.fromJson(decoded);
          if (identity.isComplete) {
            return DaemonBinaryProbe(identity: identity);
          }
        }
      } catch (_) {}
      return _daemonBinaryProbeFailure(
        'daemon --build-info did not return a complete JSON identity; '
        'stdout=${_sanitizeProbeOutput(stdout)}; '
        'stderr=${_sanitizeProbeOutput(stderr)}',
      );
    }

    return _daemonBinaryProbeFailure(
      'daemon identity probe exited with code $exitCode; '
      'stdout=${_sanitizeProbeOutput(stdout)}; '
      'stderr=${_sanitizeProbeOutput(stderr)}',
    );
  } on TimeoutException {
    try {
      process?.kill();
    } catch (_) {}
    return _daemonBinaryProbeFailure(
      'daemon identity probe timed out after '
      '${timeout.inMilliseconds} milliseconds',
    );
  } on Object catch (error) {
    return _daemonBinaryProbeFailure(_sanitizeProbeOutput(error.toString()));
  }
}

String _sanitizeProbeOutput(String value) {
  final compact = redactSensitive(
    value,
  ).replaceAll(RegExp(r'[\r\n]+'), ' ').trim();
  if (compact.isEmpty) return '<empty>';
  const maxLength = 2048;
  if (compact.length <= maxLength) return compact;
  return '${compact.substring(0, maxLength)}…';
}

DaemonBinaryProbe _daemonBinaryProbeFailure(String error) {
  return DaemonBinaryProbe(
    error: error,
    failureCode: DaemonStartupFailureCode.daemonBinaryLoadFailed,
  );
}

class DaemonBinaryProbe {
  const DaemonBinaryProbe({this.identity, this.error, this.failureCode});

  final DaemonBuildInfo? identity;
  final String? error;
  final DaemonStartupFailureCode? failureCode;
}
