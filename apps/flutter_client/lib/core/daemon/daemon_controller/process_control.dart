part of '../daemon_controller.dart';

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
      await file.writeAsString('$pid');
    } catch (_) {
      // Best-effort only; stop() can still recover by diagnostics process id.
    }
  }
}
