part of '../daemon_controller.dart';

extension DaemonControllerLaunchToken on DaemonController {
  static final _launchTokenName = RegExp(r'^p2wlan-launch-[0-9a-f]+\.token$');

  /// Create a one-shot launch credential in the user-private runtime dir.
  Future<File> createEphemeralLaunchTokenFile(
    Directory runtimeDir,
    String token,
  ) async {
    await runtimeDir.create(recursive: true);
    await _restrictLaunchPath(runtimeDir.path, directory: true);
    await cleanupStaleLaunchTokenFiles(runtimeDir);

    final random = math.Random.secure();
    final suffix = List.generate(
      16,
      (_) => random.nextInt(16).toRadixString(16),
    ).join();
    final file = File(
      '${runtimeDir.path}${Platform.pathSeparator}p2wlan-launch-$suffix.token',
    );
    try {
      await file.writeAsString(token, flush: true);
      await _restrictLaunchPath(file.path);
      return file;
    } catch (_) {
      try {
        if (await file.exists()) await file.delete();
      } catch (_) {}
      rethrow;
    }
  }

  Future<void> deleteEphemeralLaunchTokenFile(File? file) async {
    if (file == null) return;
    if (await file.exists()) await file.delete();
  }

  Future<void> cleanupStaleLaunchTokenFiles(Directory runtimeDir) async {
    if (!await runtimeDir.exists()) return;
    final now = DateTime.now();
    await for (final entity in runtimeDir.list(followLinks: false)) {
      if (entity is! File) continue;
      final name = entity.uri.pathSegments.last;
      if (!_launchTokenName.hasMatch(name)) continue;
      final modified = await entity.lastModified();
      if (now.difference(modified) > const Duration(minutes: 10)) {
        await entity.delete();
      }
    }
  }

  Future<void> _restrictLaunchPath(
    String path, {
    bool directory = false,
  }) async {
    if (Platform.isWindows) {
      // Resolve the account from the Windows security token instead of the
      // USERNAME environment variable. The latter can differ after UAC
      // elevation (and is not reliable for domain/Microsoft accounts). Run
      // icacls through the shared hidden PowerShell helper so ACL repair does
      // not flash a console window in the GUI app.
      final quotedPath = _powershellSingleQuoted(path);
      final result = await _runWindowsPowerShell(
        '\$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name; '
        '& icacls.exe $quotedPath /inheritance:r /grant:r (\$account + \':F\'); '
        '\$global:LASTEXITCODE = \$LASTEXITCODE',
      );
      if (result.exitCode != 0) {
        throw StateError(
          'Windows ACL protection failed for the launch ${directory ? 'directory' : 'file'}',
        );
      }
      return;
    }

    final result = await Process.run('chmod', [
      directory ? '700' : '600',
      path,
    ]);
    if (result.exitCode != 0) {
      throw StateError(
        'POSIX permissions could not protect the launch ${directory ? 'directory' : 'file'}',
      );
    }
  }
}
