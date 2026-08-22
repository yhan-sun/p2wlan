part of '../daemon_controller.dart';

extension DaemonControllerLaunchToken on DaemonController {
  static final _launchTokenName = RegExp(r'^p2wlan-launch-[0-9a-f]+\.token$');

  /// Create a one-shot launch credential in the user-private runtime dir.
  Future<File> createEphemeralLaunchTokenFile(
    Directory runtimeDir,
    String token,
  ) async {
    await protectRuntimeDirectory(runtimeDir);
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

  Future<void> protectRuntimeDirectory(Directory runtimeDir) async {
    await runtimeDir.create(recursive: true);
    await _restrictLaunchPath(runtimeDir.path, directory: true);
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
      try {
        final modified = await entity.lastModified();
        if (now.difference(modified) > const Duration(minutes: 10)) {
          await entity.delete();
        }
      } catch (_) {
        // A stale token may have been created by a prior elevated Windows
        // instance. It must not prevent the next launch from reaching UAC;
        // the protected runtime directory will be reused and the new token
        // gets a fresh random name.
      }
    }
  }

  Future<void> _restrictLaunchPath(
    String path, {
    bool directory = false,
  }) async {
    if (Platform.isWindows) {
      // Use SIDs rather than USERNAME/domain strings: a UAC prompt can be
      // completed with another administrator account, and name resolution is
      // locale/domain dependent. Include the local Administrators group so an
      // alternate UAC account can consume the one-shot token. It is deleted
      // immediately after startup and is never a credential store.
      final quotedPath = _powershellSingleQuoted(path);
      final result = await _runWindowsPowerShell(
        '\$acl = Get-Acl -LiteralPath $quotedPath; '
        // Remove inherited and pre-existing explicit ACEs first.  `/grant:r`
        // alone only replaces grants for the two named SIDs and can leave a
        // stale explicit Everyone/Users entry behind on a directory created
        // by an older build.
        '\$acl.SetAccessRuleProtection(\$true, \$false); '
        'foreach (\$rule in @(\$acl.Access)) { '
        '[void]\$acl.RemoveAccessRuleSpecific(\$rule) }; '
        '\$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User; '
        '\$adminSid = [System.Security.Principal.SecurityIdentifier]::new(\'S-1-5-32-544\'); '
        '\$rights = [System.Security.AccessControl.FileSystemRights]::FullControl; '
        '\$inheritance = [System.Security.AccessControl.InheritanceFlags]::None; '
        'if (\'$directory\' -eq \'True\') { '
        '\$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor '
        '[System.Security.AccessControl.InheritanceFlags]::ObjectInherit }; '
        '\$propagation = [System.Security.AccessControl.PropagationFlags]::None; '
        '\$allow = [System.Security.AccessControl.AccessControlType]::Allow; '
        '\$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(\$currentSid, \$rights, \$inheritance, \$propagation, \$allow)); '
        '\$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(\$adminSid, \$rights, \$inheritance, \$propagation, \$allow)); '
        'Set-Acl -LiteralPath $quotedPath -AclObject \$acl',
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
