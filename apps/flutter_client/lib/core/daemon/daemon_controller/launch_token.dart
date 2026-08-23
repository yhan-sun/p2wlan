part of '../daemon_controller.dart';

/// A failed Windows DACL write with redacted child-process diagnostics.
///
/// The launcher must distinguish ACL failures from token file failures: both
/// happen before UAC, but only the former means the runtime root itself is
/// unsafe. The raw helper output never leaves this object unredacted.
class WindowsAclProtectionException implements Exception {
  WindowsAclProtectionException({
    required this.directory,
    required this.exitCode,
    required String stdout,
    required String stderr,
  }) : stdout = _sanitizeProbeOutput(stdout),
       stderr = _sanitizeProbeOutput(stderr);

  final bool directory;
  final int exitCode;
  final String stdout;
  final String stderr;

  String get diagnostic =>
      'windows_acl target=${directory ? 'directory' : 'file'} '
      'exitCode=$exitCode '
      'stdout=$stdout '
      'stderr=$stderr';

  @override
  String toString() => 'Windows ACL protection failed: $diagnostic';
}

/// Windows launch-token failures are deliberately more specific than the
/// broad pre-UAC failure classifier. A token write remains a token failure;
/// only a DACL write is an ACL failure.
DaemonStartupFailureCode windowsLaunchTokenFailureCodeForError(Object error) {
  return error is WindowsAclProtectionException
      ? DaemonStartupFailureCode.aclFailure
      : DaemonStartupFailureCode.tokenAccessFailed;
}

extension DaemonControllerLaunchToken on DaemonController {
  static final _launchTokenName = RegExp(r'^p2wlan-launch-[0-9a-f]+\.token$');

  /// Create a one-shot launch credential in the user-private runtime dir.
  Future<File> createEphemeralLaunchTokenFile(
    Directory runtimeDir,
    String token,
  ) async {
    await protectRuntimeDirectory(runtimeDir);
    await cleanupStaleLaunchTokenFiles(runtimeDir);

    final file = await writeEphemeralLaunchTokenFile(runtimeDir, token);
    try {
      await protectEphemeralLaunchTokenFile(file);
      return file;
    } catch (_) {
      try {
        if (await file.exists()) await file.delete();
      } catch (_) {}
      rethrow;
    }
  }

  /// Write a token only after its containing runtime directory is protected.
  ///
  /// Windows startup uses this directly after stage 5 so it cannot rewrite the
  /// runtime directory ACL a second time.
  Future<File> writeEphemeralLaunchTokenFile(
    Directory runtimeDir,
    String token,
  ) async {
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
      return file;
    } catch (_) {
      try {
        if (await file.exists()) await file.delete();
      } catch (_) {}
      rethrow;
    }
  }

  /// Protect a token file after it has been written.
  Future<void> protectEphemeralLaunchTokenFile(File file) {
    return _restrictLaunchPath(file.path);
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
        '\$systemSid = [System.Security.Principal.SecurityIdentifier]::new(\'S-1-5-18\'); '
        '\$rights = [System.Security.AccessControl.FileSystemRights]::FullControl; '
        '\$inheritance = [System.Security.AccessControl.InheritanceFlags]::None; '
        'if (\'$directory\' -eq \'True\') { '
        '\$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor '
        '[System.Security.AccessControl.InheritanceFlags]::ObjectInherit }; '
        '\$propagation = [System.Security.AccessControl.PropagationFlags]::None; '
        '\$allow = [System.Security.AccessControl.AccessControlType]::Allow; '
        '\$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(\$currentSid, \$rights, \$inheritance, \$propagation, \$allow)); '
        '\$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(\$adminSid, \$rights, \$inheritance, \$propagation, \$allow)); '
        '\$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(\$systemSid, \$rights, \$inheritance, \$propagation, \$allow)); '
        'Set-Acl -LiteralPath $quotedPath -AclObject \$acl',
      );
      if (result.exitCode != 0) {
        throw WindowsAclProtectionException(
          directory: directory,
          exitCode: result.exitCode,
          stdout: result.stdout.toString(),
          stderr: result.stderr.toString(),
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
