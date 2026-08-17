// Secure credential storage boundary.
//
// The auth token must never live in the shared settings JSON (which is
// non-credentials config that can be backed up, shipped in support bundles,
// or read by other local processes), and it must not be passed to the daemon
// on the process command line. `SecureTokenRepository` isolates that storage
// behind an interface so:
//   - production uses a permission-protected, owner-only store;
//   - tests inject an in-memory implementation;
//   - business code never knows the concrete platform mechanism.
//
// The default file-backed implementation stores the token in a single
// 0600 owner-only file (the same permission model the daemon's existing
// `--token-file` already requires and trusts). On platforms with a native
// secret store (Keychain / DPAPI-CredentialManager / Secret Service /
// Android Keystore) a dedicated implementation can be substituted without
// changing any caller.

import 'dart:io';

abstract interface class SecureTokenRepository {
  /// Read the stored token, or `null` when none is stored.
  Future<String?> read();

  /// Persist [token] (trimmed). Replaces any prior value.
  Future<void> write(String token);

  /// Remove the stored token, if any.
  Future<void> clear();
}

/// Best-effort owner-only (0600) permission on POSIX. No-op on Windows
/// (owner-only ACLs are a different mechanism). Mirrors the existing
/// platform-shell pattern used elsewhere (e.g. `scutil` on macOS).
Future<void> tryRestrictOwnerOnly(File file) async {
  if (Platform.isWindows) return;
  try {
    await Process.run('chmod', [
      '600',
      file.path,
    ]).timeout(const Duration(seconds: 2));
  } catch (_) {
    // Best-effort hardening only; never block the credential write.
  }
}

/// In-memory implementation for tests.
class InMemorySecureTokenRepository implements SecureTokenRepository {
  String? _token;

  @override
  Future<String?> read() async => _token;

  @override
  Future<void> write(String token) async {
    final trimmed = token.trim();
    _token = trimmed.isEmpty ? null : trimmed;
  }

  @override
  Future<void> clear() async => _token = null;
}

/// File-backed owner-only store. The file is created 0600 (owner read/write)
/// so no other local user can read the token.
class FileSecureTokenRepository implements SecureTokenRepository {
  FileSecureTokenRepository(this._file);

  final File _file;

  @override
  Future<String?> read() async {
    if (!await _file.exists()) return null;
    final value = (await _file.readAsString()).trim();
    return value.isEmpty ? null : value;
  }

  @override
  Future<void> write(String token) async {
    final trimmed = token.trim();
    if (trimmed.isEmpty) {
      await clear();
      return;
    }
    await _file.parent.create(recursive: true);
    // Write to a temp file then atomically rename, so an interrupted write can
    // never leave a truncated token that is silently "present".
    final temp = File('${_file.path}.tmp');
    await temp.writeAsString(trimmed, flush: true);
    await tryRestrictOwnerOnly(temp);
    try {
      await temp.rename(_file.path);
    } catch (_) {
      // Cross-device or already-exists rename failure: fall back to a direct
      // write, then remove the temp.
      await _file.writeAsString(trimmed, flush: true);
      await tryRestrictOwnerOnly(_file);
      if (await temp.exists()) await temp.delete();
    }
  }

  @override
  Future<void> clear() async {
    if (await _file.exists()) {
      await _file.delete();
    }
    final temp = File('${_file.path}.tmp');
    if (await temp.exists()) {
      await temp.delete();
    }
  }
}
