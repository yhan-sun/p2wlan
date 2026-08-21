// Local credential storage boundary.
//
// The auth token must never live in the shared settings JSON (which is
// non-credentials config that can be backed up, shipped in support bundles,
// or read by other local processes), and it must not be passed to the daemon
// on the process command line. `SecureTokenRepository` isolates that storage
// behind an interface so:
//   - production uses an app-local token file;
//   - tests inject an in-memory implementation;
//   - business code never knows the concrete platform mechanism.

import 'dart:io';

abstract interface class SecureTokenRepository {
  /// Read the stored token, or `null` when none is stored.
  Future<String?> read();

  /// Persist [token] (trimmed). Replaces any prior value.
  Future<void> write(String token);

  /// Remove the stored token, if any.
  Future<void> clear();
}

class SecureTokenStorageException implements Exception {
  const SecureTokenStorageException(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Production repository backed by an app-local file.
///
/// This intentionally does not use Keychain, Keystore, Secret Service, or
/// another OS credential broker: those services can show an interactive
/// system-password prompt on desktop. On POSIX systems the directory and file
/// are restricted to the current user (`0700`/`0600`). Windows app-data is
/// already scoped to the current user by the OS profile.
class LocalTokenRepository implements SecureTokenRepository {
  LocalTokenRepository({File? file}) : _fileOverride = file;

  static const _fileName = 'p2wlan-auth-token';
  final File? _fileOverride;

  File _tokenFile() {
    final override = _fileOverride;
    if (override != null) return override;

    return File('${_localDirectory().path}${Platform.pathSeparator}$_fileName');
  }

  Directory _localDirectory() {
    if (Platform.isMacOS || Platform.isIOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Application Support/p2wlan-client');
      }
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null && appData.isNotEmpty) {
        return Directory('$appData\\p2wlan');
      }
    }
    if (Platform.isLinux) {
      final xdg = Platform.environment['XDG_CONFIG_HOME'];
      if (xdg != null && xdg.isNotEmpty) {
        return Directory('$xdg/p2wlan');
      }
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/.config/p2wlan');
      }
    }

    // Android's and other sandboxed runtimes' temporary directory is inside
    // the application sandbox. It is a fallback only for platforms where a
    // stable per-user application-data environment variable is unavailable.
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan-client',
    );
  }

  Future<void> _restrictDirectory(Directory directory) async {
    // Mobile sandboxes already isolate their application files, and spawning
    // /bin/chmod is unavailable on iOS/Android. Desktop POSIX permissions are
    // applied explicitly below.
    if (!Platform.isMacOS && !Platform.isLinux) return;
    final result = await Process.run('/bin/chmod', ['700', directory.path]);
    if (result.exitCode != 0) {
      throw const SecureTokenStorageException('无法限制本地凭据目录权限，未能保存 P2WLAN 登录凭据。');
    }
  }

  Future<void> _restrictFile(File file) async {
    if (!Platform.isMacOS && !Platform.isLinux) return;
    final result = await Process.run('/bin/chmod', ['600', file.path]);
    if (result.exitCode != 0) {
      throw const SecureTokenStorageException('无法限制本地凭据文件权限，未能保存 P2WLAN 登录凭据。');
    }
  }

  @override
  Future<String?> read() async {
    try {
      final file = _tokenFile();
      if (!await file.exists()) return null;
      final value = await file.readAsString();
      final trimmed = value.trim();
      return trimmed.isEmpty ? null : trimmed;
    } catch (_) {
      throw const SecureTokenStorageException('本地凭据文件不可用，无法读取 P2WLAN 登录凭据。');
    }
  }

  @override
  Future<void> write(String token) async {
    final trimmed = token.trim();
    try {
      if (trimmed.isEmpty) {
        await clear();
      } else {
        final file = _tokenFile();
        await file.parent.create(recursive: true);
        await _restrictDirectory(file.parent);
        final temp = File(
          '${file.path}.${DateTime.now().microsecondsSinceEpoch}.tmp',
        );
        try {
          await temp.writeAsString(trimmed, flush: true);
          await _restrictFile(temp);
          try {
            await temp.rename(file.path);
          } on FileSystemException {
            // Windows cannot replace an existing file with rename on every
            // filesystem. The temporary file is already flushed and contains
            // only the token, so this narrow fallback remains recoverable.
            if (await file.exists()) await file.delete();
            await temp.rename(file.path);
          }
          await _restrictFile(file);
        } finally {
          if (await temp.exists()) await temp.delete();
        }
      }
    } catch (_) {
      throw const SecureTokenStorageException(
        '本地凭据文件不可用，未能保存 P2WLAN 登录凭据；原有配置保持不变。',
      );
    }
  }

  @override
  Future<void> clear() async {
    try {
      final file = _tokenFile();
      if (await file.exists()) await file.delete();
    } catch (_) {
      throw const SecureTokenStorageException('本地凭据文件不可用，未能删除 P2WLAN 登录凭据。');
    }
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
