// Secure credential storage boundary.
//
// The auth token must never live in the shared settings JSON (which is
// non-credentials config that can be backed up, shipped in support bundles,
// or read by other local processes), and it must not be passed to the daemon
// on the process command line. `SecureTokenRepository` isolates that storage
// behind an interface so:
//   - production uses the OS secure store (Keychain/Keystore/DPAPI/Secret
//     Service through flutter_secure_storage);
//   - tests inject an in-memory implementation;
//   - business code never knows the concrete platform mechanism.

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

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

/// Production repository backed by the platform secure-storage plugin.
///
/// The plugin maps this boundary to Keychain (macOS/iOS), Keystore-backed
/// encryption (Android), DPAPI/Credential Locker (Windows), and Secret Service
/// (Linux). Errors are propagated: no plaintext-file fallback is permitted.
class PlatformSecureTokenRepository implements SecureTokenRepository {
  PlatformSecureTokenRepository({FlutterSecureStorage? storage})
    : _storage = storage ?? FlutterSecureStorage();

  static const _key = 'p2wlan.control.auth_token';
  final FlutterSecureStorage _storage;

  @override
  Future<String?> read() async {
    try {
      final value = await _storage.read(key: _key);
      final trimmed = value?.trim() ?? '';
      return trimmed.isEmpty ? null : trimmed;
    } catch (_) {
      throw const SecureTokenStorageException(
        '系统安全存储不可用，无法读取 P2WLAN 登录凭据。请启用系统 Keychain/Keystore/Secret Service 后重试。',
      );
    }
  }

  @override
  Future<void> write(String token) async {
    final trimmed = token.trim();
    try {
      if (trimmed.isEmpty) {
        await clear();
      } else {
        await _storage.write(key: _key, value: trimmed);
      }
    } catch (_) {
      throw const SecureTokenStorageException(
        '系统安全存储不可用，未能保存 P2WLAN 登录凭据；原有配置保持不变。',
      );
    }
  }

  @override
  Future<void> clear() async {
    try {
      await _storage.delete(key: _key);
    } catch (_) {
      throw const SecureTokenStorageException('系统安全存储不可用，未能删除 P2WLAN 登录凭据。');
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
