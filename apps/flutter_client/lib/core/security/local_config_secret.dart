import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

/// A small authenticated local-file secret store.
///
/// The encrypted value is kept in the JSON settings file. Its random 256-bit
/// key lives in a sibling file with user-only permissions, so copying the JSON
/// alone does not disclose the password. This deliberately does not call
/// Keychain, Keystore, Secret Service, or any other system credential broker.
///
/// This protects the value at rest from normal file browsing and from a
/// settings-file backup that omits the sidecar key. A process already running
/// as the same user can still read both files; no config-file-only design can
/// defend against that without asking for another secret at runtime.
class LocalConfigSecret {
  LocalConfigSecret._();

  static const _prefix = 'p2wlan-config-v1:';
  static const _keyLength = 32;
  static const _nonceLength = 16;
  static const _tagLength = 32;

  static Future<String> encrypt(
    String plaintext, {
    required File keyFile,
  }) async {
    if (plaintext.isEmpty) return '';
    final key = await _loadOrCreateKey(keyFile);
    final nonce = List<int>.generate(
      _nonceLength,
      (_) => Random.secure().nextInt(256),
    );
    final clearBytes = utf8.encode(plaintext);
    final ciphertext = _xor(clearBytes, _stream(key, nonce, clearBytes.length));
    final tag = _tag(key, nonce, ciphertext);
    return '$_prefix${base64Url.encode(<int>[...nonce, ...ciphertext, ...tag])}';
  }

  static Future<String> decrypt(String encoded, {required File keyFile}) async {
    if (encoded.isEmpty) return '';
    if (!encoded.startsWith(_prefix)) {
      throw const FormatException('未知的本地管理员密码格式。');
    }

    final key = await _readExistingKey(keyFile);
    final payload = base64Url.decode(
      base64Url.normalize(encoded.substring(_prefix.length)),
    );
    if (payload.length < _nonceLength + _tagLength) {
      throw const FormatException('本地管理员密码密文不完整。');
    }

    final nonce = payload.sublist(0, _nonceLength);
    final tagStart = payload.length - _tagLength;
    final ciphertext = payload.sublist(_nonceLength, tagStart);
    final tag = payload.sublist(tagStart);
    if (!_constantTimeEquals(tag, _tag(key, nonce, ciphertext))) {
      throw const FormatException('本地管理员密码密文校验失败。');
    }

    try {
      return utf8.decode(
        _xor(ciphertext, _stream(key, nonce, ciphertext.length)),
      );
    } on FormatException {
      throw const FormatException('本地管理员密码密文无法解码。');
    }
  }

  static Future<List<int>> _readExistingKey(File keyFile) async {
    if (!await keyFile.exists()) {
      throw const FormatException('本地管理员密码密钥文件不存在。');
    }
    try {
      final bytes = base64Url.decode(
        base64Url.normalize((await keyFile.readAsString()).trim()),
      );
      if (bytes.length != _keyLength) {
        throw const FormatException('本地管理员密码密钥长度无效。');
      }
      await _restrictFile(keyFile);
      return bytes;
    } on FormatException {
      rethrow;
    } catch (_) {
      throw const FormatException('本地管理员密码密钥文件不可用。');
    }
  }

  static Future<List<int>> _loadOrCreateKey(File keyFile) async {
    if (await keyFile.exists()) return _readExistingKey(keyFile);

    final key = List<int>.generate(
      _keyLength,
      (_) => Random.secure().nextInt(256),
    );
    try {
      await keyFile.parent.create(recursive: true);
      await _restrictDirectory(keyFile.parent);
      final temp = File(
        '${keyFile.path}.${DateTime.now().microsecondsSinceEpoch}.tmp',
      );
      try {
        await temp.writeAsString(base64Url.encode(key), flush: true);
        await _restrictFile(temp);
        try {
          await temp.rename(keyFile.path);
        } on FileSystemException {
          if (await keyFile.exists()) await keyFile.delete();
          await temp.rename(keyFile.path);
        }
        await _restrictFile(keyFile);
      } finally {
        if (await temp.exists()) await temp.delete();
      }
      return key;
    } catch (_) {
      throw const FormatException('无法创建本地管理员密码密钥文件。');
    }
  }

  static List<int> _stream(List<int> key, List<int> nonce, int length) {
    final result = <int>[];
    var counter = 0;
    while (result.length < length) {
      final block = Hmac(sha256, key).convert(<int>[
        ...utf8.encode('p2wlan-config-stream-v1'),
        ...nonce,
        ..._counter(counter),
      ]).bytes;
      result.addAll(block);
      counter++;
    }
    return result.sublist(0, length);
  }

  static List<int> _tag(List<int> key, List<int> nonce, List<int> ciphertext) {
    return Hmac(sha256, key).convert(<int>[
      ...utf8.encode('p2wlan-config-tag-v1'),
      ...nonce,
      ...ciphertext,
    ]).bytes;
  }

  static List<int> _counter(int value) => <int>[
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ];

  static List<int> _xor(List<int> left, List<int> right) => [
    for (var index = 0; index < left.length; index++)
      left[index] ^ right[index],
  ];

  static bool _constantTimeEquals(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }

  static Future<void> _restrictDirectory(Directory directory) async {
    if (!Platform.isMacOS && !Platform.isLinux) return;
    final result = await Process.run('/bin/chmod', ['700', directory.path]);
    if (result.exitCode != 0) {
      throw const FormatException('无法限制本地配置目录权限。');
    }
  }

  static Future<void> _restrictFile(File file) async {
    if (!Platform.isMacOS && !Platform.isLinux) return;
    final result = await Process.run('/bin/chmod', ['600', file.path]);
    if (result.exitCode != 0) {
      throw const FormatException('无法限制本地配置密钥文件权限。');
    }
  }
}
