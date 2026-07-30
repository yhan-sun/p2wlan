import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../state/settings_store.dart';

enum AuthMode { login, register }

class AuthSession {
  const AuthSession({
    required this.token,
    required this.controlServer,
    this.user,
  });

  final String token;
  final String controlServer;
  final Map<String, dynamic>? user;
}

class ControlApi {
  ControlApi({HttpClient? client}) : _client = client ?? HttpClient();

  final HttpClient _client;

  Future<AuthSession> authenticate({
    required AuthMode mode,
    required String controlServer,
    required String email,
    required String password,
  }) async {
    final normalizedControlServer = normalizeControlServer(controlServer);
    final normalizedEmail = email.trim().toLowerCase();
    if (normalizedEmail.isEmpty) {
      throw const ControlApiException('请输入邮箱');
    }
    if (password.length < 6) {
      throw const ControlApiException('密码至少需要 6 个字符');
    }
    final endpoint = Uri.parse(
      '$normalizedControlServer/api/v1/${mode == AuthMode.register ? 'register' : 'login'}',
    );
    final body = await _sendJson(
      method: 'POST',
      uri: endpoint,
      payload: {'email': normalizedEmail, 'password': password},
    );
    final token = body['token']?.toString() ?? '';
    if (token.isEmpty || body['success'] == false) {
      throw ControlApiException(_zhAuthError(body['error']?.toString()));
    }
    return AuthSession(
      token: token,
      controlServer: normalizedControlServer,
      user: body['user'] is Map
          ? Map<String, dynamic>.from(body['user'] as Map)
          : null,
    );
  }

  Future<String> renameDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
    required String deviceName,
  }) async {
    final name = deviceName.trim();
    if (name.isEmpty) {
      throw const ControlApiException('设备名称不能为空');
    }
    if (name.runes.length > 128) {
      throw const ControlApiException('设备名称不能超过 128 个字符');
    }
    if (authToken.trim().isEmpty) {
      throw const ControlApiException('登录状态已失效，请重新登录');
    }
    final endpoint = Uri.parse(
      '${normalizeControlServer(controlServer)}/api/v1/devices/${Uri.encodeComponent(deviceId)}',
    );
    final body = await _sendJson(
      method: 'PATCH',
      uri: endpoint,
      payload: {'device_name': name},
      authToken: authToken,
    );
    if (body['success'] == false) {
      throw ControlApiException(
        _zhAuthError(body['error']?.toString() ?? '设备名称保存失败'),
      );
    }
    return body['device_name']?.toString() ?? name;
  }

  Future<Map<String, dynamic>> _sendJson({
    required String method,
    required Uri uri,
    required Map<String, dynamic> payload,
    String? authToken,
  }) async {
    final request = await _client
        .openUrl(method, uri)
        .timeout(const Duration(seconds: 8));
    request.headers.contentType = ContentType.json;
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (authToken != null && authToken.trim().isNotEmpty) {
      request.headers.set(
        HttpHeaders.authorizationHeader,
        'Bearer ${authToken.trim()}',
      );
    }
    request.write(jsonEncode(payload));
    final response = await request.close().timeout(const Duration(seconds: 8));
    final text = await utf8.decodeStream(response);
    final decoded = text.trim().isEmpty
        ? <String, dynamic>{}
        : jsonDecode(text);
    final Map<String, dynamic> body = decoded is Map
        ? Map<String, dynamic>.from(decoded)
        : <String, dynamic>{};
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ControlApiException(
        _zhAuthError(body['error']?.toString(), response.statusCode),
      );
    }
    return body;
  }

  void close() {
    _client.close(force: true);
  }
}

class ControlApiException implements Exception {
  const ControlApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

String _zhAuthError(String? message, [int? statusCode]) {
  final raw = message?.trim() ?? '';
  final normalized = raw.toLowerCase();
  if (statusCode == 401) return '认证失败，请检查邮箱和密码';
  if (statusCode == 403) return '当前账号没有权限执行该操作';
  if (statusCode == 404) return '控制服务器暂不支持该接口，请先更新服务端';
  if (statusCode == 409) return '账号已存在';
  if (normalized.contains('invalid credentials')) return '邮箱或密码错误';
  if (normalized.contains('invalid email')) return '邮箱格式不正确';
  if (normalized.contains('invalid password')) return '密码不符合要求，至少需要 6 个字符';
  if (normalized.contains('registration failed')) return '注册失败，邮箱可能已存在';
  if (normalized.contains('rate limit')) return '请求过于频繁，请稍后再试';
  return raw.isEmpty ? '控制服务器请求失败' : raw;
}
