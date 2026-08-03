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

class DeviceUpdateResult {
  const DeviceUpdateResult({required this.deviceName, required this.virtualIp});

  final String deviceName;
  final String virtualIp;
}

class ControlApi {
  ControlApi({HttpClient? client}) : _client = client ?? HttpClient() {
    _client.connectionTimeout = const Duration(seconds: 8);
  }

  final HttpClient _client;

  Future<AuthSession> authenticate({
    required AuthMode mode,
    required String controlServer,
    required String email,
    required String password,
  }) async {
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
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
    final result = await updateDevice(
      controlServer: controlServer,
      authToken: authToken,
      deviceId: deviceId,
      deviceName: deviceName,
    );
    return result.deviceName;
  }

  Future<DeviceUpdateResult> updateDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
    String? deviceName,
    String? virtualIp,
  }) async {
    final name = deviceName?.trim() ?? '';
    final ip = virtualIp?.trim() ?? '';
    if (name.isEmpty && ip.isEmpty) {
      throw const ControlApiException('设备名称或虚拟 IP 至少需要填写一项');
    }
    if (ip.isNotEmpty &&
        InternetAddress.tryParse(ip)?.type != InternetAddressType.IPv4) {
      throw const ControlApiException('虚拟 IP 格式不正确，例如 10.20.0.42');
    }
    if (deviceId.trim().isEmpty) {
      throw const ControlApiException('设备标识不能为空');
    }
    if (name.isNotEmpty && name.runes.length > 128) {
      throw const ControlApiException('设备名称不能超过 128 个字符');
    }
    if (ip.length > 64) {
      throw const ControlApiException('虚拟 IP 不能超过 64 个字符');
    }
    if (authToken.trim().isEmpty) {
      throw const ControlApiException('登录状态已失效，请重新登录');
    }
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
    final endpoint = Uri.parse(
      '$normalizedControlServer/api/v1/devices/${Uri.encodeComponent(deviceId)}',
    );
    final body = await _sendJson(
      method: 'PATCH',
      uri: endpoint,
      payload: {
        if (name.isNotEmpty) 'device_name': name,
        if (ip.isNotEmpty) 'virtual_ip': ip,
      },
      authToken: authToken,
      unauthorizedMessage: '登录状态已过期或无权修改该设备，请重新登录后再试',
    );
    if (body['success'] == false) {
      throw ControlApiException(
        _zhAuthError(body['error']?.toString() ?? '设备名称保存失败'),
      );
    }
    final device = body['device'] is Map
        ? Map<String, dynamic>.from(body['device'] as Map)
        : const <String, dynamic>{};
    return DeviceUpdateResult(
      deviceName:
          body['device_name']?.toString() ??
          device['device_name']?.toString() ??
          name,
      virtualIp:
          body['virtual_ip']?.toString() ??
          device['virtual_ip']?.toString() ??
          ip,
    );
  }

  Future<void> deleteDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
  }) async {
    final id = deviceId.trim();
    if (id.isEmpty) {
      throw const ControlApiException('设备标识不能为空');
    }
    if (authToken.trim().isEmpty) {
      throw const ControlApiException('登录状态已失效，请重新登录');
    }
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
    final endpoint = Uri.parse(
      '$normalizedControlServer/api/v1/devices/${Uri.encodeComponent(id)}',
    );
    final body = await _sendJson(
      method: 'DELETE',
      uri: endpoint,
      authToken: authToken,
      unauthorizedMessage: '登录状态已过期或无权移除该设备，请重新登录后再试',
    );
    if (body['success'] == false) {
      throw ControlApiException(
        _zhAuthError(body['error']?.toString() ?? '设备删除失败'),
      );
    }
  }

  Future<Map<String, dynamic>> _sendJson({
    required String method,
    required Uri uri,
    Map<String, dynamic>? payload,
    String? authToken,
    String? unauthorizedMessage,
  }) async {
    try {
      final request = await _client
          .openUrl(method, uri)
          .timeout(const Duration(seconds: 8));
      request.persistentConnection = false;
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (authToken != null && authToken.trim().isNotEmpty) {
        request.headers.set(
          HttpHeaders.authorizationHeader,
          'Bearer ${authToken.trim()}',
        );
      }
      if (payload != null) {
        request.headers.contentType = ContentType.json;
        request.write(jsonEncode(payload));
      }
      final response = await request.close().timeout(
        const Duration(seconds: 8),
      );
      final text = await utf8.decodeStream(response);
      final decoded = text.trim().isEmpty
          ? <String, dynamic>{}
          : jsonDecode(text);
      final Map<String, dynamic> body = decoded is Map
          ? Map<String, dynamic>.from(decoded)
          : <String, dynamic>{};
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw ControlApiException(
          _zhAuthError(
            body['error']?.toString(),
            response.statusCode,
            unauthorizedMessage,
          ),
        );
      }
      return body;
    } on ControlApiException {
      rethrow;
    } on TimeoutException {
      throw ControlApiException('连接控制服务器超时：${uri.origin}');
    } on SocketException catch (error) {
      throw ControlApiException(_zhNetworkError(error, uri));
    } on HandshakeException {
      throw ControlApiException('控制服务器 TLS 握手失败：${uri.origin}');
    } on FormatException {
      throw const ControlApiException('控制服务器返回了无法解析的数据');
    } on HttpException catch (error) {
      throw ControlApiException('控制服务器请求失败：${error.message}');
    }
  }

  void close() {
    _client.close(force: true);
  }
}

String _normalizeAuthControlServer(String value) {
  try {
    return normalizeControlServer(value);
  } on FormatException catch (error) {
    throw ControlApiException(error.message);
  }
}

class ControlApiException implements Exception {
  const ControlApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

String _zhAuthError(
  String? message, [
  int? statusCode,
  String? unauthorizedMessage,
]) {
  final raw = message?.trim() ?? '';
  final normalized = raw.toLowerCase();
  if (statusCode == 401) return unauthorizedMessage ?? '认证失败，请检查邮箱和密码';
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

String _zhNetworkError(SocketException error, Uri uri) {
  final osMessage = error.osError?.message.toLowerCase() ?? '';
  final message = error.message.toLowerCase();
  if (osMessage.contains('nodename nor servname') ||
      osMessage.contains('name or service not known') ||
      osMessage.contains('no address associated') ||
      message.contains('failed host lookup')) {
    return '无法解析控制服务器域名：${uri.host}。请检查网络，或把控制面服务器改为可访问地址。';
  }
  if (osMessage.contains('connection refused') ||
      message.contains('connection refused')) {
    return '无法连接控制服务器：${uri.origin}。请确认服务端已启动且地址/端口正确。';
  }
  if (osMessage.contains('socket is not connected') ||
      osMessage.contains('no address') ||
      osMessage.contains('sendto') ||
      osMessage.contains('套接字没有连接') ||
      osMessage.contains('没有提供地址') ||
      message.contains('socket is not connected') ||
      message.contains('no address') ||
      message.contains('sendto') ||
      message.contains('套接字没有连接') ||
      message.contains('没有提供地址')) {
    return 'Windows 无法建立到控制服务器的连接：${uri.origin}。请检查代理/VPN/防火墙，或在浏览器打开 ${uri.origin}/health 验证是否返回 ok。';
  }
  return '控制服务器网络请求失败：${error.message}';
}
