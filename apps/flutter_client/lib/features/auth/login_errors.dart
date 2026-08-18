import 'dart:async';
import 'dart:io';

import '../../core/api/control_api.dart';

/// User-facing buckets for the login flow. The `ControlApi` layer raises
/// `ControlApiException` with Chinese developer messages; this feature layer
/// classifies them so the UI can render a localized, non-technical message
/// instead of leaking the raw message (or an English UI showing Chinese text).
enum LoginErrorKind {
  /// Local form validation (email empty, password too short).
  validation,

  /// Credentials rejected / token expired / account conflicts.
  authentication,

  /// The email is already registered on the control server.
  accountExists,

  /// Control server unreachable, DNS failure, TLS failure.
  network,

  /// Request timed out.
  timeout,

  /// Server responded but the API/endpoint is unavailable or malformed.
  server,

  /// Rate limited by the control server.
  rateLimited,

  /// Registration-specific failures.
  registrationFailed,

  /// Anything that cannot be classified safely.
  unknown,
}

class LoginValidationException implements Exception {
  const LoginValidationException(this.message);

  final String message;
}

/// Classifies a thrown error into a user-facing bucket.
///
/// The mapping is keyed on the known, finite set of messages raised by
/// `ControlApi` (they are developer-facing Chinese strings); anything not in
/// that set falls back to [LoginErrorKind.unknown] so the raw exception text
/// never reaches the primary UI.
LoginErrorKind loginErrorKindOf(Object error) {
  if (error is LoginValidationException) return LoginErrorKind.validation;
  if (error is ControlApiException) {
    return _kindForControlMessage(error.message);
  }
  if (error is SocketException ||
      error is HandshakeException ||
      error is HttpException) {
    return LoginErrorKind.network;
  }
  if (error is TimeoutException) return LoginErrorKind.timeout;
  return LoginErrorKind.unknown;
}

LoginErrorKind _kindForControlMessage(String message) {
  if (message.startsWith('无法连接控制服务器') ||
      message.startsWith('无法解析控制服务器域名') ||
      message.startsWith('Windows 无法建立到控制服务器的连接') ||
      message.startsWith('控制服务器网络请求失败') ||
      message.startsWith('控制服务器 TLS 握手失败')) {
    return LoginErrorKind.network;
  }
  if (message.startsWith('连接控制服务器超时')) {
    return LoginErrorKind.timeout;
  }
  if (message.startsWith('控制服务器暂不支持') ||
      message.startsWith('控制服务器返回了无法解析的数据') ||
      message.startsWith('控制服务器请求失败')) {
    return LoginErrorKind.server;
  }
  if (message.startsWith('账号已存在')) {
    return LoginErrorKind.accountExists;
  }
  if (message.startsWith('请求过于频繁')) {
    return LoginErrorKind.rateLimited;
  }
  if (message.startsWith('注册失败')) {
    return LoginErrorKind.registrationFailed;
  }
  if (message.startsWith('邮箱') ||
      message.startsWith('密码') ||
      message.startsWith('认证') ||
      message.startsWith('登录状态') ||
      message.startsWith('当前账号没有权限')) {
    return LoginErrorKind.authentication;
  }
  return LoginErrorKind.unknown;
}
