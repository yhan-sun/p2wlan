import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

/// Small native bridge for platform-owned values Flutter cannot resolve from
/// its process environment. Android and HarmonyOS supply an application-private
/// persistent directory through their native application context.
const _nativePlatformChannel = MethodChannel('p2wlan/platform');

const _nativeBuildInfoErrorCodes = <String>{
  'NATIVE_LIBRARY_LOAD_FAILED',
  'NATIVE_ABI_MISMATCH',
  'NATIVE_QUERY_FAILED',
  'NATIVE_RESULT_INVALID',
};

const _vpnEngineStatusErrorCodes = <String>{
  'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED',
  'VPN_ENGINE_STATUS_SNAPSHOT_INVALID',
  'VPN_ENGINE_STATUS_SNAPSHOT_TOO_LARGE',
  'VPN_ENGINE_STATUS_QUERY_FAILED',
  'VPN_ENGINE_STATUS_RESULT_INVALID',
  'VPN_ENGINE_STATUS_STALE',
  'VPN_ENGINE_STATUS_FUTURE',
  'VPN_ENGINE_STATUS_REVISION_REGRESSION',
};

const _vpnEngineStatusValues = <String>{
  'starting',
  'ready',
  'stopping',
  'stopped',
  'draining',
  'failed',
};

const _vpnOperationValues = <String>{'start', 'stop'};

class NativeBuildInfo {
  const NativeBuildInfo({
    required this.abiVersion,
    required this.engineVersion,
    required this.target,
    required this.arch,
  });

  final int abiVersion;
  final String engineVersion;
  final String target;
  final String arch;
}

class NativeBuildInfoException implements Exception {
  const NativeBuildInfoException(this.code);

  final String code;

  @override
  String toString() => 'NativeBuildInfoException($code)';
}

class VpnEngineStatusIdentity {
  const VpnEngineStatusIdentity({
    required this.instanceId,
    required this.generation,
  });

  final String instanceId;
  final int generation;
}

class VpnEngineStatusSnapshot {
  const VpnEngineStatusSnapshot({
    required this.schemaVersion,
    required this.revision,
    required this.updatedAtEpochMs,
    required this.requestId,
    required this.operation,
    required this.settingsRevision,
    required this.identity,
    required this.status,
    this.code,
  });

  final int schemaVersion;
  final int revision;
  final int updatedAtEpochMs;
  final String requestId;
  final String operation;
  final int settingsRevision;
  final VpnEngineStatusIdentity? identity;
  final String status;
  final String? code;

  DateTime get updatedAt =>
      DateTime.fromMillisecondsSinceEpoch(updatedAtEpochMs).toLocal();
}

class VpnEngineStatusException implements Exception {
  const VpnEngineStatusException(this.code);

  final String code;

  @override
  String toString() => 'VpnEngineStatusException($code)';
}

/// Reads the Extension-owned status snapshot and enforces its freshness and
/// monotonic revision contract in the Flutter process.
class VpnEngineStatusBridge {
  VpnEngineStatusBridge({
    required this.operatingSystem,
    required this.channel,
    int Function()? nowEpochMs,
  }) : _nowEpochMs = nowEpochMs ?? _systemNowEpochMs;

  static const _maxAgeMs = 15 * 1000;
  static const _maxSafeInteger = 9007199254740991;

  final String operatingSystem;
  final MethodChannel channel;
  final int Function() _nowEpochMs;
  int? _lastRevision;

  Future<VpnEngineStatusSnapshot> read() async {
    final snapshot = await readMaybe();
    if (snapshot == null) {
      throw const VpnEngineStatusException(
        'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED',
      );
    }
    return snapshot;
  }

  Future<VpnEngineStatusSnapshot?> readMaybe({
    bool allowStaleStopped = false,
  }) async {
    if (operatingSystem != 'ohos') {
      throw UnsupportedError('VPN engine status is only available on OHOS.');
    }

    Object? response;
    try {
      response = await channel.invokeMethod<Object?>('vpnEngineStatusV2');
    } catch (_) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_QUERY_FAILED');
    }

    final snapshot = _parseResponse(response);
    if (snapshot == null) return null;
    final now = _nowEpochMs();
    if (snapshot.updatedAtEpochMs > now) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_FUTURE');
    }
    if (now - snapshot.updatedAtEpochMs > _maxAgeMs &&
        !(allowStaleStopped && snapshot.status == 'stopped')) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_STALE');
    }
    final previousRevision = _lastRevision;
    if (previousRevision != null && snapshot.revision < previousRevision) {
      throw const VpnEngineStatusException(
        'VPN_ENGINE_STATUS_REVISION_REGRESSION',
      );
    }
    _lastRevision = snapshot.revision;
    return snapshot;
  }

  VpnEngineStatusSnapshot? _parseResponse(Object? response) {
    if (response is! Map) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }
    if (response['ok'] == false) {
      if (!_hasExactKeys(response, const {'ok', 'error'})) {
        throw const VpnEngineStatusException(
          'VPN_ENGINE_STATUS_RESULT_INVALID',
        );
      }
      final error = response['error'];
      if (error is! Map || !_hasExactKeys(error, const {'code'})) {
        throw const VpnEngineStatusException(
          'VPN_ENGINE_STATUS_RESULT_INVALID',
        );
      }
      final code = error['code'];
      if (code is String && _vpnEngineStatusErrorCodes.contains(code)) {
        throw VpnEngineStatusException(code);
      }
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }
    if (response['ok'] != true ||
        !_hasExactKeys(response, const {'ok', 'data'})) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }

    final data = response['data'];
    if (data == null) return null;
    if (data is! Map) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }
    final hasCode = data.containsKey('code');
    final expectedKeys = <String>{
      'schemaVersion',
      'revision',
      'updatedAtEpochMs',
      'requestId',
      'operation',
      'settingsRevision',
      'identity',
      'status',
      if (hasCode) 'code',
    };
    if (!_hasExactKeys(data, expectedKeys)) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }

    final schemaVersion = data['schemaVersion'];
    final revision = data['revision'];
    final updatedAtEpochMs = data['updatedAtEpochMs'];
    final requestId = data['requestId'];
    final operation = data['operation'];
    final settingsRevision = data['settingsRevision'];
    final status = data['status'];
    final identity = _parseIdentity(data['identity']);
    final code = data['code'];
    if (schemaVersion is! int ||
        schemaVersion != 2 ||
        revision is! int ||
        revision <= 0 ||
        revision > _maxSafeInteger ||
        updatedAtEpochMs is! int ||
        updatedAtEpochMs <= 0 ||
        updatedAtEpochMs > _maxSafeInteger ||
        requestId is! String ||
        requestId.isEmpty ||
        requestId.length > 128 ||
        !RegExp(r'^[A-Za-z0-9._:-]+$').hasMatch(requestId) ||
        operation is! String ||
        !_vpnOperationValues.contains(operation) ||
        settingsRevision is! int ||
        settingsRevision <= 0 ||
        settingsRevision > _maxSafeInteger ||
        status is! String ||
        !_vpnEngineStatusValues.contains(status) ||
        (hasCode &&
            (code is! String ||
                !RegExp(r'^[A-Za-z][A-Za-z0-9_]{0,63}$').hasMatch(code)))) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }

    return VpnEngineStatusSnapshot(
      schemaVersion: schemaVersion,
      revision: revision,
      updatedAtEpochMs: updatedAtEpochMs,
      requestId: requestId,
      operation: operation,
      settingsRevision: settingsRevision,
      identity: identity,
      status: status,
      code: hasCode ? code as String : null,
    );
  }

  VpnEngineStatusIdentity? _parseIdentity(Object? value) {
    if (value == null) return null;
    if (value is! Map ||
        !_hasExactKeys(value, const {'instanceId', 'generation'})) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }
    final instanceId = value['instanceId'];
    final generation = value['generation'];
    if (instanceId is! String ||
        instanceId.isEmpty ||
        instanceId.length > 256 ||
        instanceId.trim() != instanceId ||
        instanceId.contains('\u0000') ||
        generation is! int ||
        generation <= 0 ||
        generation > _maxSafeInteger) {
      throw const VpnEngineStatusException('VPN_ENGINE_STATUS_RESULT_INVALID');
    }
    return VpnEngineStatusIdentity(
      instanceId: instanceId,
      generation: generation,
    );
  }

  static bool _hasExactKeys(Map value, Set<String> expected) =>
      value.length == expected.length &&
      value.keys.every((key) => key is String && expected.contains(key));

  static int _systemNowEpochMs() => DateTime.now().millisecondsSinceEpoch;
}

abstract interface class HarmonyVpnTransport {
  Future<void> start(String requestId, int settingsRevision);

  Future<void> stop({
    required String requestId,
    required String expectedStatusRequestId,
    required int settingsRevision,
    required int afterStatusRevision,
  });

  Future<VpnEngineStatusSnapshot?> status();
}

class MethodChannelHarmonyVpnTransport implements HarmonyVpnTransport {
  MethodChannelHarmonyVpnTransport({
    MethodChannel? channel,
    VpnEngineStatusBridge? statusBridge,
    this.startRequestTimeout = const Duration(seconds: 45),
    this.stopRequestTimeout = const Duration(seconds: 12),
    this.statusRequestTimeout = const Duration(seconds: 5),
  }) : channel = channel ?? _nativePlatformChannel,
       _statusBridge =
           statusBridge ??
           VpnEngineStatusBridge(
             operatingSystem: 'ohos',
             channel: channel ?? _nativePlatformChannel,
           );

  final MethodChannel channel;
  final VpnEngineStatusBridge _statusBridge;
  final Duration startRequestTimeout;
  final Duration stopRequestTimeout;
  final Duration statusRequestTimeout;
  Future<void>? _pendingStartRequest;
  Future<void>? _pendingStopRequest;
  Future<VpnEngineStatusSnapshot?>? _pendingStatusRequest;

  @override
  Future<void> start(String requestId, int settingsRevision) {
    if (_pendingStartRequest != null) {
      return Future<void>.error(
        PlatformException(code: 'VPN_ABILITY_REQUEST_PENDING'),
      );
    }
    final request = channel
        .invokeMethod<Object?>('startVpnV2', {
          'requestId': requestId,
          'settingsRevision': settingsRevision,
        })
        .then<void>(
          (response) => _validateRequestResult(response, 'start_requested'),
        );
    _pendingStartRequest = request;
    _clearWhenComplete(request, () {
      if (identical(_pendingStartRequest, request)) {
        _pendingStartRequest = null;
      }
    });
    // A system authorization prompt may keep the native method call open.
    // Bound the caller's wait, but retain the in-flight marker until the
    // platform actually replies so retries cannot stack another VPN request.
    return request.timeout(startRequestTimeout);
  }

  @override
  Future<void> stop({
    required String requestId,
    required String expectedStatusRequestId,
    required int settingsRevision,
    required int afterStatusRevision,
  }) {
    if (_pendingStopRequest != null) {
      return Future<void>.error(
        PlatformException(code: 'VPN_ABILITY_REQUEST_PENDING'),
      );
    }
    final request = channel
        .invokeMethod<Object?>('stopVpnV2', {
          'requestId': requestId,
          'expectedStatusRequestId': expectedStatusRequestId,
          'settingsRevision': settingsRevision,
          'afterStatusRevision': afterStatusRevision,
        })
        .then<void>(
          (response) => _validateRequestResult(response, 'stop_requested'),
        );
    _pendingStopRequest = request;
    _clearWhenComplete(request, () {
      if (identical(_pendingStopRequest, request)) {
        _pendingStopRequest = null;
      }
    });
    return request.timeout(stopRequestTimeout);
  }

  @override
  Future<VpnEngineStatusSnapshot?> status() {
    if (_pendingStatusRequest != null) {
      return Future<VpnEngineStatusSnapshot?>.error(
        const VpnEngineStatusException('VPN_ENGINE_STATUS_QUERY_FAILED'),
      );
    }
    final request = _statusBridge.readMaybe(allowStaleStopped: true);
    _pendingStatusRequest = request;
    _clearWhenComplete(request, () {
      if (identical(_pendingStatusRequest, request)) {
        _pendingStatusRequest = null;
      }
    });
    return request.timeout(statusRequestTimeout);
  }

  void _clearWhenComplete<T>(Future<T> request, void Function() clear) {
    unawaited(
      request.then<void>(
        (_) => clear(),
        onError: (Object _, StackTrace _) => clear(),
      ),
    );
  }

  void _validateRequestResult(Object? response, String expectedPhase) {
    if (response is! Map || response['ok'] is! bool) {
      throw PlatformException(code: 'VPN_ABILITY_REQUEST_RESULT_INVALID');
    }
    if (response['ok'] == false) {
      if (!_hasExactRequestKeys(response, const {'ok', 'error'})) {
        throw PlatformException(code: 'VPN_ABILITY_REQUEST_RESULT_INVALID');
      }
      final error = response['error'];
      if (error is! Map || !_hasExactRequestKeys(error, const {'code'})) {
        throw PlatformException(code: 'VPN_ABILITY_REQUEST_FAILED');
      }
      final code = error['code'];
      if (code is String &&
          RegExp(r'^[A-Za-z][A-Za-z0-9_]{0,63}$').hasMatch(code)) {
        throw PlatformException(code: code);
      }
      throw PlatformException(code: 'VPN_ABILITY_REQUEST_FAILED');
    }
    if (!_hasExactRequestKeys(response, const {'ok', 'phase'}) ||
        response['phase'] != expectedPhase) {
      throw PlatformException(code: 'VPN_ABILITY_REQUEST_RESULT_INVALID');
    }
  }

  bool _hasExactRequestKeys(Map value, Set<String> expected) =>
      value.length == expected.length &&
      value.keys.every((key) => key is String && expected.contains(key));
}

String? _cachedApplicationSupportDirectoryPath;

bool usesApplicationSupportDirectoryBridge(String operatingSystem) =>
    operatingSystem == 'android' || operatingSystem == 'ohos';

/// Keeps the native filesystem lookup testable without changing the running
/// process platform or registering a production channel handler in tests.
class NativePlatformBridge {
  const NativePlatformBridge({
    required this.operatingSystem,
    required this.channel,
  });

  final String operatingSystem;
  final MethodChannel channel;

  bool get usesApplicationSupportDirectory =>
      usesApplicationSupportDirectoryBridge(operatingSystem);

  Future<String?> readDiagnosticsAuthToken() async {
    if (operatingSystem != 'ohos') return null;
    try {
      final value = await channel
          .invokeMethod<String>('diagnosticsAuthToken')
          .timeout(const Duration(seconds: 2));
      return value != null &&
              value.length == 64 &&
              RegExp(r'^[0-9a-f]{64}$').hasMatch(value)
          ? value
          : null;
    } catch (_) {
      return null;
    }
  }

  Future<Directory?> resolveApplicationSupportDirectory() async {
    if (!usesApplicationSupportDirectory) return null;

    final path = await channel.invokeMethod<String>(
      'applicationSupportDirectory',
    );
    final trimmed = path?.trim() ?? '';
    if (trimmed.isEmpty) {
      throw StateError('Native application support directory is unavailable.');
    }
    return Directory(trimmed);
  }

  Future<NativeBuildInfo> queryNativeBuildInfo() async {
    if (operatingSystem != 'ohos') {
      throw UnsupportedError('Native build info is only available on OHOS.');
    }

    Object? response;
    try {
      response = await channel.invokeMethod<Object?>('nativeBuildInfo');
    } catch (_) {
      // Keep platform-channel details private and expose only a stable code.
      throw const NativeBuildInfoException('NATIVE_QUERY_FAILED');
    }

    if (response is! Map) {
      throw const NativeBuildInfoException('NATIVE_RESULT_INVALID');
    }
    if (response['ok'] == false) {
      final error = response['error'];
      final code = error is Map ? error['code'] : null;
      if (code is String && _nativeBuildInfoErrorCodes.contains(code)) {
        throw NativeBuildInfoException(code);
      }
      throw const NativeBuildInfoException('NATIVE_RESULT_INVALID');
    }
    if (response['ok'] != true) {
      throw const NativeBuildInfoException('NATIVE_RESULT_INVALID');
    }

    final data = response['data'];
    if (data is! Map) {
      throw const NativeBuildInfoException('NATIVE_RESULT_INVALID');
    }
    final abiVersion = data['abiVersion'];
    if (abiVersion is! int) {
      throw const NativeBuildInfoException('NATIVE_RESULT_INVALID');
    }
    if (abiVersion != 1) {
      throw const NativeBuildInfoException('NATIVE_ABI_MISMATCH');
    }

    final engineVersion = data['engineVersion'];
    final target = data['target'];
    final arch = data['arch'];
    if (engineVersion is! String ||
        target is! String ||
        arch is! String ||
        engineVersion.trim().isEmpty ||
        target.trim().isEmpty ||
        arch.trim().isEmpty) {
      throw const NativeBuildInfoException('NATIVE_RESULT_INVALID');
    }

    return NativeBuildInfo(
      abiVersion: abiVersion,
      engineVersion: engineVersion.trim(),
      target: target.trim(),
      arch: arch.trim(),
    );
  }
}

final _nativePlatformBridge = NativePlatformBridge(
  operatingSystem: Platform.operatingSystem,
  channel: _nativePlatformChannel,
);

final _vpnEngineStatusBridge = VpnEngineStatusBridge(
  operatingSystem: Platform.operatingSystem,
  channel: _nativePlatformChannel,
);

/// True when persistent storage must be obtained from the application context.
bool get usesNativeApplicationSupportDirectory =>
    _nativePlatformBridge.usesApplicationSupportDirectory;

/// Keep the resolved app-private path available to synchronous display-only
/// getters after SettingsStore has initialized the native bridge.
String? get cachedApplicationSupportDirectoryPath =>
    _cachedApplicationSupportDirectoryPath;

Future<Directory?> resolveApplicationSupportDirectory() async {
  final directory = await _nativePlatformBridge
      .resolveApplicationSupportDirectory();
  _cachedApplicationSupportDirectoryPath = directory?.path;
  return directory;
}

Future<NativeBuildInfo> queryNativeBuildInfo() =>
    _nativePlatformBridge.queryNativeBuildInfo();

Future<VpnEngineStatusSnapshot> queryVpnEngineStatus() =>
    _vpnEngineStatusBridge.read();

Future<String?> resolveAndroidDeviceName() async {
  if (!Platform.isAndroid) return null;
  try {
    final value = await _nativePlatformChannel.invokeMethod<String>(
      'deviceName',
    );
    final trimmed = value?.trim() ?? '';
    return trimmed.isEmpty ? null : trimmed;
  } catch (_) {
    // Device naming is a convenience. A bridge failure must not prevent an
    // existing configuration from loading or a user from logging in.
    return null;
  }
}
