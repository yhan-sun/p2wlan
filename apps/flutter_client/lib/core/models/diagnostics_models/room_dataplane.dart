part of '../diagnostics_models.dart';

class RoomDataPlaneSnapshot {
  RoomDataPlaneSnapshot.fromJson(JsonMap json)
    : authorizationState = _string(json['authorization_state'], 'unknown'),
      localIp = _nullableString(json['local_ip']),
      leaseAtCaptureMs = _int(json['lease_remaining_ms']),
      lastDrop = _mapOrNull(json['last_drop']),
      peers = [for (final value in _list(json['peers'])) _map(value)],
      drops = _map(json['drops']);

  final String authorizationState;
  final String? localIp;
  final int leaseAtCaptureMs;
  final JsonMap? lastDrop;
  final List<JsonMap> peers;
  final JsonMap drops;
  final Stopwatch _age = Stopwatch()..start();

  static RoomDataPlaneSnapshot? parse(dynamic value) {
    final json = _mapOrNull(value);
    return json == null ? null : RoomDataPlaneSnapshot.fromJson(json);
  }

  int get elapsedMs => _age.elapsedMilliseconds;
  String get currentState =>
      authorizationState == 'valid' && leaseAtCaptureMs <= elapsedMs
      ? 'expired'
      : authorizationState;

  String? get blockingLabel => switch (currentState) {
    'valid' => null,
    'missing' => '等待房间授权',
    'expired' => '房间授权已过期',
    'local_ip_mismatch' => '本机地址待同步',
    _ => '房间数据状态未知',
  };
}
