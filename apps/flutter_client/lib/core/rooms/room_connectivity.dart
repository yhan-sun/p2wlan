import '../models/diagnostics_models.dart';

class RoomConnectivitySummary {
  const RoomConnectivitySummary({
    required this.direct,
    required this.relay,
    required this.pending,
    required this.offline,
    this.establishingSession = false,
    this.punching = false,
  });

  factory RoomConnectivitySummary.fromPeers(Iterable<PeerSnapshot> peers) {
    var direct = 0, relay = 0, pending = 0, offline = 0;
    var establishingSession = false, punching = false;
    for (final peer in peers) {
      if (!peer.online) {
        offline++;
      } else if (peer.isDirectVerified) {
        direct++;
      } else if (peer.isRelayVerified) {
        relay++;
      } else {
        pending++;
        final state = peer.state.toLowerCase();
        establishingSession |=
            state.contains('handshake') || state.contains('connect');
        punching |= state.contains('punch') || state.contains('prob');
      }
    }
    return RoomConnectivitySummary(
      direct: direct,
      relay: relay,
      pending: pending,
      offline: offline,
      establishingSession: establishingSession,
      punching: punching,
    );
  }

  final int direct;
  final int relay;
  final int pending;
  final int offline;
  final bool establishingSession;
  final bool punching;
  int get reachable => direct + relay;
  int get online => reachable + pending;

  String get label {
    if (online == 0) return '等待好友';
    if (reachable == 0) {
      if (establishingSession) return '建立加密会话';
      if (punching) return '直连探测';
      return '建立连接中';
    }
    if (pending > 0) return '部分连通';
    if (direct > 0 && relay > 0) return '直连与中继';
    return direct > 0 ? '已直连' : '中继可用';
  }

  String get details =>
      '在线 $online · 可互通 $reachable · 直连 $direct / 中继 $relay / 未连通 $pending';
}
