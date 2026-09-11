import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../daemon/daemon_controller.dart';
import '../diagnostics/support_log_protocol.dart';
import '../models/diagnostics_models.dart';
import 'room_api.dart';
import 'room_profiles.dart';
import 'room_connection_preferences.dart';

enum RoomConnectionPhase { starting, running, unavailable, stopping, failed }

class ParallelRoomPlan {
  ParallelRoomPlan(
    AppSettings account,
    this.room, {
    this.automatic = false,
    int? diagnosticsPort,
  }) {
    final selected = selectRoomSettings(account, room);
    profileId = roomProfileId(selected);
    final port =
        diagnosticsPort ??
        (40000 + int.parse(profileId.substring(0, 8), radix: 16) % 20000);
    if (port < 40000 || port >= 60000) {
      throw ArgumentError.value(port, 'diagnosticsPort');
    }
    settings = selected.copyWith(
      diagnosticsUrl: 'http://127.0.0.1:$port/status',
      tunInterface: 'p2r${profileId.substring(0, 12)}',
      udpBind: '0.0.0.0:0',
      udpAdvertise: '',
    );
  }

  final FriendRoom room;
  final bool automatic;
  late final String profileId;
  late final AppSettings settings;
}

abstract interface class RoomRuntime {
  Future<bool> exists();
  Future<DaemonCommandResult> start();
  Future<DaemonCommandResult> stop();
  Future<DiagnosticsSnapshot> status();
  void close();
}

abstract interface class RoomControlStatus {
  String? get controlWarning;
}

class ParallelRoomSession {
  ParallelRoomSession(this.plan, this.runtime);
  final ParallelRoomPlan plan;
  final RoomRuntime runtime;
  RoomConnectionPhase phase = RoomConnectionPhase.starting;
  DiagnosticsSnapshot? snapshot;
  String? message;
  bool refreshing = false;
  int revision = 0;
}

typedef RoomRuntimeFactory = RoomRuntime Function(ParallelRoomPlan plan);

class ParallelRooms extends ChangeNotifier {
  ParallelRooms({
    required this.readSettings,
    required this.runtimeFactory,
    bool? supported,
    RoomConnectionPreferences? preferences,
    this.maxConnections = 8,
    this.refreshInterval = const Duration(seconds: 5),
  }) : preferences = preferences ?? RoomConnectionPreferences(),
       supported = supported ?? platformSupported {
    if (maxConnections < 1 || maxConnections > 32) {
      throw ArgumentError.value(maxConnections, 'maxConnections');
    }
    _credentials = _credentialKey(readSettings());
  }

  static bool get platformSupported =>
      Platform.isWindows || Platform.isMacOS || Platform.isLinux;

  final RoomConnectionPreferences preferences;
  final AppSettings Function() readSettings;
  final RoomRuntimeFactory runtimeFactory;
  final bool supported;
  final int maxConnections;
  final Duration refreshInterval;
  final _sessions = <String, ParallelRoomSession>{};
  final _operations = <String, Future<DaemonCommandResult>>{};
  final _recovering = <String>{};
  final _recentRoomSnapshots = <String, DiagnosticsSnapshot?>{};
  final _recentRoomPlans = <String, ParallelRoomPlan>{};
  final _recentRoomPhases = <String, RoomConnectionPhase>{};
  final _recentRoomMessages = <String, String>{};
  Timer? _timer;
  Duration? _scheduledInterval;
  var _credentials = '';
  var _epoch = 0;
  var _admissionPauses = 0;
  var _disposed = false;
  Future<DaemonCommandResult>? _stoppingAll;
  String? lastError;

  Map<String, ParallelRoomSession> get sessions => Map.unmodifiable(_sessions);
  Map<String, DiagnosticsSnapshot?> get recentRoomSnapshots =>
      Map.unmodifiable(_recentRoomSnapshots);
  List<String> get supportLogProfileCandidates {
    final ids = <String>[];
    void add(String id) {
      if (!ids.contains(id)) {
        ids.add(id);
      }
    }

    for (final s in _sessions.values) {
      if (!_isCurrentAccountPlan(s.plan)) continue;
      add(s.plan.profileId);
    }
    // The map is an LRU-style bounded history.  Prefer the most recently
    // stopped/failed rooms after all live rooms, so a support bundle stays
    // within the v2 eight-room contract without losing the latest failure.
    for (final id in _recentRoomPlans.keys.toList().reversed) {
      final plan = _recentRoomPlans[id];
      if (plan == null || !_isCurrentAccountPlan(plan)) continue;
      add(id);
    }
    return List.unmodifiable(ids);
  }

  SupportLogRoomSelection get supportLogSelection =>
      selectSupportLogRoomProfiles(supportLogProfileCandidates);

  List<String> get allRecentRoomProfileIds =>
      supportLogSelection.retainedProfileIds;

  Map<String, String> exportStatusSummaries() {
    final summaries = <String, String>{};
    for (final id in allRecentRoomProfileIds) {
      ParallelRoomSession? active;
      for (final s in _sessions.values) {
        if (s.plan.profileId == id) {
          active = s;
          break;
        }
      }
      final snapshot = active?.snapshot ?? _recentRoomSnapshots[id];
      final plan = active?.plan ?? _recentRoomPlans[id];
      if (plan != null) {
        final phase =
            active?.phase ??
            _recentRoomPhases[id] ??
            RoomConnectionPhase.unavailable;
        final message = active?.message ?? _recentRoomMessages[id];
        summaries[id] = jsonEncode({
          'network_id': plan.room.id,
          'room_name': plan.room.name,
          'profile_id': id,
          'phase': phase.name,
          if (message != null && message.isNotEmpty) 'message': message,
          if (snapshot != null) 'last_status': snapshot.raw,
        });
      }
    }
    return summaries;
  }

  void _rememberRoom(
    ParallelRoomPlan plan, {
    DiagnosticsSnapshot? snapshot,
    bool replaceSnapshot = false,
    RoomConnectionPhase? phase,
    String? message,
  }) {
    // A late status/start failure from the previous account must never make
    // its room path eligible for the next account's support upload.
    if (!_isCurrentAccountPlan(plan)) return;
    final id = plan.profileId;
    _recentRoomPlans.remove(id);
    _recentRoomPlans[id] = plan;
    if (replaceSnapshot) _recentRoomSnapshots[id] = snapshot;
    if (phase != null) _recentRoomPhases[id] = phase;
    if (message == null || message.isEmpty) {
      _recentRoomMessages.remove(id);
    } else {
      _recentRoomMessages[id] = message;
    }
    while (_recentRoomPlans.length > maxTrackedSupportLogRoomInstances) {
      final oldest = _recentRoomPlans.keys.first;
      _recentRoomPlans.remove(oldest);
      _recentRoomSnapshots.remove(oldest);
      _recentRoomPhases.remove(oldest);
      _recentRoomMessages.remove(oldest);
    }
  }

  bool get hasSessions =>
      _sessions.isNotEmpty || _operations.isNotEmpty || _recovering.isNotEmpty;
  int get activeConnections => _sessions.length;
  bool get connectionsPaused => _admissionPauses > 0;
  bool get stoppingAll => _stoppingAll != null;
  bool get busy =>
      _operations.isNotEmpty || _stoppingAll != null || connectionsPaused;
  ParallelRoomSession? session(String roomId) => _sessions[roomId];

  String _credentialKey(AppSettings value) =>
      '${value.controlServer}\n${value.authToken}';

  bool _isCurrentAccountPlan(ParallelRoomPlan plan) {
    final planCredentials = _credentialKey(plan.settings);
    return planCredentials == _credentials &&
        planCredentials == _credentialKey(readSettings());
  }

  Future<DaemonCommandResult> credentialsChanged() {
    final next = _credentialKey(readSettings());
    if (next == _credentials) return Future.value(_ok());
    _credentials = next;
    _epoch++;
    _recentRoomPlans.clear();
    _recentRoomSnapshots.clear();
    _recentRoomPhases.clear();
    _recentRoomMessages.clear();
    return stopAll();
  }

  Future<T> withConnectionsPaused<T>(Future<T> Function() action) {
    _admissionPauses++;
    _epoch++;
    _notify();
    try {
      final future = action();
      return future.whenComplete(() {
        _admissionPauses--;
        _notify();
      });
    } catch (_) {
      _admissionPauses--;
      _notify();
      rethrow;
    }
  }

  Future<DaemonCommandResult> connect(
    FriendRoom room, {
    bool automatic = false,
  }) {
    if (!supported) return Future.value(_fail('当前平台尚未接入多房间并行运行时'));
    if (_disposed || _stoppingAll != null || connectionsPaused) {
      return Future.value(_fail('网络正在关闭，未启动房间'));
    }
    if (_credentialKey(readSettings()) != _credentials) {
      return credentialsChanged().then(
        (result) => result.ok ? connect(room, automatic: automatic) : result,
      );
    }
    final epoch = _epoch;
    final credentials = _credentialKey(readSettings());
    return _enqueue(
      room.id,
      () => _connect(room, epoch, credentials, automatic),
    );
  }

  Future<DaemonCommandResult> disconnect(String roomId) =>
      _stoppingAll ??
      _enqueue(roomId, () async {
        final entry = _sessions[roomId];
        if (entry != null) {
          try {
            await preferences.update(entry.plan.profileId, wanted: false);
          } catch (_) {
            final result = await _disconnect(roomId);
            return result.ok ? _fail('本机已断开，但无法保存停止自动连接设置，请检查本地目录权限') : result;
          }
        }
        return _disconnect(roomId);
      });

  Future<RoomConnectionPreference> connectionPreference(FriendRoom room) =>
      preferences.read(ParallelRoomPlan(readSettings(), room).profileId);

  Future<void> setAutoConnect(FriendRoom room, bool enabled) async {
    await preferences.update(
      ParallelRoomPlan(readSettings(), room).profileId,
      autoConnect: enabled,
      wanted: enabled,
    );
    _notify();
  }

  Future<void> forgetConnectionIntent(FriendRoom room) => preferences.update(
    ParallelRoomPlan(readSettings(), room).profileId,
    wanted: false,
  );

  Future<DaemonCommandResult> _enqueue(
    String id,
    Future<DaemonCommandResult> Function() action,
  ) {
    if (_disposed) return Future.value(_fail('房间管理器已经关闭'));
    final previous = _operations[id];
    final future = (previous ?? Future.value(_ok())).then((_) async {
      try {
        return await action();
      } catch (_) {
        return _fail('房间操作失败，请检查本地服务和控制服务器');
      }
    });
    _operations[id] = future;
    unawaited(
      future.then((_) {
        if (identical(_operations[id], future)) _operations.remove(id);
        _notify();
      }),
    );
    return future;
  }

  bool _accepts(int epoch, String credentials) =>
      !_disposed &&
      _stoppingAll == null &&
      !connectionsPaused &&
      epoch == _epoch &&
      credentials == _credentialKey(readSettings());

  Future<DaemonCommandResult> _connect(
    FriendRoom room,
    int epoch,
    String credentials,
    bool automatic,
  ) async {
    if (!_accepts(epoch, credentials)) return _fail('登录状态已变化，已取消连接');
    var account = readSettings();
    final initialPlan = ParallelRoomPlan(account, room, automatic: automatic);
    final preference = await preferences.read(initialPlan.profileId);
    if (!_accepts(epoch, credentials)) return _fail('登录状态已变化，已取消连接');
    account = readSettings();
    if (_sessions.values.any(
      (entry) => _credentialKey(entry.plan.settings) != credentials,
    )) {
      return _fail('上一个登录会话仍有未停止的房间，请先全部断开');
    }
    final existing = _sessions[room.id];
    if (existing != null) {
      if (existing.phase == RoomConnectionPhase.running) return _ok();
      return _fail('房间已有运行时，请先断开后重连');
    }
    if (_sessions.length >= maxConnections) {
      return _fail('已达到并行房间上限 $maxConnections');
    }
    var plan = ParallelRoomPlan(
      account,
      room,
      automatic: automatic,
      diagnosticsPort: preference.diagnosticsPort,
    );
    final firstPort = Uri.parse(plan.settings.diagnosticsUrl).port;
    for (
      var attempt = 0;
      _portConflict(plan, account) && attempt < 32;
      attempt++
    ) {
      plan = ParallelRoomPlan(
        account,
        room,
        automatic: automatic,
        diagnosticsPort: 40000 + (firstPort - 40000 + attempt + 1) % 20000,
      );
    }
    final conflict = _conflict(plan, account);
    if (conflict != null) return _fail(conflict);
    final entry = ParallelRoomSession(plan, runtimeFactory(plan));
    _sessions[room.id] = entry;
    _rememberRoom(
      plan,
      snapshot: null,
      replaceSnapshot: true,
      phase: RoomConnectionPhase.starting,
    );
    _notify();
    DaemonCommandResult started;
    try {
      await preferences.update(
        plan.profileId,
        wanted: automatic ? null : true,
        diagnosticsPort: Uri.parse(plan.settings.diagnosticsUrl).port,
      );
      started = _accepts(epoch, credentials)
          ? await entry.runtime.start()
          : _fail('登录状态已变化，连接已取消');
    } catch (error) {
      if (error is RoomConnectionStopped) {
        try {
          await preferences.update(plan.profileId, wanted: false);
        } catch (_) {
          /* Cleanup must still run. Server policy prevents automatic resume. */
        }
      }
      started = _fail(
        error is RoomException ? error.message : '房间启动失败，需要清理本地运行时',
      );
    }
    if (!started.ok || !_accepts(epoch, credentials)) {
      entry.phase = RoomConnectionPhase.failed;
      entry.message = started.ok
          ? '登录状态已变化，连接已取消'
          : (started.message.isEmpty ? '房间启动失败' : started.message);
      _rememberRoom(
        entry.plan,
        snapshot: entry.snapshot,
        replaceSnapshot: true,
        phase: entry.phase,
        message: entry.message,
      );
      final cleanup = await _disconnect(room.id);
      return cleanup.ok
          ? (started.ok ? _fail('登录状态已变化，连接已取消') : started)
          : cleanup;
    }
    await _refresh(entry);
    _schedulePoll();
    if (entry.phase != RoomConnectionPhase.running) {
      return _fail(entry.message ?? '房间进程已启动，但地址或路由尚未就绪；可重试状态检查或断开');
    }
    return started;
  }

  bool _portConflict(ParallelRoomPlan plan, AppSettings account) {
    final port = Uri.parse(plan.settings.diagnosticsUrl).port;
    return Uri.tryParse(account.diagnosticsUrl)?.port == port ||
        _sessions.values.any(
          (entry) => Uri.parse(entry.plan.settings.diagnosticsUrl).port == port,
        );
  }

  String? _conflict(ParallelRoomPlan plan, AppSettings account) {
    if (account.networkId == plan.room.id) return '此房间仍被主网络使用，请先切回个人网络';
    if (Uri.tryParse(account.diagnosticsUrl)?.port ==
        Uri.parse(plan.settings.diagnosticsUrl).port) {
      return '房间诊断端口与主网络配置冲突';
    }
    for (final session in _sessions.values) {
      final other = session.plan;
      if (cidrsOverlap(other.room.cidr, plan.room.cidr)) return '房间网段与已连接房间重叠';
      if (other.settings.diagnosticsUrl == plan.settings.diagnosticsUrl ||
          other.settings.tunInterface == plan.settings.tunInterface) {
        return '房间运行时资源标识冲突，未修改其他房间';
      }
    }
    return null;
  }

  Future<DaemonCommandResult> _disconnect(String id) async {
    final entry = _sessions[id];
    if (entry == null) return _ok();
    final previousSnapshot = entry.snapshot;
    final previousPhase = entry.phase;
    final previousMessage = entry.message;
    entry.revision++;
    entry.phase = RoomConnectionPhase.stopping;
    entry.snapshot = null;
    _notify();
    DaemonCommandResult result;
    try {
      result = await entry.runtime.stop();
    } catch (_) {
      result = _fail('无法确认房间运行时已停止');
    }
    if (result.ok) {
      _sessions.remove(id);
      final retainedFailure =
          previousPhase == RoomConnectionPhase.failed ||
          previousPhase == RoomConnectionPhase.unavailable;
      _rememberRoom(
        entry.plan,
        snapshot: previousSnapshot,
        replaceSnapshot: true,
        phase: retainedFailure
            ? previousPhase
            : RoomConnectionPhase.unavailable,
        message: retainedFailure ? previousMessage : '房间运行时已停止；保留本次实例日志供支持分析',
      );
      entry.runtime.close();
    } else {
      entry.phase = RoomConnectionPhase.failed;
      entry.message = previousMessage == null || previousMessage.isEmpty
          ? '停止失败，运行时仍被保留，请重试断开'
          : '$previousMessage；停止失败，运行时仍被保留，请重试断开';
      _rememberRoom(
        entry.plan,
        snapshot: previousSnapshot,
        replaceSnapshot: true,
        phase: entry.phase,
        message: entry.message,
      );
      lastError = entry.message;
    }
    if (_sessions.isEmpty) {
      _timer?.cancel();
      _timer = null;
      _scheduledInterval = null;
    } else {
      _schedulePoll();
    }
    _notify();
    return result;
  }

  Future<DaemonCommandResult> stopAll() {
    final pending = _stoppingAll;
    if (pending != null) return pending;
    final completer = Completer<DaemonCommandResult>();
    _stoppingAll = completer.future;
    _epoch++;
    unawaited(() async {
      try {
        await Future.wait(_operations.values.toList());
        final results = await Future.wait(
          _sessions.keys.toList().map(_disconnect),
        );
        final failed = results.any((result) => !result.ok);
        final forced = results.any((result) => result.forcedTermination);
        completer.complete(
          DaemonCommandResult(
            ok: !failed,
            message: failed ? '部分房间未能停止，请重试；尚未清除运行时记录' : '所有并行房间已停止',
            graceful:
                !failed &&
                !forced &&
                results.every((result) => result.graceful),
            forcedTermination: forced,
          ),
        );
      } catch (_) {
        completer.complete(_fail('关闭房间失败，尚未确认资源释放'));
      } finally {
        _stoppingAll = null;
        _notify();
      }
    }());
    return completer.future;
  }

  Future<void> recoverJoinedRooms() async {
    if (!supported || _disposed || _stoppingAll != null || connectionsPaused) {
      return;
    }
    final account = readSettings();
    if (account.authToken.trim().isEmpty) return;
    RoomApi? api;
    try {
      api = RoomApi(server: account.controlServer, token: account.authToken);
      final rooms = await api.list();
      if (_credentialKey(account) != _credentialKey(readSettings())) return;
      for (final room in rooms) {
        await recover(room);
        final preference = await connectionPreference(room);
        if (preference.autoConnect &&
            preference.wanted &&
            session(room.id) == null &&
            _credentialKey(account) == _credentialKey(readSettings())) {
          await connect(room, automatic: true);
        }
      }
    } catch (_) {
      lastError = '无法恢复房间运行时，请检查登录和控制服务器';
      _notify();
    } finally {
      api?.close();
    }
  }

  Future<void> recover(FriendRoom room) async {
    if (!supported ||
        _disposed ||
        _stoppingAll != null ||
        connectionsPaused ||
        _sessions.containsKey(room.id) ||
        !_recovering.add(room.id)) {
      return;
    }
    final epoch = _epoch;
    try {
      await _enqueue(room.id, () async {
        if (epoch != _epoch ||
            _sessions.containsKey(room.id) ||
            _stoppingAll != null ||
            connectionsPaused) {
          return _ok();
        }
        final account = readSettings();
        final initial = ParallelRoomPlan(account, room);
        final preference = await preferences.read(initial.profileId);
        if (_credentialKey(account) != _credentialKey(readSettings()) ||
            _stoppingAll != null ||
            connectionsPaused ||
            _disposed ||
            epoch != _epoch ||
            _sessions.containsKey(room.id)) {
          return _ok();
        }
        final plan = ParallelRoomPlan(
          account,
          room,
          diagnosticsPort: preference.diagnosticsPort,
        );
        if (_conflict(plan, account) != null ||
            _sessions.length >= maxConnections) {
          return _ok();
        }
        final runtime = runtimeFactory(plan);
        final entry = ParallelRoomSession(plan, runtime);
        _sessions[room.id] = entry;
        _rememberRoom(
          plan,
          snapshot: null,
          replaceSnapshot: true,
          phase: RoomConnectionPhase.starting,
        );
        try {
          if (!await runtime.exists()) {
            _sessions.remove(room.id);
            _rememberRoom(
              plan,
              snapshot: null,
              replaceSnapshot: true,
              phase: RoomConnectionPhase.unavailable,
              message: '未发现房间运行时；保留本次实例日志供支持分析',
            );
            runtime.close();
            return _ok();
          }
        } catch (_) {
          entry.phase = RoomConnectionPhase.failed;
          entry.message = '无法确认房间进程状态，请重试断开';
          _rememberRoom(
            plan,
            snapshot: null,
            replaceSnapshot: true,
            phase: entry.phase,
            message: entry.message,
          );
          return _fail(entry.message!);
        }
        if (_credentialKey(account) != _credentialKey(readSettings()) ||
            _stoppingAll != null) {
          return _disconnect(room.id);
        }
        await _refresh(entry);
        _schedulePoll();
        return _ok();
      });
    } finally {
      _recovering.remove(room.id);
      _notify();
    }
  }

  Future<void> _refresh(ParallelRoomSession entry) async {
    if (entry.refreshing || entry.phase == RoomConnectionPhase.stopping) return;
    entry.refreshing = true;
    final revision = entry.revision;
    try {
      final snapshot = await entry.runtime.status();
      if (_disposed ||
          revision != entry.revision ||
          !identical(_sessions[entry.plan.room.id], entry)) {
        return;
      }
      if (snapshot.networkId != entry.plan.room.id ||
          !validRoomIp(snapshot.virtualIp, entry.plan.room.cidr)) {
        throw const RoomException('房间运行时身份不匹配');
      }
      entry.snapshot = snapshot;
      entry.phase = RoomConnectionPhase.running;
      final runtime = entry.runtime;
      entry.message = runtime is RoomControlStatus
          ? (runtime as RoomControlStatus).controlWarning
          : null;
      _rememberRoom(
        entry.plan,
        snapshot: snapshot,
        replaceSnapshot: true,
        phase: entry.phase,
        message: entry.message,
      );
    } catch (error) {
      if (error is RoomConnectionStopped &&
          !_disposed &&
          revision == entry.revision &&
          identical(_sessions[entry.plan.room.id], entry)) {
        var message = error.message;
        try {
          await preferences.update(entry.plan.profileId, wanted: false);
        } catch (_) {
          message = '$message；无法保存本地自动连接设置';
        }
        entry.message = message;
        await _disconnect(entry.plan.room.id);
        lastError = message;
        return;
      }
      if (!_disposed &&
          revision == entry.revision &&
          identical(_sessions[entry.plan.room.id], entry)) {
        entry.snapshot = null;
        entry.phase = RoomConnectionPhase.unavailable;
        entry.message = '运行时或路由不可用；未显示过期的在线状态';
        _rememberRoom(
          entry.plan,
          snapshot: null,
          replaceSnapshot: true,
          phase: entry.phase,
          message: entry.message,
        );
      }
    } finally {
      entry.refreshing = false;
      _notify();
      _schedulePoll();
    }
  }

  bool _isPeerTransitional(PeerSnapshot p) {
    if (!p.online) return false;
    final state = p.state.toLowerCase();
    if (state.contains('connect') ||
        state.contains('handshake') ||
        state.contains('prob') ||
        state.contains('punch')) {
      return true;
    }
    if (p.path == 'probing' || p.path == 'direct_trial') return true;
    if (p.path == 'relay' && !p.isRelayVerified) return true;
    if (p.path == 'direct' && !p.isDirectVerified) return true;
    return false;
  }

  bool _isSessionTransitional(ParallelRoomSession entry) {
    if (entry.phase == RoomConnectionPhase.starting) return true;
    if (entry.phase == RoomConnectionPhase.running) {
      final snap = entry.snapshot;
      if (snap == null || snap.peerSnapshotStale) return true;
      final onlinePeers = snap.peers.where((p) => p.online);
      if (onlinePeers.any(_isPeerTransitional)) {
        return true;
      }
    }
    return false;
  }

  bool _hasTransitionalSession() {
    return _sessions.values.any(_isSessionTransitional);
  }

  Duration get _currentPollingInterval {
    if (refreshInterval <= Duration.zero) return Duration.zero;
    if (_hasTransitionalSession()) {
      return refreshInterval < const Duration(milliseconds: 500)
          ? refreshInterval
          : const Duration(milliseconds: 500);
    }
    return refreshInterval;
  }

  void _schedulePoll() {
    if (_disposed ||
        refreshInterval <= Duration.zero ||
        _sessions.isEmpty ||
        !hasListeners) {
      _timer?.cancel();
      _timer = null;
      _scheduledInterval = null;
      return;
    }
    final interval = _currentPollingInterval;
    if (_timer != null && _scheduledInterval == interval) {
      return;
    }
    _timer?.cancel();
    _scheduledInterval = interval;
    _timer = Timer(interval, _onPollTimer);
  }

  void _onPollTimer() {
    _timer = null;
    _scheduledInterval = null;
    if (_disposed || _sessions.isEmpty || !hasListeners) return;
    for (final entry in _sessions.values.toList()) {
      if (entry.phase != RoomConnectionPhase.stopping &&
          entry.phase != RoomConnectionPhase.failed) {
        unawaited(_refresh(entry));
      }
    }
    _schedulePoll();
  }

  @override
  void addListener(VoidCallback listener) {
    super.addListener(listener);
    _schedulePoll();
  }

  @override
  void removeListener(VoidCallback listener) {
    super.removeListener(listener);
    if (!hasListeners) {
      _timer?.cancel();
      _timer = null;
      _scheduledInterval = null;
    }
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _timer?.cancel();
    _timer = null;
    _scheduledInterval = null;
    unawaited(stopAll());
    super.dispose();
  }

  static DaemonCommandResult _ok() =>
      const DaemonCommandResult(ok: true, message: '完成', graceful: true);
  static DaemonCommandResult _fail(String message) =>
      DaemonCommandResult(ok: false, message: message);
}

bool cidrsOverlap(String left, String right) {
  (int, int)? range(String text) {
    final parts = text.split('/');
    if (parts.length != 2) return null;
    final ip = InternetAddress.tryParse(parts[0]);
    final prefix = int.tryParse(parts[1]);
    if (ip == null ||
        ip.type != InternetAddressType.IPv4 ||
        prefix == null ||
        prefix < 0 ||
        prefix > 32) {
      return null;
    }
    final address = ip.rawAddress.fold<int>(
      0,
      (value, byte) => (value << 8) | byte,
    );
    final mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) & 0xffffffff;
    final start = address & mask;
    return (start, start | (0xffffffff ^ mask));
  }

  final a = range(left);
  final b = range(right);
  return a == null || b == null || (a.$1 <= b.$2 && b.$1 <= a.$2);
}
