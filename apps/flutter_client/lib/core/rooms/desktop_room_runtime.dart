import '../api/diagnostics_api.dart';
import '../daemon/daemon_controller.dart';
import '../daemon/diagnostics_auth.dart';
import '../models/diagnostics_models.dart';
import 'parallel_rooms.dart';
import 'room_api.dart';

class DesktopRoomRuntime implements RoomRuntime, RoomControlStatus {
  DesktopRoomRuntime(
    this.plan, {
    DiagnosticsApi? diagnosticsApi,
    DaemonController? daemonController,
    this._hasCredentials,
    this._checkRoutes,
    this.controlApiFactory,
  }) {
    _api =
        diagnosticsApi ??
        DiagnosticsApi(
          authTokenReader: () => readRoomDiagnosticsAuthToken(plan.profileId),
        );
    _daemon =
        daemonController ??
        DaemonController(diagnosticsApi: _api, roomInstanceId: plan.profileId);
  }

  final RoomApi Function()? controlApiFactory;
  final ParallelRoomPlan plan;
  late final DiagnosticsApi _api;
  late final DaemonController _daemon;
  final Future<bool> Function()? _hasCredentials;
  final Future<String?> Function(String)? _checkRoutes;

  Future<bool> _credentialsExist() async => _hasCredentials != null
      ? await _hasCredentials()
      : await readRoomDiagnosticsAuthToken(plan.profileId) != null;

  @override
  Future<bool> exists() => _daemon.hasRoomRuntime();

  @override
  Future<DaemonCommandResult> start() async {
    if (await _api.fetchHealth(plan.settings.diagnosticsUrl) &&
        !await _credentialsExist()) {
      return const DaemonCommandResult(
        ok: false,
        message: '房间诊断端口被其他进程占用，未停止任何进程。',
      );
    }
    if (await _credentialsExist() || await exists()) {
      try {
        final snapshot = await _api.fetchStatus(plan.settings.diagnosticsUrl);
        if (snapshot.networkId != plan.room.id) {
          return const DaemonCommandResult(
            ok: false,
            message: '房间诊断实例身份不匹配，未修改现有连接',
          );
        }
      } catch (_) {
        // stop() also verifies the per-profile PID and exact process arguments.
      }
      final stopped = await _daemon.stop(plan.settings.diagnosticsUrl);
      if (!stopped.ok) {
        return DaemonCommandResult(
          ok: false,
          message: '此房间的旧连接未能退出：${stopped.message}',
        );
      }
    }
    final conflict = _checkRoutes != null
        ? await _checkRoutes(plan.room.cidr)
        : await _daemon.roomRouteConflict(plan.room.cidr);
    if (conflict != null) {
      return DaemonCommandResult(ok: false, message: conflict);
    }
    await _requestAccess(resume: !plan.automatic);
    final result = await _daemon.start(plan.settings);
    // A first registration can create a pending approval before it has an IP.
    // Surface that decision instead of the generic daemon startup timeout.
    if (!result.ok) await _requestAccess(resume: false);
    return result;
  }

  @override
  Future<DaemonCommandResult> stop() =>
      _daemon.stop(plan.settings.diagnosticsUrl);

  @override
  Future<DiagnosticsSnapshot> status() async {
    await _checkRemoteAccess();
    final snapshot = await _api.fetchStatus(plan.settings.diagnosticsUrl);
    if (snapshot.networkId != plan.room.id ||
        !validRoomIp(snapshot.virtualIp, plan.room.cidr)) {
      throw const RoomException('房间运行时身份或地址不匹配');
    }
    final routes = await _api.verifyRoutes(plan.settings.diagnosticsUrl);
    if (!routes.healthy) throw const RoomException('房间路由未通过校验');
    return snapshot;
  }

  DateTime? _lastAccessCheck;
  String? _controlWarning;
  @override
  String? get controlWarning => _controlWarning;

  Future<void> _requestAccess({required bool resume}) async {
    if (!plan.room.deviceControls) return;
    final identity = await _daemon.roomDeviceIdentity(plan.settings);
    if (identity == null) return;
    final api =
        controlApiFactory?.call() ??
        RoomApi(
          server: plan.settings.controlServer,
          token: plan.settings.authToken,
        );
    try {
      await api.request(
        'POST',
        [plan.room.id, 'device-access'],
        {
          'public_key': identity['public_key'],
          'device_name': identity['device_name'],
          'platform': identity['platform'],
          'resume': resume,
        },
      );
    } on RoomException catch (error) {
      if (const [
        'room_device_paused',
        'room_device_blocked',
        'room_device_pending',
        'room_access',
      ].contains(error.code)) {
        throw RoomConnectionStopped(error.message);
      }
      rethrow;
    } finally {
      api.close();
    }
  }

  Future<void> _checkRemoteAccess() async {
    if (!plan.room.deviceControls) return;
    final now = DateTime.now();
    if (_lastAccessCheck != null &&
        now.difference(_lastAccessCheck!) < const Duration(seconds: 2)) {
      return;
    }
    _lastAccessCheck = now;
    RoomApi? api;
    try {
      final identity = await _daemon.roomDeviceIdentity(plan.settings);
      if (identity == null) {
        _controlWarning = '无法读取本机设备身份；房间访问仍由本地服务校验。';
        return;
      }
      api =
          controlApiFactory?.call() ??
          RoomApi(
            server: plan.settings.controlServer,
            token: plan.settings.authToken,
            requestTimeout: const Duration(seconds: 2),
          );
      final roster = await api.roster(plan.room.id);
      for (final access in roster.deviceAccess) {
        if (access['public_key'] != identity['public_key']) continue;
        if (access['state'] != 'allowed') {
          throw RoomConnectionStopped(switch (access['state']) {
            'blocked' => '本机已被禁止连接此房间',
            'pending' => '本机正在等待房主审批',
            _ => '本机已被远程断开，请手动重新连接',
          });
        }
      }
      _controlWarning = null;
    } on RoomConnectionStopped {
      rethrow;
    } on RoomException catch (error) {
      if (error.code == 'room_access') {
        throw const RoomConnectionStopped('该账号已退出或被移出房间，本机连接已停止');
      }
      _controlWarning = error.code == 'auth_expired'
          ? '登录已过期，暂时无法管理房间，请重新登录。'
          : '暂时无法从控制服务器同步房间权限；本地连接状态独立检查，授权过期后会暂停通信。';
    } catch (_) {
      _controlWarning = '暂时无法从控制服务器同步房间权限；本地连接状态独立检查，授权过期后会暂停通信。';
    } finally {
      api?.close();
    }
  }

  @override
  void close() => _api.close();
}
