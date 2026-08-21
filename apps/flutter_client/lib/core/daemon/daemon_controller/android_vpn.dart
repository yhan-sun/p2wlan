part of '../daemon_controller.dart';

/// Flutter-side control surface for the Android VpnService + Rust daemon.
///
/// Android has no detached executable to launch. The platform service owns the
/// TUN permission and foreground lifecycle; the existing DiagnosticsApi still
/// remains the readiness/status contract for the UI.
const _androidVpnChannel = MethodChannel('p2wlan/android_vpn');
const _androidProvisionalVirtualIp = '10.20.0.1';

extension DaemonControllerAndroidVpn on DaemonController {
  Future<DaemonCommandResult> _startAndroidVpn(AppSettings settings) async {
    // Stop a previous service/runtime first. This makes repeated starts safe
    // across hot restart, debug/release installs, and stale foreground
    // services holding the previous TUN fd.
    final stopped = await _stopAndroidVpn(settings.diagnosticsUrl);
    if (!stopped.ok && await _androidNativeRunning()) {
      return DaemonCommandResult(
        ok: false,
        message: '检测到旧的 Android VPN 实例，但在启动新实例前无法停止：${stopped.message}',
      );
    }

    final permissionGranted = await _prepareAndroidVpn();
    if (!permissionGranted) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Android VPN 权限未授予。请在系统弹窗中允许 P2WLAN 建立 VPN。',
      );
    }

    final requestJson = _androidRequestJson(settings);

    try {
      await _androidVpnChannel.invokeMethod<bool>('start', {
        'requestJson': requestJson,
      });
    } on PlatformException catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: error.message ?? 'Android VPN 启动失败。',
      );
    } catch (error) {
      return DaemonCommandResult(ok: false, message: 'Android VPN 启动失败：$error');
    }

    final ready = await _waitForAndroidHealth(
      settings.diagnosticsUrl,
      const Duration(seconds: 30),
    );
    if (!ready) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Android VPN 服务已启动，但 Rust 本地 daemon 未在 30 秒内就绪。请查看本地诊断日志。',
      );
    }

    // On a first managed start the control plane may assign a VIP only after
    // the native daemon has registered. Re-establish the Android VPN with
    // that real address; otherwise the system interface would keep the
    // provisional 10.20.0.1 while Rust correctly expects the assigned VIP.
    final assignedVirtualIp = await _androidAssignedVirtualIp(
      settings.diagnosticsUrl,
    );
    final requestedVirtualIp = settings.virtualIp.trim().isEmpty
        ? _androidProvisionalVirtualIp
        : settings.virtualIp.trim();
    if (assignedVirtualIp != null &&
        assignedVirtualIp != requestedVirtualIp) {
      final rebound = await _restartAndroidVpnWithVirtualIp(
        settings,
        assignedVirtualIp,
      );
      if (!rebound.ok) return rebound;
    }

    return const DaemonCommandResult(
      ok: true,
      message: 'Android P2WLAN VPN 已启动。',
    );
  }

  String _androidRequestJson(AppSettings settings, {String? virtualIp}) {
    return jsonEncode({
      'control_server': settings.controlServer,
      'network_id': settings.networkId.trim().isEmpty
          ? defaultNetworkId
          : settings.networkId.trim(),
      'auth_token': settings.authToken,
      'device_name': settings.deviceName,
      'virtual_ip': virtualIp ?? settings.virtualIp,
      'manual_mode': settings.manualMode,
      'overlay_cidr': settings.overlayCidr,
      'mtu': settings.mtu,
      'udp_bind': settings.udpBind,
      'udp_advertise': settings.udpAdvertise,
      'relay_servers': settings.relayServers,
      'socket_pool': settings.socketPool,
      'diagnostics_bind': _androidDiagnosticsBind(settings.diagnosticsUrl),
    });
  }

  Future<DaemonCommandResult> _restartAndroidVpnWithVirtualIp(
    AppSettings settings,
    String virtualIp,
  ) async {
    final stopped = await _stopAndroidVpn(settings.diagnosticsUrl);
    if (!stopped.ok) return stopped;
    if (!await _prepareAndroidVpn()) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Android VPN 权限已失效，无法按已分配的虚拟 IP 重建 VPN。',
      );
    }
    try {
      await _androidVpnChannel.invokeMethod<bool>('start', {
        'requestJson': _androidRequestJson(settings, virtualIp: virtualIp),
      });
    } on PlatformException catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: error.message ?? 'Android VPN 启动失败。',
      );
    } catch (error) {
      return DaemonCommandResult(ok: false, message: 'Android VPN 启动失败：$error');
    }

    final ready = await _waitForAndroidHealth(
      settings.diagnosticsUrl,
      const Duration(seconds: 30),
    );
    if (!ready) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Android VPN 服务已启动，但 Rust 本地 daemon 未在 30 秒内就绪。请查看本地诊断日志。',
      );
    }
    return const DaemonCommandResult(
      ok: true,
      message: 'Android P2WLAN VPN 已启动。',
    );
  }

  Future<DaemonCommandResult> _stopAndroidVpn(String diagnosticsUrl) async {
    try {
      await _androidVpnChannel.invokeMethod<bool>('stop');
    } on PlatformException catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: error.message ?? 'Android VPN 停止失败。',
      );
    } catch (error) {
      return DaemonCommandResult(ok: false, message: 'Android VPN 停止失败：$error');
    }

    final deadline = DateTime.now().add(const Duration(seconds: 10));
    while (DateTime.now().isBefore(deadline)) {
      final nativeRunning = await _androidNativeRunning();
      final health = await _diagnosticsApi.fetchHealth(diagnosticsUrl);
      if (!nativeRunning && !health) {
        return const DaemonCommandResult(
          ok: true,
          message: 'Android P2WLAN VPN 已停止。',
        );
      }
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return const DaemonCommandResult(
      ok: false,
      message: 'Android VPN 正在停止，但旧 daemon 仍未完全退出。',
    );
  }

  Future<bool> _prepareAndroidVpn() async {
    try {
      return await _androidVpnChannel.invokeMethod<bool>('prepareVpn') ?? false;
    } catch (_) {
      return false;
    }
  }

  Future<bool> _androidNativeRunning() async {
    try {
      final status = await _androidVpnChannel
          .invokeMethod<Map<Object?, Object?>>('status');
      return status?['nativeRunning'] == true;
    } catch (_) {
      return false;
    }
  }

  Future<bool> _waitForAndroidHealth(
    String diagnosticsUrl,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      if (!await _androidNativeRunning()) {
        // The service can be alive while Rust exits during startup. Give the
        // endpoint one final read before reporting failure.
        await Future<void>.delayed(const Duration(milliseconds: 250));
        return _diagnosticsApi.fetchHealth(diagnosticsUrl);
      }
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  Future<String?> _androidAssignedVirtualIp(String diagnosticsUrl) async {
    for (var attempt = 0; attempt < 6; attempt++) {
      try {
        final snapshot = await _diagnosticsApi.fetchStatus(diagnosticsUrl);
        final virtualIp = snapshot.virtualIp.trim();
        if (virtualIp.isNotEmpty) return virtualIp;
      } catch (_) {
        // The diagnostics listener and its per-process token can become
        // visible a fraction later than /health during the first start.
      }
      await Future<void>.delayed(const Duration(milliseconds: 400));
    }
    return null;
  }

  String _androidDiagnosticsBind(String diagnosticsUrl) {
    final uri = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    final host = uri.host.contains(':') ? '[${uri.host}]' : uri.host;
    return '$host:${uri.port}';
  }
}
