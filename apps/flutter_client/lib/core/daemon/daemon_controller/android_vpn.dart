part of '../daemon_controller.dart';

/// Flutter-side control surface for the Android VpnService + Rust daemon.
///
/// Android has no detached executable to launch. The platform service owns the
/// TUN permission and foreground lifecycle; the existing DiagnosticsApi still
/// remains the readiness/status contract for the UI.
const _androidVpnChannel = MethodChannel('p2wlan/android_vpn');

extension DaemonControllerAndroidVpn on DaemonController {
  Future<DaemonCommandResult> _startAndroidVpn(AppSettings settings) async {
    if (!settings.manualMode && isAuthTokenExpired(settings.authToken)) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Android VPN 启动失败：登录状态已过期，请重新登录。',
      );
    }
    // Stop a previous service/runtime first. This makes repeated starts safe
    // across hot restart, debug/release installs, and stale foreground
    // services holding the previous TUN fd.
    final stopped = await _stopAndroidVpn();
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
      final nativeError = await _androidNativeError();
      // A failed readiness wait used to leave the foreground VPN/TUN alive.
      // The next start then raced the old registration loop and appeared to
      // work only after the user manually disabled TUN in Android settings.
      // Always tear down the failed attempt before returning the error.
      await _stopAndroidVpn();
      return DaemonCommandResult(
        ok: false,
        message: nativeError == null
            ? 'Android VPN 服务已启动，但 Rust 本地 daemon 未在 30 秒内就绪。请查看本地诊断日志。'
            : 'Android VPN 启动失败：$nativeError',
      );
    }

    return const DaemonCommandResult(
      ok: true,
      message: 'Android P2WLAN VPN 已启动。',
    );
  }

  String _androidRequestJson(AppSettings settings) {
    return jsonEncode({
      'control_server': settings.controlServer,
      'network_id': settings.networkId.trim().isEmpty
          ? defaultNetworkId
          : settings.networkId.trim(),
      'auth_token': settings.authToken,
      'device_name': settings.deviceName,
      'virtual_ip': settings.virtualIp,
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

  Future<DaemonCommandResult> _stopAndroidVpn() async {
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
      // The native runtime is the owner of the detached VPN fd. Once it has
      // stopped, a briefly stale HTTP health response must not block a new
      // VpnService start; requiring both states caused needless 10-second
      // waits and made the manual TUN toggle look like the fix.
      if (!nativeRunning) {
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

  Future<String?> _androidNativeError() async {
    try {
      final status = await _androidVpnChannel
          .invokeMethod<Map<Object?, Object?>>('status');
      final value = status?['nativeError']?.toString().trim();
      return value == null || value.isEmpty ? null : value;
    } catch (_) {
      return null;
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

  String _androidDiagnosticsBind(String diagnosticsUrl) {
    final uri = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    final host = uri.host.contains(':') ? '[${uri.host}]' : uri.host;
    return '$host:${uri.port}';
  }
}
