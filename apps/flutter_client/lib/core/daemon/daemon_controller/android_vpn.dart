part of '../daemon_controller.dart';

/// Flutter-side control surface for the Android VpnService + Rust daemon.
///
/// Android has no detached executable to launch. The platform service owns the
/// TUN permission and foreground lifecycle; the existing DiagnosticsApi still
/// remains the readiness/status contract for the UI.
// Build-time experiment switches keep the default APK on the existing
// AsyncFd/no-Wi-Fi-lock path while allowing GitHub Actions/device A/B builds
// to select the alternate implementation without adding UI state.
const _androidTunMode = String.fromEnvironment(
  'P2WLAN_ANDROID_TUN_MODE',
  defaultValue: 'async_fd',
);
const _androidWifiLowLatency = bool.fromEnvironment(
  'P2WLAN_ANDROID_WIFI_LOW_LATENCY',
  defaultValue: false,
);

extension DaemonControllerAndroidVpn on DaemonController {
  Future<DaemonCommandResult> _startAndroidVpn(AppSettings settings) async {
    // Stop a previous service/runtime first. This makes repeated starts safe
    // across hot restart, debug/release installs, and stale foreground
    // services holding the previous TUN fd.
    final stopped = await _stopAndroidVpn();
    if (!stopped.ok) {
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

    try {
      var requestJson = _androidRequestJson(settings);
      if (isRoomNetwork(settings.networkId)) {
        final transport = androidVpnTransport;
        if (transport is! AndroidRoomPreparingTransport) {
          throw const RoomException('当前 Android 原生组件不支持房间，请更新完整安装包');
        }
        final prepared = jsonDecode(
          await (transport as AndroidRoomPreparingTransport).prepareRoom(
            requestJson,
          ),
        );
        if (prepared is Map && prepared['error'] is String) {
          throw RoomException(switch (prepared['error']) {
            'room_device_pending' => '本机正在等待房主审批，批准后请重新连接',
            'room_device_blocked' => '本机已被禁止连接此房间，请解除限制后重试',
            'room_device_paused' => '本机已被远程断开，请重新手动连接',
            _ => '房间 IP 注册失败，请检查成员资格和设备权限',
          });
        }
        if (prepared is! Map ||
            prepared['error'] != null ||
            prepared['cidr'] is! String ||
            prepared['virtual_ip'] is! String ||
            prepared['cidr'] != settings.overlayCidr ||
            !validRoomIp(
              prepared['virtual_ip'] as String,
              prepared['cidr'] as String,
            )) {
          throw const RoomException('房间 IP 注册失败或地址已变化，请刷新房间后重新连接');
        }
        final request = jsonDecode(requestJson) as Map<String, dynamic>;
        request['virtual_ip'] = prepared['virtual_ip'];
        request['overlay_cidr'] = prepared['cidr'];
        requestJson = jsonEncode(request);
      }
      final started = await androidVpnTransport.start(requestJson);
      if (!started) {
        return const DaemonCommandResult(
          ok: false,
          message: 'Android VPN 服务拒绝启动请求。',
        );
      }
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
      if (settings.authToken.trim().isNotEmpty)
        'profile_id': managedNetworkProfileId(settings),
      'virtual_ip': settings.virtualIp,
      'manual_mode': false,
      'overlay_cidr': settings.overlayCidr,
      'mtu': settings.mtu,
      'udp_bind': settings.udpBind,
      'udp_advertise': settings.udpAdvertise,
      'relay_servers': settings.relayServers,
      'socket_pool': settings.socketPool,
      'diagnostics_bind': _androidDiagnosticsBind(settings.diagnosticsUrl),
      'android_tun_mode': _androidTunMode,
      'android_wifi_low_latency': _androidWifiLowLatency,
    });
  }

  @visibleForTesting
  Future<DaemonCommandResult> stopAndroidVpnForTesting() => _stopAndroidVpn();

  Future<DaemonCommandResult> _stopAndroidVpn() async {
    try {
      if (!await androidVpnTransport.stop()) {
        return const DaemonCommandResult(
          ok: false,
          message: 'Android VPN 未接受停止请求。',
        );
      }
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
      final bool nativeRunning;
      try {
        nativeRunning = (await androidVpnTransport.status()).nativeRunning;
      } catch (_) {
        return const DaemonCommandResult(
          ok: false,
          message: '无法确认旧 Android VPN 已停止，账号没有切换。',
        );
      }
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
      return await androidVpnTransport.prepareVpn();
    } catch (_) {
      return false;
    }
  }

  Future<bool> _androidNativeRunning() async {
    try {
      return (await androidVpnTransport.status()).nativeRunning;
    } catch (_) {
      return false;
    }
  }

  Future<String?> _androidNativeError() async {
    try {
      final value = (await androidVpnTransport.status()).nativeError
          ?.toString()
          .trim();
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
