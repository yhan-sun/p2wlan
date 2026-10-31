part of '../daemon_controller.dart';

extension DaemonControllerHarmonyVpn on DaemonController {
  static const _startTimeout = Duration(seconds: 45);
  static const _stopTimeout = Duration(seconds: 12);

  Future<DaemonCommandResult> _startHarmonyVpn(
    AppSettings settings,
    int? settingsRevision,
  ) async {
    if (settingsRevision == null || settingsRevision <= 0) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 配置版本无效，已拒绝启动。',
      );
    }
    if (isAuthTokenExpired(settings.authToken)) {
      return const DaemonCommandResult(
        ok: false,
        message: '登录状态已过期，请重新登录后再启动 Harmony VPN。',
      );
    }

    final previous = await _stopHarmonyVpn(allowMissing: true);
    if (!previous.ok) {
      return DaemonCommandResult(
        ok: false,
        message: '启动前无法确认旧 Harmony VPN 已停止：${previous.message}',
      );
    }

    final requestId = _newHarmonyVpnRequestId();
    try {
      await harmonyVpnTransport.start(requestId, settingsRevision);
    } on PlatformException catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 启动请求失败：${_safeHarmonyCode(error.code)}',
      );
    } on TimeoutException {
      return const DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 系统启动请求超时，当前启动状态未知；未确认网络已启动或已停止。',
      );
    } catch (_) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 启动请求失败。',
      );
    }

    final deadline = DateTime.now().add(_startTimeout);
    String? lastStatusCode;
    while (DateTime.now().isBefore(deadline)) {
      try {
        final status = await harmonyVpnTransport.status();
        if (status != null &&
            status.requestId == requestId &&
            status.operation == 'start' &&
            status.settingsRevision == settingsRevision) {
          switch (status.status) {
            case 'ready':
              return const DaemonCommandResult(
                ok: true,
                message: 'Harmony P2WLAN VPN 已就绪。',
              );
            case 'failed':
              return DaemonCommandResult(
                ok: false,
                message: 'Harmony VPN 启动失败（${status.code ?? 'unknown'}）。',
              );
            case 'stopped':
              return const DaemonCommandResult(
                ok: false,
                message: 'Harmony VPN 在报告就绪前已停止。',
              );
            case 'draining':
              return const DaemonCommandResult(
                ok: false,
                message: 'Harmony VPN 仍在排空，未确认启动完成。',
              );
            case 'starting':
            case 'stopping':
              break;
          }
        }
      } on VpnEngineStatusException catch (error) {
        lastStatusCode = error.code;
      } catch (_) {
        lastStatusCode = 'VPN_ENGINE_STATUS_QUERY_FAILED';
      }
      await Future<void>.delayed(DaemonController._readyPoll);
    }

    final cleanup = await _stopHarmonyVpn();
    final suffix = lastStatusCode == null ? '' : '（$lastStatusCode）';
    return DaemonCommandResult(
      ok: false,
      message: cleanup.ok
          ? '未收到本次 Harmony VPN 启动的就绪回执$suffix；已确认清理到停止状态。'
          : '未收到本次 Harmony VPN 启动的就绪回执$suffix，且无法确认清理完成：${cleanup.message}',
    );
  }

  Future<DaemonCommandResult> _stopHarmonyVpn({
    bool allowMissing = false,
  }) async {
    VpnEngineStatusSnapshot? current;
    try {
      current = await harmonyVpnTransport.status();
    } on VpnEngineStatusException catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: '无法读取 Harmony VPN 状态（${error.code}）。',
      );
    } catch (_) {
      return const DaemonCommandResult(
        ok: false,
        message: '无法读取 Harmony VPN 状态。',
      );
    }

    if (current == null) {
      return allowMissing
          ? const DaemonCommandResult(
              ok: true,
              message: '当前没有可确认的 Harmony VPN 会话。',
            )
          : const DaemonCommandResult(
              ok: false,
              message: '没有 Harmony VPN 状态快照，无法确认停止结果。',
            );
    }
    if (current.status == 'stopped') {
      return const DaemonCommandResult(
        ok: true,
        message: 'Harmony P2WLAN VPN 已停止。',
        graceful: true,
      );
    }
    if (current.status == 'draining' ||
        (current.operation == 'stop' && current.status == 'stopping')) {
      return _waitForHarmonyStop(current.requestId, current.settingsRevision);
    }

    final requestId = _newHarmonyVpnRequestId();
    try {
      await harmonyVpnTransport.stop(
        requestId: requestId,
        expectedStatusRequestId: current.requestId,
        settingsRevision: current.settingsRevision,
        afterStatusRevision: current.revision,
      );
    } on PlatformException catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 停止请求失败（${_safeHarmonyCode(error.code)}）。',
      );
    } on TimeoutException {
      return const DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 停止请求超时，当前状态未知；未确认网络已停止。',
      );
    } catch (_) {
      return const DaemonCommandResult(
        ok: false,
        message: 'Harmony VPN 停止请求失败。',
      );
    }
    return _waitForHarmonyStop(requestId, current.settingsRevision);
  }

  Future<DaemonCommandResult> _waitForHarmonyStop(
    String requestId,
    int settingsRevision,
  ) async {
    final deadline = DateTime.now().add(_stopTimeout);
    String? lastCode;
    while (DateTime.now().isBefore(deadline)) {
      try {
        final status = await harmonyVpnTransport.status();
        if (status != null &&
            status.requestId == requestId &&
            status.operation == 'stop' &&
            status.settingsRevision == settingsRevision) {
          if (status.status == 'stopped') {
            return const DaemonCommandResult(
              ok: true,
              message: 'Harmony P2WLAN VPN 已停止。',
              graceful: true,
            );
          }
          if (status.status == 'draining' || status.status == 'failed') {
            return DaemonCommandResult(
              ok: false,
              message: 'Harmony VPN 停止未完成（${status.code ?? status.status}）。',
            );
          }
        }
      } on VpnEngineStatusException catch (error) {
        lastCode = error.code;
      } catch (_) {
        lastCode = 'VPN_ENGINE_STATUS_QUERY_FAILED';
      }
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    final suffix = lastCode == null ? '' : '（$lastCode）';
    return DaemonCommandResult(
      ok: false,
      message: '停止请求已发出，但没有收到匹配的停止完成回执$suffix。',
    );
  }

  String _newHarmonyVpnRequestId() {
    final random = math.Random.secure();
    final entropy = List<String>.generate(
      16,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
      growable: false,
    ).join();
    return 'h-$entropy';
  }

  String _safeHarmonyCode(String value) =>
      RegExp(r'^[A-Za-z][A-Za-z0-9_]{0,63}$').hasMatch(value)
      ? value
      : 'VPN_ABILITY_REQUEST_FAILED';
}
