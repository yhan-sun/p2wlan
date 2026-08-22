import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/services.dart';

import '../api/diagnostics_api.dart';
import '../models/diagnostics_models.dart';

part 'daemon_controller/process_control.dart';
part 'daemon_controller/elevation.dart';
part 'daemon_controller/diagnostics_paths.dart';
part 'daemon_controller/launch_token.dart';
part 'daemon_controller/pids.dart';
part 'daemon_controller/android_vpn.dart';

class DaemonCommandResult {
  const DaemonCommandResult({
    required this.ok,
    required this.message,
    this.manualCommand,
  });

  final bool ok;
  final String message;
  final String? manualCommand;
}

class DaemonController {
  DaemonController({
    required DiagnosticsApi diagnosticsApi,
    this.readMacosAdminPassword,
    this.saveMacosAdminPassword,
    this.clearMacosAdminPassword,
  }) : _diagnosticsApi = diagnosticsApi;

  static const daemonBinaryName = 'p2wlan-daemon';
  static const envDaemonBin = 'P2WLAN_DAEMON_BIN';
  static const _readyPoll = Duration(milliseconds: 400);
  static const _macosReadyTimeout = Duration(seconds: 60);
  static const _directReadyTimeout = Duration(seconds: 20);

  final DiagnosticsApi _diagnosticsApi;

  /// These callbacks are supplied by [SettingsStore] for the normal app
  /// path. Keeping them as callbacks also lets the PID cleanup path reuse the
  /// same config-file credential without reading Keychain or another broker.
  final String? Function()? readMacosAdminPassword;
  final Future<void> Function(String password)? saveMacosAdminPassword;
  final Future<void> Function()? clearMacosAdminPassword;

  DateTime? _lastLaunchExitProbeAt;
  bool? _lastLaunchExitProbeResult;

  Future<DaemonCommandResult> start(AppSettings settings) async {
    if (Platform.isAndroid) return _startAndroidVpn(settings);
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    final binary = await _resolveDaemonBinary();
    if (binary == null) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'Could not find p2wlan-daemon. Build it with cargo or set P2WLAN_DAEMON_BIN.',
      );
    }

    final windowsProbeError = await _probeWindowsDaemonBinary(binary);
    if (windowsProbeError != null) {
      return DaemonCommandResult(
        ok: false,
        message: 'Windows 守护进程无法加载，发布包可能缺少运行库或文件不完整：$windowsProbeError',
      );
    }

    // A stale daemon can keep /health returning 200 after its TUN/dataplane
    // has failed.  Do not treat the liveness endpoint as proof that the
    // instance is reusable: clean up the verified old daemon first, then
    // launch the binary selected above.  This also handles a daemon left by
    // an older Debug/Release app bundle on the same diagnostics port.
    if (await _hasExistingDaemonForStart(settings.diagnosticsUrl)) {
      final stopped = await stop(settings.diagnosticsUrl);
      if (!stopped.ok) {
        return DaemonCommandResult(
          ok: false,
          message: '检测到旧 p2wlan-daemon，但启动新实例前无法停止它：${stopped.message}',
        );
      }
    }

    final bind = _diagnosticsBindFromStatusUrl(settings.diagnosticsUrl);
    final configPath = _defaultConfigPath();
    final logDir = _defaultLogDir();
    final logPath = '${logDir.path}${Platform.pathSeparator}p2wlan-daemon.log';
    final pidPath = '${logDir.path}${Platform.pathSeparator}p2wlan-daemon.pid';
    final authToken = settings.authToken.trim();
    final deviceName = settings.deviceName.trim();
    final useManualMode = settings.manualMode || authToken.isEmpty;
    final udpAdvertise = settings.udpAdvertise.trim();
    final relayServers = settings.relayServers.trim();

    final requiresElevation =
        Platform.isMacOS && !_isRootUser() ||
        Platform.isWindows && !await _isWindowsAdministrator() ||
        Platform.isLinux && !_isRootUser();
    final windowsClientSid = Platform.isWindows
        ? await _windowsCurrentUserSid()
        : null;
    File? tokenFile;
    // Windows console daemons cannot safely receive a managed token over a
    // detached stdin: depending on the Windows process mode this can create
    // a console window even when the Flutter app itself is GUI-only. Use the
    // same one-shot protected file for both elevated and already-elevated
    // Windows launches. It also makes the two Windows launch paths behave
    // identically, which prevents a second fallback process from being
    // started after UAC succeeds.
    if (!useManualMode && (requiresElevation || Platform.isWindows)) {
      try {
        tokenFile = await createEphemeralLaunchTokenFile(logDir, authToken);
      } catch (error) {
        return DaemonCommandResult(
          ok: false,
          message: _startFailureMessage(error),
        );
      }
    } else if (Platform.isWindows) {
      try {
        // Manual/offline mode has no launch token, but an elevated daemon
        // still needs the same user/admin ACL on the runtime directory for
        // its log, PID marker, and diagnostics session file.
        await protectRuntimeDirectory(logDir);
      } catch (error) {
        return DaemonCommandResult(
          ok: false,
          message: _startFailureMessage(error),
        );
      }
    }

    final args = [
      '--config',
      configPath.path,
      '--control',
      settings.controlServer,
      '--network',
      settings.networkId.trim().isEmpty
          ? defaultNetworkId
          : settings.networkId.trim(),
      '--diagnostics-bind',
      bind,
      '--log-file',
      logPath,
      if (deviceName.isNotEmpty) ...['--device-name', deviceName],
      if (settings.virtualIp.trim().isNotEmpty) ...[
        '--address',
        settings.virtualIp.trim(),
      ],
      '--interface',
      settings.effectiveTunInterface,
      '--mtu',
      settings.mtu.toString(),
      '--udp-bind',
      settings.udpBind.trim().isEmpty
          ? defaultUdpBind
          : settings.udpBind.trim(),
      if (udpAdvertise.isNotEmpty) ...['--udp-advertise', udpAdvertise],
      if (settings.socketPool.trim().isNotEmpty) ...[
        '--socket-pool',
        settings.socketPool.trim(),
      ],
      if (relayServers.isNotEmpty) ...['--relay', relayServers],
      if (windowsClientSid != null) ...[
        '--diagnostics-client-sid',
        windowsClientSid,
      ],
      if (useManualMode)
        '--manual'
      else if (tokenFile != null) ...[
        '--managed',
        '--token-file',
        tokenFile.path,
      ] else ...[
        '--managed',
        '--token-stdin',
      ],
    ];

    await configPath.parent.create(recursive: true);
    await logDir.create(recursive: true);
    // Pre-create the log as the interactive user.  Elevated macOS/Windows
    // launches must append to this file rather than creating a root/admin-owned
    // file that the Flutter UI cannot read for startup diagnostics.
    await File(logPath).create(recursive: true);

    final elevatedShell = _buildElevatedShell(
      binary: binary,
      args: args,
      configDir: configPath.parent,
      logDir: logDir,
      logPath: logPath,
      pidPath: pidPath,
    );
    // Managed launches include an auth token. Never expose a token-bearing
    // command in UI error messages or the clipboard.
    final manualCommand = useManualMode
        ? _manualCommandForPlatform(
            elevatedShell: elevatedShell,
            binary: binary,
            args: args,
          )
        : null;

    try {
      if (requiresElevation && Platform.isMacOS) {
        await _startMacosElevated(
          elevatedShell,
          password: settings.macosAdminPassword,
        );
      } else if (requiresElevation && Platform.isWindows) {
        await _startWindowsElevated(
          binary: binary,
          args: args,
          pidPath: pidPath,
        );
      } else if (requiresElevation && Platform.isLinux) {
        await _startLinuxElevated(binary: binary, args: args);
      } else {
        final process = await _startDetached(
          binary: binary,
          args: args,
          stdinToken: tokenFile == null && !useManualMode ? authToken : null,
        );
        await _writePidMarker(pidPath, process.pid);
      }
    } catch (error) {
      // The launch itself failed: never leave the temporary credential file
      // behind.
      try {
        await deleteEphemeralLaunchTokenFile(tokenFile);
      } catch (_) {}
      return DaemonCommandResult(
        ok: false,
        message: _startFailureMessage(error),
        manualCommand: manualCommand,
      );
    }

    // The daemon reads the token synchronously at startup, so once the
    // diagnostics endpoint is up (or the launch has failed/timed out) the
    // temporary credential file is no longer needed. Delete it now so no
    // long-lived plaintext token file persists, and always clean it up on
    // failure/timeout below.
    _lastLaunchExitProbeAt = null;
    _lastLaunchExitProbeResult = null;
    final timeout = Platform.isMacOS ? _macosReadyTimeout : _directReadyTimeout;
    final ready = await _waitForHealth(
      settings.diagnosticsUrl,
      timeout,
      logPath,
    );
    try {
      await deleteEphemeralLaunchTokenFile(tokenFile);
    } catch (_) {}
    if (!ready) {
      // A daemon that exited right after an elevated launch usually failed
      // for a definitive, actionable reason.  Detect a permanent control
      // auth failure (expired token / revoked credential) from the log tail
      // and surface it immediately instead of a generic "TUN failed" wait.
      if (await _logShowsPermanentAuthFailure(logPath)) {
        return DaemonCommandResult(
          ok: false,
          message: '登录已过期，请重新登录。后台 p2wlan-daemon 因认证失败退出，启动过程未创建虚拟网卡。',
          manualCommand: manualCommand,
        );
      }
      if (Platform.isWindows && await _logShowsWintunMissing(logPath)) {
        return DaemonCommandResult(
          ok: false,
          message:
              'Windows 运行组件缺失：找不到 wintun.dll。请重新安装包含 Wintun 的 P2WLAN 安装包，或把 wintun.dll 放到 p2wlan-daemon.exe 同级目录。',
          manualCommand: manualCommand,
        );
      }
      return DaemonCommandResult(
        ok: false,
        message:
            '已完成启动授权，但 p2wlan-daemon 没有在 ${timeout.inSeconds} 秒内响应诊断端点。请查看日志：$logPath',
        manualCommand: manualCommand,
      );
    }
    return DaemonCommandResult(
      ok: true,
      message: useManualMode
          ? 'p2wlan-daemon started in manual/offline mode. Add a control token in Settings to join the managed P2WLAN network.'
          : 'p2wlan-daemon started.',
    );
  }

  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    if (Platform.isAndroid) return _stopAndroidVpn();
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    // The Windows start path already performs one verified WMI scan. Reuse
    // the same cheap process identity check here instead of forcing a full
    // /status snapshot (which can be the slowest endpoint when peer locks are
    // busy). Fall back to /status only when WMI returned no safe candidate.
    final windowsDaemonPids = Platform.isWindows
        ? await _findWindowsDaemonPids()
        : const <int>[];
    final statusPid = Platform.isWindows && windowsDaemonPids.isNotEmpty
        ? null
        : await _diagnosticsProcessId(diagnosticsUrl);
    final shutdownRequested = await _diagnosticsApi.requestShutdown(
      diagnosticsUrl,
    );
    if (shutdownRequested) {
      final endpointDown = await _waitForHealthDown(
        diagnosticsUrl,
        const Duration(seconds: 8),
      );
      final processDown = Platform.isWindows && windowsDaemonPids.isNotEmpty
          ? await _waitForWindowsDaemonPidsExit(
              windowsDaemonPids,
              const Duration(seconds: 3),
            )
          : statusPid == null ||
                await _waitForDaemonPidExit(
                  statusPid,
                  const Duration(seconds: 3),
                );
      if (endpointDown && processDown) {
        await _removePidMarker();
        return const DaemonCommandResult(
          ok: true,
          message: 'p2wlan-daemon stopped.',
        );
      }
    }

    final candidatePids = <int?>[
      statusPid,
      await _readVerifiedPid(),
      if (Platform.isWindows) ...[
        ...(windowsDaemonPids.isNotEmpty
            ? windowsDaemonPids
            : await _findWindowsDaemonPids()),
      ] else ...[
        await _findDaemonPidByDiagnosticsBind(
          _diagnosticsBindFromStatusUrl(diagnosticsUrl),
        ),
        await _findSingleDaemonPid(),
      ],
    ];
    final attempted = <int>{};
    for (final pid in candidatePids.whereType<int>()) {
      if (!attempted.add(pid)) continue;
      if (!await _processLooksLikeDaemon(pid)) continue;
      if (!await _terminatePid(pid)) continue;
      final processDown = await _waitForDaemonPidExit(
        pid,
        const Duration(seconds: 3),
      );
      final stopped = await _waitForHealthDown(
        diagnosticsUrl,
        const Duration(seconds: 5),
      );
      if (stopped && processDown) {
        await _removePidMarker();
        return DaemonCommandResult(ok: true, message: 'p2wlan-daemon stopped.');
      }
    }

    final knownPids = [statusPid, ...attempted].whereType<int>();
    final knownProcessesDown = !await _anyDaemonPidStillRunning(knownPids);
    if (!await _diagnosticsApi.fetchHealth(diagnosticsUrl) &&
        knownProcessesDown) {
      await _removePidMarker();
      return const DaemonCommandResult(
        ok: true,
        message: 'p2wlan-daemon stopped.',
      );
    }

    if (attempted.isEmpty) {
      return DaemonCommandResult(
        ok: false,
        message: shutdownRequested
            ? 'Requested daemon shutdown, but diagnostics is still reachable and no safe p2wlan-daemon PID could be found.'
            : 'Could not stop p2wlan-daemon: diagnostics is reachable but no safe p2wlan-daemon PID could be found.',
      );
    }

    return DaemonCommandResult(
      ok: false,
      message:
          'Tried to stop p2wlan-daemon PID(s) ${attempted.join(', ')}, but diagnostics is still reachable.',
    );
  }
}
