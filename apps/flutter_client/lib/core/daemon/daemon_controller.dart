import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../api/diagnostics_api.dart';
import '../models/diagnostics_models.dart';

part 'daemon_controller/process_control.dart';
part 'daemon_controller/elevation.dart';
part 'daemon_controller/diagnostics_paths.dart';
part 'daemon_controller/pids.dart';

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
  DaemonController({required DiagnosticsApi diagnosticsApi})
    : _diagnosticsApi = diagnosticsApi;

  static const daemonBinaryName = 'p2wlan-daemon';
  static const envDaemonBin = 'P2WLAN_DAEMON_BIN';
  static const _readyPoll = Duration(milliseconds: 400);
  static const _macosReadyTimeout = Duration(seconds: 60);
  static const _directReadyTimeout = Duration(seconds: 20);

  final DiagnosticsApi _diagnosticsApi;

  Future<DaemonCommandResult> start(AppSettings settings) async {
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    if (await _diagnosticsApi.fetchHealth(settings.diagnosticsUrl)) {
      return const DaemonCommandResult(
        ok: true,
        message: 'p2wlan-daemon is already running.',
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
      if (useManualMode) '--manual' else ...['--managed', '--token', authToken],
    ];

    await configPath.parent.create(recursive: true);
    await logDir.create(recursive: true);

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
      if (Platform.isMacOS && !_isRootUser()) {
        await _startMacosElevated(elevatedShell);
      } else if (Platform.isWindows && !await _isWindowsAdministrator()) {
        await _startWindowsElevated(binary: binary, args: args);
      } else if (Platform.isLinux && !_isRootUser()) {
        await _startLinuxElevated(binary: binary, args: args);
      } else {
        final process = await _startDetached(binary: binary, args: args);
        await _writePidMarker(pidPath, process.pid);
      }
    } catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: _startFailureMessage(error),
        manualCommand: manualCommand,
      );
    }

    final timeout = Platform.isMacOS ? _macosReadyTimeout : _directReadyTimeout;
    final ready = await _waitForHealth(
      settings.diagnosticsUrl,
      timeout,
      logPath,
    );
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
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    final statusPid = await _diagnosticsProcessId(diagnosticsUrl);
    final shutdownRequested = await _diagnosticsApi.requestShutdown(
      diagnosticsUrl,
    );
    if (shutdownRequested) {
      final endpointDown = await _waitForHealthDown(
        diagnosticsUrl,
        const Duration(seconds: 8),
      );
      final processDown =
          statusPid == null ||
          await _waitForDaemonPidExit(statusPid, const Duration(seconds: 3));
      if (endpointDown && processDown) {
        await _removePidMarker();
        return const DaemonCommandResult(
          ok: true,
          message: 'p2wlan-daemon stopped.',
        );
      }
    }

    final diagnosticsBind = _diagnosticsBindFromStatusUrl(diagnosticsUrl);
    final candidatePids = <int?>[
      statusPid,
      await _readVerifiedPid(),
      await _findDaemonPidByDiagnosticsBind(diagnosticsBind),
      await _findSingleDaemonPid(),
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
