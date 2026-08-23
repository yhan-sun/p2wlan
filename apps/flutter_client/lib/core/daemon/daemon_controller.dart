import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/services.dart';

import '../api/diagnostics_api.dart';
import '../build_info.dart';
import '../capabilities/permission_preflight.dart';
import '../models/diagnostics_models.dart';

part 'daemon_controller/process_control.dart';
part 'daemon_controller/elevation.dart';
part 'daemon_controller/diagnostics_paths.dart';
part 'daemon_controller/launch_token.dart';
part 'daemon_controller/pids.dart';
part 'daemon_controller/android_vpn.dart';
part 'daemon_controller/startup_trace.dart';

class DaemonCommandResult {
  const DaemonCommandResult({
    required this.ok,
    required this.message,
    this.manualCommand,
    this.failureCode,
  });

  final bool ok;
  final String message;
  final String? manualCommand;
  final DaemonStartupFailureCode? failureCode;
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
  DaemonBuildInfo? _lastDaemonBuildInfo;

  ClientBuildInfo get clientBuildInfo => ClientBuildInfo.current;
  DaemonBuildInfo? get lastDaemonBuildInfo => _lastDaemonBuildInfo;
  String get clientLogPath =>
      '${_defaultLogDir().path}${Platform.pathSeparator}${WindowsStartupTrace.fileName}';
  String get daemonLogPath =>
      '${_defaultLogDir().path}${Platform.pathSeparator}p2wlan-daemon.log';

  Future<DaemonCommandResult> start(AppSettings settings) async {
    if (Platform.isAndroid) return _startAndroidVpn(settings);
    _lastDaemonBuildInfo = null;
    final startupTrace = Platform.isWindows
        ? WindowsStartupTrace(_defaultLogDir())
        : null;
    if (startupTrace != null) {
      await startupTrace.open();
      await startupTrace.startRequested();
      try {
        final preflight = await runPermissionPreflight();
        await startupTrace.detail(
          'permission preflight state=${preflight.state.name} '
          'reason=${preflight.reasonCode} '
          'can_create_tun=${preflight.canCreateTunLabel} '
          'can_modify_routes=${preflight.canModifyRoutesLabel}',
        );
      } catch (_) {
        await startupTrace.detail('permission preflight unavailable');
      }
    }
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    await startupTrace?.stageStart(1, 'resolve_daemon');
    final binary = await _resolveDaemonBinary();
    if (binary == null) {
      return _startupFailure(
        startupTrace,
        stage: 1,
        code: DaemonStartupFailureCode.daemonBinaryLoadFailed,
        message:
            'Could not find p2wlan-daemon. Build it with cargo or set P2WLAN_DAEMON_BIN.',
      );
    }
    await startupTrace?.stageOk(1, 'resolve_daemon');
    await startupTrace?.detail('daemon binary resolved');

    await startupTrace?.stageStart(2, 'binary_probe');
    final windowsProbe = await _probeWindowsDaemonBinary(binary);
    if (windowsProbe.error != null) {
      return _startupFailure(
        startupTrace,
        stage: 2,
        code: DaemonStartupFailureCode.daemonBinaryLoadFailed,
        message:
            '[DAEMON_BINARY_LOAD_FAILED] Windows 守护进程无法加载，发布包可能缺少运行库或文件不完整：${windowsProbe.error}',
      );
    }
    _lastDaemonBuildInfo = windowsProbe.identity;
    if (Platform.isWindows && windowsProbe.identity != null) {
      final daemonBuild = windowsProbe.identity!;
      await startupTrace?.detail(
        'daemon build identity app_version=${daemonBuild.appVersion} '
        'git_commit=${daemonBuild.gitCommit} build_id=${daemonBuild.buildId} '
        'dirty=${daemonBuild.dirtyLabel} diff_hash=${daemonBuild.diffHash} '
        'profile=${daemonBuild.profile}',
      );
      final mismatch = clientBuildInfo.mismatchWith(daemonBuild);
      if (mismatch != null) {
        return _startupFailure(
          startupTrace,
          stage: 2,
          code: DaemonStartupFailureCode.clientDaemonBuildMismatch,
          message:
              '[CLIENT_DAEMON_BUILD_MISMATCH] Flutter client 与 daemon build identity 不一致（$mismatch），已阻止 TUN 启动。请使用同一次 clean build 重新打包。',
        );
      }
    }
    await startupTrace?.stageOk(2, 'binary_probe');

    // A stale daemon can keep /health returning 200 after its TUN/dataplane
    // has failed.  Do not treat the liveness endpoint as proof that the
    // instance is reusable: clean up the verified old daemon first, then
    // launch the binary selected above.  This also handles a daemon left by
    // an older Debug/Release app bundle on the same diagnostics port.
    await startupTrace?.stageStart(3, 'stale_daemon_check');
    if (await _hasExistingDaemonForStart(settings.diagnosticsUrl)) {
      final stopped = await stop(settings.diagnosticsUrl);
      if (!stopped.ok) {
        return _startupFailure(
          startupTrace,
          stage: 3,
          code: DaemonStartupFailureCode.staleDaemonCleanupFailed,
          message: '检测到旧 p2wlan-daemon，但启动新实例前无法停止它：${stopped.message}',
        );
      }
    }
    await startupTrace?.stageOk(3, 'stale_daemon_check');

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
    await startupTrace?.detail(
      'permission preflight requires_elevation=$requiresElevation',
    );
    await startupTrace?.stageStart(4, 'current_sid');
    final windowsClientSid = Platform.isWindows
        ? await _windowsCurrentUserSid()
        : null;
    if (Platform.isWindows && windowsClientSid == null) {
      return _startupFailure(
        startupTrace,
        stage: 4,
        code: DaemonStartupFailureCode.tokenAccessFailed,
        message:
            '[TOKEN_ACCESS_FAILED] 无法读取当前 Windows 用户 SID，无法建立安全的跨账户启动 ACL。',
      );
    }
    await startupTrace?.stageOk(4, 'current_sid');
    File? tokenFile;
    // Windows console daemons cannot safely receive a managed token over a
    // detached stdin: depending on the Windows process mode this can create
    // a console window even when the Flutter app itself is GUI-only. Use the
    // same one-shot protected file for both elevated and already-elevated
    // Windows launches. It also makes the two Windows launch paths behave
    // identically, which prevents a second fallback process from being
    // started after UAC succeeds.
    await startupTrace?.stageStart(5, 'runtime_acl');
    try {
      if (Platform.isWindows) await protectRuntimeDirectory(logDir);
      await startupTrace?.stageOk(5, 'runtime_acl');
    } catch (error) {
      return _startupFailure(
        startupTrace,
        stage: 5,
        code: DaemonStartupFailureCode.aclFailure,
        message: _startFailureMessage(error),
      );
    }

    await startupTrace?.stageStart(6, 'launch_token');
    if (!useManualMode && (requiresElevation || Platform.isWindows)) {
      try {
        tokenFile = await createEphemeralLaunchTokenFile(logDir, authToken);
        await startupTrace?.stageOk(6, 'launch_token');
      } catch (error) {
        return _startupFailure(
          startupTrace,
          stage: 6,
          code: Platform.isWindows
              ? DaemonStartupFailureCode.tokenAccessFailed
              : _failureCodeForError(error),
          message: _startFailureMessage(error),
        );
      }
    } else if (Platform.isWindows) {
      try {
        // Manual/offline mode has no launch token, but an elevated daemon
        // still needs the same user/admin ACL on the runtime directory for
        // its log, PID marker, and diagnostics session file.
        await protectRuntimeDirectory(logDir);
        await startupTrace?.stageOk(6, 'launch_token');
      } catch (error) {
        return _startupFailure(
          startupTrace,
          stage: 6,
          code: _failureCodeForError(error),
          message: _startFailureMessage(error),
        );
      }
    } else {
      await startupTrace?.stageSkipped(6, 'launch_token');
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

    await startupTrace?.stageStart(7, 'log_prepare');
    try {
      await configPath.parent.create(recursive: true);
      await logDir.create(recursive: true);
      if (Platform.isWindows) {
        // The daemon may run under the alternate administrator selected in
        // the UAC prompt. Grant only the interactive SID and local
        // Administrators (never Everyone) access to both runtime roots.
        await protectRuntimeDirectory(configPath.parent);
        await protectRuntimeDirectory(logDir);
        if (await configPath.exists()) {
          await _restrictLaunchPath(configPath.path);
        }
      }
      // Keep the current log and one previous startup log. macOS elevated
      // launches rotate inside the sudo shell below so a root-owned log can
      // be repaired before it is moved; all other desktop paths can rotate as
      // the interactive user here.
      if (!(Platform.isMacOS && requiresElevation)) {
        await rotateP2wlanLogFiles(File(logPath));
        // Pre-create and truncate as the interactive user. Elevated launches
        // must append to this file rather than creating an admin-owned file or
        // inheriting stale startup markers.
        await File(logPath).writeAsString('', flush: true);
        if (Platform.isWindows) {
          await _restrictLaunchPath(logPath);
        }
      }
      await _clearPidMarkerForStart(pidPath);
      await startupTrace?.stageOk(7, 'log_prepare');
    } catch (error) {
      try {
        await deleteEphemeralLaunchTokenFile(tokenFile);
      } catch (_) {}
      return _startupFailure(
        startupTrace,
        stage: 7,
        code: _failureCodeForError(error),
        message: _startFailureMessage(error),
      );
    }

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

    int? launchPid;
    await startupTrace?.stageStart(8, 'uac');
    try {
      if (requiresElevation && Platform.isMacOS) {
        await _startMacosElevated(
          elevatedShell,
          password: settings.macosAdminPassword,
        );
      } else if (requiresElevation && Platform.isWindows) {
        launchPid = await _startWindowsElevated(binary: binary, args: args);
        await _writePidMarker(pidPath, launchPid);
        await startupTrace?.stageAccepted(8, 'uac');
        await startupTrace?.childPid(launchPid);
      } else if (requiresElevation && Platform.isLinux) {
        await _startLinuxElevated(binary: binary, args: args);
        await startupTrace?.stageSkipped(8, 'uac');
      } else {
        final process = await _startDetached(
          binary: binary,
          args: args,
          stdinToken: tokenFile == null && !useManualMode ? authToken : null,
        );
        launchPid = process.pid;
        if (Platform.isWindows &&
            !await _waitForWindowsChildIdentity(launchPid)) {
          throw StateError(
            'PID_MARKER_FAILED: Windows daemon PID did not resolve to p2wlan-daemon.',
          );
        }
        await _writePidMarker(pidPath, launchPid);
        if (Platform.isWindows) {
          await startupTrace?.stageSkipped(8, 'uac');
          await startupTrace?.childPid(launchPid);
        }
      }
    } catch (error) {
      // The launch itself failed: never leave the temporary credential file
      // behind.
      try {
        await _cleanupFailedStartup(launchPid);
      } catch (_) {}
      try {
        await deleteEphemeralLaunchTokenFile(tokenFile);
      } catch (_) {}
      return _startupFailure(
        startupTrace,
        stage: Platform.isWindows ? 8 : 0,
        code: _failureCodeForError(error),
        message: _startFailureMessage(error),
        manualCommand: manualCommand,
      );
    }

    // Stage 09 records the PID returned by the launch path; stage 10 is the
    // verified Win32 process handoff. Keep both before health polling so the
    // trace proves whether failure happened in process creation or readiness.
    if (Platform.isWindows && launchPid != null) {
      await startupTrace?.daemonAlive();
    }

    // The daemon reads the token synchronously at startup, so once the
    // diagnostics endpoint is up (or the launch has failed/timed out) the
    // temporary credential file is no longer needed. Delete it now so no
    // long-lived plaintext token file persists, and always clean it up on
    // failure/timeout below.
    _lastLaunchExitProbeAt = null;
    _lastLaunchExitProbeResult = null;
    final timeout = Platform.isMacOS ? _macosReadyTimeout : _directReadyTimeout;
    await startupTrace?.stageStart(11, 'health_wait');
    final startup = await _waitForHealth(
      settings.diagnosticsUrl,
      timeout,
      logPath,
      launchPid,
    );
    try {
      await deleteEphemeralLaunchTokenFile(tokenFile);
    } catch (_) {}
    if (!startup.ready) {
      try {
        await _cleanupFailedStartup(launchPid);
      } catch (_) {}
      final failure =
          startup.failure ??
          const DaemonStartupFailure(
            DaemonStartupFailureCode.startupTimeout,
            'p2wlan-daemon 未在启动时限内完成诊断端点就绪。',
          );
      await startupTrace?.failure(11, failure.codeValue);
      if (failure.code == DaemonStartupFailureCode.controlAuthFailed) {
        return DaemonCommandResult(
          ok: false,
          message: '登录已过期，请重新登录。${failure.message}',
          manualCommand: manualCommand,
          failureCode: failure.code,
        );
      }
      return DaemonCommandResult(
        ok: false,
        message: '[${failure.codeValue}] ${failure.message} 请查看日志：$logPath',
        manualCommand: manualCommand,
        failureCode: failure.code,
      );
    }
    await startupTrace?.stageOk(11, 'health_wait');
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

  Future<DaemonCommandResult> _startupFailure(
    WindowsStartupTrace? trace, {
    required int stage,
    required DaemonStartupFailureCode code,
    required String message,
    String? manualCommand,
  }) async {
    await trace?.failure(stage, code.value);
    return DaemonCommandResult(
      ok: false,
      message: message,
      manualCommand: manualCommand,
      failureCode: code,
    );
  }

  DaemonStartupFailureCode _failureCodeForError(Object error) {
    if (Platform.isWindows) {
      return classifyWindowsLaunchFailure(error.toString()).code;
    }
    final normalized = error.toString().toLowerCase();
    if (normalized.contains('acl') || normalized.contains('permission')) {
      return DaemonStartupFailureCode.aclFailure;
    }
    if (normalized.contains('pid marker')) {
      return DaemonStartupFailureCode.pidMarkerFailed;
    }
    return DaemonStartupFailureCode.uacLaunchFailed;
  }
}
