import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import '../core/daemon/daemon_controller.dart';
import '../core/models/diagnostics_models.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../shared/formatters.dart';
import 'app_constants.dart';
import 'app_strings.dart';
import 'desktop_window_operations.dart';

class DesktopTrayController with TrayListener, WindowListener {
  DesktopTrayController({
    required this.settingsStore,
    required this.statusStore,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  static const _macosTrayIconSize = 22;
  static const _windowsTrayIconAsset = 'assets/tray_icon.ico';
  static const _linuxTrayIconAsset = 'assets/tray_icon.png';
  static const _macosBusyIconAsset = 'assets/tray_icon_macos_busy.png';
  static const _macosOnIconAsset = 'assets/tray_icon_macos_on.png';
  static const _macosOffIconAsset = 'assets/tray_icon_macos_off.png';
  static const _macosAttentionIconAsset =
      'assets/tray_icon_macos_attention.png';
  static const _quitBusyPollInterval = Duration(milliseconds: 100);
  static const _quitBusyTimeout = Duration(seconds: 20);
  static const _alreadyStoppedResult = DaemonCommandResult(
    ok: true,
    message: 'p2wlan-daemon is already stopped.',
  );

  bool _initialized = false;
  bool _quitting = false;
  bool _menuUpdateRequested = false;
  Future<void>? _menuUpdateInFlight;
  String? _lastTrayIconAsset;
  String? _lastDesktopTitle;
  bool _macosDockBadgeCleared = false;
  Future<DaemonCommandResult>? _stopDaemonFuture;

  static bool get isSupported {
    return !kIsWeb &&
        (Platform.isMacOS || Platform.isLinux || Platform.isWindows);
  }

  Future<void> initialize() async {
    if (_initialized || !isSupported) return;
    _initialized = true;
    trayManager.addListener(this);
    windowManager.addListener(this);
    settingsStore.addListener(_scheduleMenuUpdate);
    statusStore.addListener(_scheduleMenuUpdate);

    try {
      await DesktopWindowOperations.run(
        () => windowManager.setPreventClose(true),
      );
      if (!_initialized) return;
      if (Platform.isLinux) {
        await trayManager.setTitle(trayTitleForTesting());
      } else if (Platform.isMacOS) {
        // Keep the macOS menu bar item icon-only. This also clears a title
        // left behind by an older client version.
        await trayManager.setTitle('');
      }
      await _updateTrayIcon(force: true);
      await _queueMenuUpdate();
    } catch (error) {
      debugPrint('Failed to initialize P2WLAN tray: $error');
    }
  }

  Future<void> dispose() async {
    if (!_initialized) return;
    _initialized = false;
    _menuUpdateRequested = false;
    settingsStore.removeListener(_scheduleMenuUpdate);
    statusStore.removeListener(_scheduleMenuUpdate);
    windowManager.removeListener(this);
    trayManager.removeListener(this);
    final pendingUpdate = _menuUpdateInFlight;
    if (pendingUpdate != null) {
      await pendingUpdate;
    }
    try {
      await trayManager.destroy();
    } catch (_) {
      // Best effort cleanup on app shutdown.
    }
  }

  @override
  void onWindowClose() {
    if (_quitting) return;
    if (closeActionForTesting() == 'quit') {
      unawaited(_quitApp());
    } else {
      unawaited(_hideWindow());
    }
  }

  @visibleForTesting
  String closeActionForTesting() {
    return normalizeCloseBehavior(settingsStore.settings.closeBehavior) ==
            'stop-and-quit'
        ? 'quit'
        : 'hide';
  }

  @override
  void onTrayIconMouseUp() {
    unawaited(trayManager.popUpContextMenu());
  }

  @override
  void onTrayIconRightMouseUp() {
    unawaited(trayManager.popUpContextMenu());
  }

  void _scheduleMenuUpdate() {
    unawaited(_queueMenuUpdate());
  }

  Future<void> _queueMenuUpdate() {
    if (!_initialized) return Future<void>.value();
    _menuUpdateRequested = true;
    final inFlight = _menuUpdateInFlight;
    if (inFlight != null) return inFlight;

    final future = _drainMenuUpdates();
    _menuUpdateInFlight = future;
    return future;
  }

  Future<void> _drainMenuUpdates() async {
    try {
      while (_initialized && _menuUpdateRequested) {
        _menuUpdateRequested = false;
        try {
          await _updateMenu();
        } catch (error) {
          debugPrint('Failed to update P2WLAN tray: $error');
        }
      }
    } finally {
      _menuUpdateInFlight = null;
      if (_initialized && _menuUpdateRequested) {
        unawaited(_queueMenuUpdate());
      }
    }
  }

  Future<void> _updateMenu() async {
    final strings = AppStrings.fromCode(settingsStore.settings.languageCode);
    final statusLabel = _statusLabel(strings);
    final taskbarTitle = trayTitleForTesting();

    await _updateTrayIcon();
    await trayManager.setToolTip(
      Platform.isMacOS ? p2wlanAppName : '$taskbarTitle - $statusLabel',
    );
    if (Platform.isLinux) {
      await trayManager.setTitle(taskbarTitle);
    } else if (Platform.isMacOS) {
      // Live metrics belong in the expanded menu, not beside the icon.
      await trayManager.setTitle('');
    }
    await _updateDesktopWindowIndicators(taskbarTitle);

    await trayManager.setContextMenu(buildMenuForTesting());
  }

  Future<void> _updateDesktopWindowIndicators(String title) async {
    final shouldUpdateTitle = _lastDesktopTitle != title;
    final shouldClearMacosDockBadge =
        Platform.isMacOS && !_macosDockBadgeCleared;
    if (!shouldUpdateTitle && !shouldClearMacosDockBadge) return;

    try {
      await DesktopWindowOperations.run(() async {
        if (shouldUpdateTitle) {
          await windowManager.setTitle(title);
          _lastDesktopTitle = title;
        }
        if (shouldClearMacosDockBadge) {
          // Do not show live metrics as a red macOS Dock badge. Calling this
          // once also clears a badge written by an older client version.
          await windowManager.setBadgeLabel();
          _macosDockBadgeCleared = true;
        }
      });
    } catch (error) {
      if (shouldUpdateTitle) {
        debugPrint('Failed to update P2WLAN taskbar title: $error');
      }
      if (shouldClearMacosDockBadge) {
        debugPrint('Failed to update P2WLAN Dock badge: $error');
      }
    }
  }

  Future<void> _updateTrayIcon({bool force = false}) async {
    final asset = trayIconAssetForTesting();
    if (!force && _lastTrayIconAsset == asset) return;
    try {
      await trayManager.setIcon(
        asset,
        isTemplate: trayIconUsesTemplateForTesting(),
        iconSize: Platform.isMacOS ? _macosTrayIconSize : 18,
      );
      _lastTrayIconAsset = asset;
    } catch (error) {
      debugPrint('Failed to update P2WLAN tray icon $asset: $error');
    }
  }

  @visibleForTesting
  Menu buildMenuForTesting() {
    final strings = AppStrings.fromCode(settingsStore.settings.languageCode);
    final snapshot = statusStore.snapshot;
    final daemonReachable = statusStore.daemonReachable;
    final busy = statusStore.daemonBusy;
    final statusLabel = _statusLabel(strings);
    final networkLabel = _networkLabel(strings, snapshot);
    final primaryControlLabel = busy
        ? strings.daemonWorking
        : daemonReachable
        ? strings.stopP2wlan
        : strings.startP2wlan;

    return Menu(
      items: [
        MenuItem(label: '${strings.trayStatus}: $statusLabel', disabled: true),
        MenuItem(label: networkLabel, disabled: true),
        MenuItem.separator(),
        MenuItem(
          label: strings.openConsole,
          onClick: (_) => unawaited(_showWindow()),
        ),
        MenuItem(
          label: primaryControlLabel,
          disabled: busy,
          onClick: (_) =>
              unawaited(daemonReachable ? _stopDaemon() : _startDaemon()),
        ),
        MenuItem(
          label: strings.refreshNow,
          disabled: busy || statusStore.refreshing,
          onClick: (_) => unawaited(statusStore.refresh()),
        ),
        MenuItem.separator(),
        MenuItem(label: strings.devices, disabled: true),
        ..._deviceItems(strings, snapshot),
        MenuItem.separator(),
        MenuItem(
          label: strings.openLogs,
          onClick: (_) => unawaited(_openLogDirectory()),
        ),
        MenuItem(
          label: strings.quitP2wlan,
          onClick: (_) => unawaited(_quitApp()),
        ),
      ],
    );
  }

  String _statusLabel(AppStrings strings) {
    if (statusStore.daemonBusy) return strings.daemonWorking;
    if (statusStore.snapshotStale) return strings.stale;
    if (!statusStore.daemonReachable) return strings.offline;
    final health = statusStore.snapshot?.health.status;
    if (health == null || health.isEmpty) return strings.degraded;
    return strings.healthStatusLabel(health);
  }

  @visibleForTesting
  String trayIconAssetForTesting() {
    if (!Platform.isMacOS) {
      return Platform.isWindows ? _windowsTrayIconAsset : _linuxTrayIconAsset;
    }
    if (statusStore.daemonBusy) return _macosBusyIconAsset;
    if (statusStore.snapshotStale) return _macosAttentionIconAsset;
    if (!statusStore.daemonReachable) return _macosOffIconAsset;
    final health = statusStore.snapshot?.health.status.toLowerCase();
    if (health == 'healthy') return _macosOnIconAsset;
    return _macosAttentionIconAsset;
  }

  @visibleForTesting
  bool trayIconUsesTemplateForTesting() => Platform.isMacOS;

  @visibleForTesting
  String trayTitleForPlatformForTesting() {
    return Platform.isMacOS ? '' : trayTitleForTesting();
  }

  @visibleForTesting
  String trayTitleForTesting() {
    final snapshot = _metricsSnapshot;
    if (snapshot == null) return p2wlanAppName;
    return '$p2wlanAppName · ${formatLatency(_averageLatency(snapshot))} · ${formatTransferRate(_aggregateSpeed(snapshot))}';
  }

  String _networkLabel(AppStrings strings, DiagnosticsSnapshot? snapshot) {
    final virtualIp = snapshot?.virtualIp.trim();
    final peerCount = snapshot?.stats.totalPeers ?? 0;
    final metricsSnapshot = _metricsSnapshot;
    return '${strings.virtualIp}: ${virtualIp == null || virtualIp.isEmpty ? '—' : virtualIp} · ${strings.peerCount}: $peerCount · 延迟: ${formatLatency(_averageLatency(metricsSnapshot))} · 速度: ${formatTransferRate(_aggregateSpeed(metricsSnapshot))}';
  }

  DiagnosticsSnapshot? get _metricsSnapshot {
    if (!statusStore.daemonReachable || statusStore.snapshotStale) return null;
    return statusStore.snapshot;
  }

  int? _averageLatency(DiagnosticsSnapshot? snapshot) {
    if (snapshot == null) return null;
    final latencies = [
      for (final peer in snapshot.peers)
        if (peer.online && peer.latencyMs != null) peer.latencyMs!,
    ];
    if (latencies.isEmpty) return null;
    final total = latencies.fold<int>(0, (sum, value) => sum + value);
    return (total / latencies.length).round();
  }

  int? _aggregateSpeed(DiagnosticsSnapshot? snapshot) {
    if (snapshot == null) return null;
    var total = 0;
    var hasSample = false;
    for (final peer in snapshot.peers) {
      if (!peer.online) continue;
      final rate = statusStore.peerTransferRatesBytesPerSecond[peer.nodeId];
      if (rate == null) continue;
      total += rate;
      hasSample = true;
    }
    return hasSample ? total : null;
  }

  List<MenuItem> _deviceItems(
    AppStrings strings,
    DiagnosticsSnapshot? snapshot,
  ) {
    final peers = [
      for (final peer in snapshot?.peers ?? const <PeerSnapshot>[])
        if (peer.online && peer.path != 'offline') peer,
    ];
    if (peers.isEmpty) {
      return [MenuItem(label: strings.noOnlineDevices, disabled: true)];
    }
    return [
      for (final peer in peers)
        MenuItem(
          label: _peerLabel(peer),
          onClick: (_) => unawaited(_copyPeerIp(peer.virtualIp)),
        ),
    ];
  }

  String _peerLabel(PeerSnapshot peer) {
    final ip = peer.virtualIp.trim().isEmpty ? '—' : peer.virtualIp.trim();
    return '${peer.displayName} · $ip';
  }

  Future<void> _showWindow() async {
    if (!isSupported) return;
    await DesktopWindowOperations.run(() async {
      if (!Platform.isWindows) {
        await windowManager.setSkipTaskbar(false);
      }
      await windowManager.show();
      if (await windowManager.isMinimized()) {
        await windowManager.restore();
      }
      await windowManager.focus();
    });
  }

  Future<void> _hideWindow() async {
    if (!isSupported) return;
    await DesktopWindowOperations.run(() async {
      await windowManager.hide();
      if (!Platform.isWindows) {
        await windowManager.setSkipTaskbar(true);
      }
    });
  }

  Future<void> _startDaemon() async {
    await _showWindow();
    await statusStore.startDaemon();
  }

  Future<DaemonCommandResult> _stopDaemon() {
    final existing = _stopDaemonFuture;
    if (existing != null) return existing;

    final future = statusStore.stopDaemon();
    _stopDaemonFuture = future;
    future.whenComplete(() {
      if (identical(_stopDaemonFuture, future)) {
        _stopDaemonFuture = null;
      }
    });
    return future;
  }

  Future<DaemonCommandResult> _stopDaemonForQuit() {
    final existing = _stopDaemonFuture;
    if (existing != null) return existing;
    return _stopDaemonForQuitAfterExternalCommand();
  }

  Future<DaemonCommandResult> _stopDaemonForQuitAfterExternalCommand() async {
    await _waitForExternalDaemonCommand();
    final existing = _stopDaemonFuture;
    if (existing != null) return existing;
    if (!statusStore.daemonBusy && !statusStore.daemonReachable) {
      return _alreadyStoppedResult;
    }

    final result = await _stopDaemon();
    if (!result.ok && !statusStore.daemonReachable) {
      return _alreadyStoppedResult;
    }
    return result;
  }

  Future<void> _waitForExternalDaemonCommand() async {
    if (!statusStore.daemonBusy) return;
    final deadline = DateTime.now().add(_quitBusyTimeout);
    while (statusStore.daemonBusy && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(_quitBusyPollInterval);
    }
  }

  @visibleForTesting
  Future<DaemonCommandResult> stopDaemonForTesting() => _stopDaemon();

  @visibleForTesting
  Future<DaemonCommandResult> stopDaemonForQuitForTesting() {
    return _stopDaemonForQuit();
  }

  Future<void> _copyPeerIp(String virtualIp) async {
    final value = virtualIp.trim();
    if (value.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: value));
  }

  Future<void> _openLogDirectory() async {
    final dir = _defaultLogDir();
    await dir.create(recursive: true);
    if (Platform.isMacOS) {
      await Process.start('open', [dir.path]);
    } else if (Platform.isWindows) {
      await Process.start('explorer', [dir.path]);
    } else {
      await Process.start('xdg-open', [dir.path]);
    }
  }

  Future<void> _quitApp() async {
    if (_quitting) return;
    _quitting = true;
    final stopResult = await _stopDaemonForQuit();
    if (!stopResult.ok) {
      _quitting = false;
      await _showWindow();
      await _updateMenu();
      return;
    }
    await _destroyTrayWindowAndExit();
  }

  Future<void> _destroyTrayWindowAndExit() async {
    try {
      await trayManager.destroy();
    } catch (_) {
      // Ignore best effort tray teardown.
    }
    try {
      await DesktopWindowOperations.run(() async {
        await windowManager.setPreventClose(false);
        await windowManager.destroy();
      });
    } finally {
      Timer(const Duration(milliseconds: 400), () => exit(0));
    }
  }

  Directory _defaultLogDir() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Logs/p2wlan');
      }
    }
    if (Platform.isWindows) {
      final localAppData = Platform.environment['LOCALAPPDATA'];
      if (localAppData != null && localAppData.isNotEmpty) {
        return Directory('$localAppData\\p2wlan\\logs');
      }
    }
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.local/state/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
  }
}
