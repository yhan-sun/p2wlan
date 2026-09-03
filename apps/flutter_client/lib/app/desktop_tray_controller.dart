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

/// Windows tray events have used both `MouseDown` and `MouseUp` callback names
/// across tray_manager builds (the native message is a button-up notification
/// in the current plug-in). The controller accepts either left-click callback
/// and de-duplicates the pair; other desktop implementations retain the
/// established mouse-up context menu behavior.
enum DesktopTrayPointerAction { showWindow, contextMenu }

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
  Future<void>? _disposeFuture;
  Future<void>? _quitFuture;
  Timer? _windowsLeftClickDedupeTimer;
  var _windowsLeftClickHandled = false;

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
      if (Platform.isMacOS || Platform.isLinux) {
        await trayManager.setTitle(trayMenuBarTitleForTesting());
      }
      await _updateTrayIcon(force: true);
      await _queueMenuUpdate();
    } catch (error) {
      debugPrint('Failed to initialize P2WLAN tray: $error');
    }
  }

  Future<void> dispose() {
    final existing = _disposeFuture;
    if (existing != null) return existing;
    if (!_initialized) return Future<void>.value();

    _initialized = false;
    _windowsLeftClickDedupeTimer?.cancel();
    _windowsLeftClickDedupeTimer = null;
    _windowsLeftClickHandled = false;
    _menuUpdateRequested = false;
    settingsStore.removeListener(_scheduleMenuUpdate);
    statusStore.removeListener(_scheduleMenuUpdate);
    windowManager.removeListener(this);
    trayManager.removeListener(this);
    final pendingUpdate = _menuUpdateInFlight;
    final future = _finishDispose(pendingUpdate);
    _disposeFuture = future;
    return future;
  }

  Future<void> _finishDispose(Future<void>? pendingUpdate) async {
    if (pendingUpdate != null) await pendingUpdate;
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
  void onTrayIconMouseDown() {
    _handleTrayPointer(mouseDown: true, rightButton: false);
  }

  @override
  void onTrayIconRightMouseDown() {
    _handleTrayPointer(mouseDown: true, rightButton: true);
  }

  @override
  void onTrayIconMouseUp() {
    _handleTrayPointer(mouseDown: false, rightButton: false);
  }

  @override
  void onTrayIconRightMouseUp() {
    _handleTrayPointer(mouseDown: false, rightButton: true);
  }

  void _handleTrayPointer({
    required bool mouseDown,
    required bool rightButton,
  }) {
    final action = trayPointerActionForTesting(
      isWindows: Platform.isWindows,
      mouseDown: mouseDown,
      rightButton: rightButton,
    );
    if (Platform.isWindows && action == DesktopTrayPointerAction.showWindow) {
      // Some tray_manager Windows builds deliver a left click through both
      // callback names. Accept either one, but only restore the window once.
      if (_windowsLeftClickHandled) return;
      _windowsLeftClickHandled = true;
      _windowsLeftClickDedupeTimer?.cancel();
      _windowsLeftClickDedupeTimer = Timer(
        const Duration(milliseconds: 200),
        () {
          _windowsLeftClickHandled = false;
          _windowsLeftClickDedupeTimer = null;
        },
      );
    }

    switch (action) {
      case DesktopTrayPointerAction.showWindow:
        unawaited(_showWindow());
        break;
      case DesktopTrayPointerAction.contextMenu:
        unawaited(trayManager.popUpContextMenu());
        break;
      case null:
        break;
    }
  }

  /// Maps a native tray notification to one application action.
  ///
  /// On Windows, a left click is a show-window action regardless of whether
  /// the native plug-in reports it as mouse-down or mouse-up. Right-click is
  /// intentionally handled on the down callback only, so a native click does
  /// not open the context menu twice.
  @visibleForTesting
  static DesktopTrayPointerAction? trayPointerActionForTesting({
    required bool isWindows,
    required bool mouseDown,
    required bool rightButton,
  }) {
    if (isWindows) {
      if (rightButton) {
        return mouseDown ? DesktopTrayPointerAction.contextMenu : null;
      }
      return DesktopTrayPointerAction.showWindow;
    }
    return mouseDown ? null : DesktopTrayPointerAction.contextMenu;
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
    final taskbarTitle = desktopVisibleTitleForTesting();

    await _updateTrayIcon();
    await trayManager.setToolTip(
      Platform.isMacOS ? p2wlanAppName : '$taskbarTitle - $statusLabel',
    );
    if (Platform.isMacOS || Platform.isLinux) {
      await trayManager.setTitle(trayMenuBarTitleForTesting());
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
          disabled: busy || statusStore.refreshActivityVisible,
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
  String desktopVisibleTitleForTesting() {
    // Keep the stable app title for the Dock/window. The macOS menu-bar item
    // intentionally uses trayMenuBarTitleForTesting() and stays icon-only;
    // connection metrics remain available in the tray menu.
    return Platform.isMacOS ? p2wlanAppName : trayTitleForTesting();
  }

  @visibleForTesting
  String trayMenuBarTitleForTesting() {
    // Keep the macOS status item icon-only. The tooltip still carries the
    // accessible app name, while the Dock/window title remains P2WLAN.
    return Platform.isMacOS ? '' : desktopVisibleTitleForTesting();
  }

  @visibleForTesting
  String desktopVisibleBadgeForTesting() {
    // A live latency/speed badge is also connection information in the Dock.
    // Returning an empty value clears badges left by older client versions.
    return Platform.isMacOS ? '' : dockBadgeForTesting();
  }

  @visibleForTesting
  String trayTitleForTesting() {
    final snapshot = _metricsSnapshot;
    if (snapshot == null) return p2wlanAppName;
    return '$p2wlanAppName · ${formatLatency(_averageLatency(snapshot))} · ${formatTransferRate(_aggregateSpeed(snapshot))}';
  }

  @visibleForTesting
  String dockBadgeForTesting() {
    final snapshot = _metricsSnapshot;
    if (snapshot == null) return '';
    final latency = _averageLatency(snapshot);
    final speed = _aggregateSpeed(snapshot);
    if (latency == null && speed == null) return '';
    final latencyLabel = latency == null ? '—' : '${latency}ms';
    final speedLabel = speed == null
        ? '—'
        : formatTransferRate(speed).replaceAll(' ', '');
    return '$latencyLabel/$speedLabel';
  }

  String _networkLabel(AppStrings strings, DiagnosticsSnapshot? snapshot) {
    final virtualIp = snapshot?.virtualIp.trim();
    final peerCount = snapshot?.stats.totalPeers ?? 0;
    final metricsSnapshot = _metricsSnapshot;
    return '${strings.virtualIp}: ${virtualIp == null || virtualIp.isEmpty ? '—' : virtualIp} · ${strings.peerCount}: $peerCount · ${strings.localAverageRtt}: ${formatLatency(_averageLatency(metricsSnapshot))} · ${strings.transferSpeed}: ${formatTransferRate(_aggregateSpeed(metricsSnapshot))}';
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
    final peers = statusStore
        .stablePeerOrder(snapshot?.peers ?? const <PeerSnapshot>[])
        .where((peer) => peer.online && peer.path != 'offline')
        .toList(growable: false);
    if (peers.isEmpty) {
      return [MenuItem(label: strings.noOnlineDevices, disabled: true)];
    }
    return [
      for (final peer in peers)
        MenuItem(
          label: _peerLabel(strings, peer),
          onClick: (_) => unawaited(_copyPeerIp(peer.virtualIp)),
        ),
    ];
  }

  String _peerLabel(AppStrings strings, PeerSnapshot peer) {
    final ip = peer.virtualIp.trim().isEmpty ? '—' : peer.virtualIp.trim();
    final path = peer.path;
    final marker = switch (path) {
      'direct' => '🟢',
      'relay' => '🟠',
      _ => '🟡',
    };
    return '$marker ${strings.pathLabel(path)} · ${peer.displayName} · $ip';
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

  /// Exercise the packaged tray quit path from the Windows release harness.
  /// The harness starts the app without a virtual adapter; `_quitApp` must
  /// still tear down the tray/window and exit without trying to force-kill a
  /// nonexistent daemon.
  Future<void> quitForLifecycleTest() => _quitApp();

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

  Future<void> _quitApp() {
    final existing = _quitFuture;
    if (existing != null) return existing;

    final future = _performQuit();
    _quitFuture = future;
    future.then<void>(
      (_) {
        if (!_quitting && identical(_quitFuture, future)) {
          _quitFuture = null;
        }
      },
      onError: (Object _, StackTrace _) {
        if (identical(_quitFuture, future)) _quitFuture = null;
      },
    );
    return future;
  }

  Future<void> _performQuit() async {
    if (_quitting) return;
    _quitting = true;
    try {
      final stopResult = await _stopDaemonForQuit();
      if (!stopResult.ok) {
        _quitting = false;
        await _showWindow();
        await _updateMenu();
        return;
      }
      await _destroyTrayWindowAndExit();
    } catch (_) {
      _quitting = false;
      rethrow;
    }
  }

  Future<void> _destroyTrayWindowAndExit() async {
    // This also makes any Widget.dispose during engine shutdown return the
    // same Future. The tray plugin must receive exactly one destroy call per
    // controller lifetime.
    await dispose();
    await DesktopWindowOperations.run(() async {
      await windowManager.setPreventClose(false);
      await windowManager.destroy();
    });
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
