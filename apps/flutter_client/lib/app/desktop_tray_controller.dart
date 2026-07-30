import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import '../core/models/diagnostics_models.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import 'app_constants.dart';
import 'app_strings.dart';

class DesktopTrayController with TrayListener, WindowListener {
  DesktopTrayController({
    required this.settingsStore,
    required this.statusStore,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  static const _macosTrayIconSize = 18;
  static const _windowsTrayIconAsset = 'assets/tray_icon.ico';
  static const _linuxTrayIconAsset = 'assets/tray_icon.png';
  static const _macosBusyIconAsset = 'assets/tray_icon_macos_busy.png';
  static const _macosOnIconAsset = 'assets/tray_icon_macos_on.png';
  static const _macosOffIconAsset = 'assets/tray_icon_macos_off.png';
  static const _macosAttentionIconAsset =
      'assets/tray_icon_macos_attention.png';

  bool _initialized = false;
  bool _quitting = false;
  bool _menuUpdateQueued = false;
  String? _lastTrayIconAsset;

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
      await windowManager.setPreventClose(true);
      await _updateTrayIcon(force: true);
      await _updateMenu();
    } catch (error) {
      debugPrint('Failed to initialize P2WLAN tray: $error');
    }
  }

  Future<void> dispose() async {
    if (!_initialized) return;
    settingsStore.removeListener(_scheduleMenuUpdate);
    statusStore.removeListener(_scheduleMenuUpdate);
    windowManager.removeListener(this);
    trayManager.removeListener(this);
    try {
      await trayManager.destroy();
    } catch (_) {
      // Best effort cleanup on app shutdown.
    }
    _initialized = false;
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
    if (_menuUpdateQueued) return;
    _menuUpdateQueued = true;
    scheduleMicrotask(() async {
      _menuUpdateQueued = false;
      if (_initialized) {
        await _updateMenu();
      }
    });
  }

  Future<void> _updateMenu() async {
    final strings = AppStrings.fromCode(settingsStore.settings.languageCode);
    final statusLabel = _statusLabel(strings);

    await _updateTrayIcon();
    await trayManager.setToolTip('$p2wlanAppName - $statusLabel');
    if (Platform.isMacOS) {
      await trayManager.setTitle('');
    }

    await trayManager.setContextMenu(buildMenuForTesting());
  }

  Future<void> _updateTrayIcon({bool force = false}) async {
    final asset = trayIconAssetForTesting();
    if (!force && _lastTrayIconAsset == asset) return;
    await trayManager.setIcon(
      asset,
      isTemplate: false,
      iconSize: Platform.isMacOS ? _macosTrayIconSize : 18,
    );
    _lastTrayIconAsset = asset;
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
        MenuItem.submenu(
          label: strings.devices,
          submenu: Menu(items: _deviceItems(strings, snapshot)),
        ),
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
    if (!statusStore.daemonReachable) return _macosOffIconAsset;
    final health = statusStore.snapshot?.health.status.toLowerCase();
    if (health == 'healthy') return _macosOnIconAsset;
    return _macosAttentionIconAsset;
  }

  String _networkLabel(AppStrings strings, DiagnosticsSnapshot? snapshot) {
    final virtualIp = snapshot?.virtualIp.trim();
    final peerCount = snapshot?.stats.totalPeers ?? 0;
    return '${strings.virtualIp}: ${virtualIp == null || virtualIp.isEmpty ? '—' : virtualIp} · ${strings.peerCount}: $peerCount';
  }

  List<MenuItem> _deviceItems(
    AppStrings strings,
    DiagnosticsSnapshot? snapshot,
  ) {
    final peers = snapshot?.peers ?? const <PeerSnapshot>[];
    if (peers.isEmpty) {
      return [MenuItem(label: strings.noOnlineDevices, disabled: true)];
    }
    return [
      for (final peer in peers.take(12))
        MenuItem(
          label: _peerLabel(peer),
          onClick: (_) => unawaited(_copyPeerIp(peer.virtualIp)),
        ),
      if (peers.length > 12)
        MenuItem(label: '+${peers.length - 12}', disabled: true),
    ];
  }

  String _peerLabel(PeerSnapshot peer) {
    final ip = peer.virtualIp.trim().isEmpty ? '—' : peer.virtualIp.trim();
    return '${peer.displayName} · $ip';
  }

  Future<void> _showWindow() async {
    if (!isSupported) return;
    await windowManager.setSkipTaskbar(false);
    await windowManager.show();
    if (await windowManager.isMinimized()) {
      await windowManager.restore();
    }
    await windowManager.focus();
  }

  Future<void> _hideWindow() async {
    if (!isSupported) return;
    await windowManager.hide();
    await windowManager.setSkipTaskbar(true);
  }

  Future<void> _startDaemon() async {
    await _showWindow();
    await statusStore.startDaemon();
  }

  Future<void> _stopDaemon() async {
    await statusStore.stopDaemon();
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
    final stopResult = await statusStore.stopDaemon();
    if (!stopResult.ok) {
      _quitting = false;
      await _showWindow();
      await _updateMenu();
      return;
    }
    try {
      await trayManager.destroy();
    } catch (_) {
      // Ignore best effort tray teardown.
    }
    await windowManager.setPreventClose(false);
    await windowManager.destroy();
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
