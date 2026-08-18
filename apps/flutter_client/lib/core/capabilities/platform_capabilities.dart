// Platform capability model for the unified Flutter GUI.
//
// A page must render only operations the current platform + daemon actually
// support. Capabilities are decided jointly by:
//   1. the platform baseline (`PlatformCapabilities.fromPlatform`), i.e. what
//      the OS can even do, and
//   2. what the local daemon reports (`withDaemonCapabilities`), i.e. what is
//      actually available at runtime (e.g. no admin elevation, TUN disabled).
//
// Pages must NOT branch on `Platform.isX` everywhere; they read this model.
// On non-desktop platforms (mobile/web) the local-daemon/TUN capabilities are
// off by default, so the UI never shows a fake "start daemon" button.
import 'dart:io' show Platform;

class PlatformCapabilities {
  const PlatformCapabilities({
    required this.canControlLocalDaemon,
    required this.canRequestElevation,
    required this.canVerifyRoutes,
    required this.canRepairRoutes,
    required this.canOpenLocalLogs,
    required this.canCreateSupportBundle,
    required this.canUseSystemTray,
    required this.canActAsLocalVpnNode,
    required this.canManageRemoteDevices,
  });

  /// Desktop/local can start, stop, restart the local daemon.
  final bool canControlLocalDaemon;

  /// Can prompt for admin/root elevation (needed for route/TUN ops).
  final bool canRequestElevation;

  /// Can ask the daemon to verify the live system routing table (read-only).
  final bool canVerifyRoutes;

  /// Can ask the daemon to repair routes in place (no daemon restart).
  final bool canRepairRoutes;

  /// Can open the local daemon log directory / read the log tail.
  final bool canOpenLocalLogs;

  /// Can create a (redacted) support bundle.
  final bool canCreateSupportBundle;

  /// This OS supports a resident system tray.
  final bool canUseSystemTray;

  /// This device can act as a local P2WLAN VPN node (TUN up).
  final bool canActAsLocalVpnNode;

  /// Can manage remote devices / control plane (account, networks, peers).
  final bool canManageRemoteDevices;

  /// Baseline capabilities for a normalized OS name.
  ///
  /// `os` is one of `windows`, `macos`, `linux`, `android`, `ios`, `fuchsia`,
  /// `web`. Mobile and web are deliberately local-daemon/TUN-incapable until a
  /// native VPN mode is built; they keep remote-management capability.
  factory PlatformCapabilities.fromPlatform(String os) {
    switch (os) {
      case 'windows':
      case 'macos':
      case 'linux':
        return const PlatformCapabilities(
          canControlLocalDaemon: true,
          canRequestElevation: true,
          canVerifyRoutes: true,
          canRepairRoutes: true,
          canOpenLocalLogs: true,
          canCreateSupportBundle: true,
          canUseSystemTray: true,
          canActAsLocalVpnNode: true,
          canManageRemoteDevices: true,
        );
      case 'android':
      case 'ios':
      case 'fuchsia':
        return const PlatformCapabilities(
          canControlLocalDaemon: false,
          canRequestElevation: false,
          canVerifyRoutes: false,
          canRepairRoutes: false,
          canOpenLocalLogs: false,
          canCreateSupportBundle: false,
          canUseSystemTray: false,
          canActAsLocalVpnNode: false,
          canManageRemoteDevices: true,
        );
      case 'web':
      default:
        return const PlatformCapabilities(
          canControlLocalDaemon: false,
          canRequestElevation: false,
          canVerifyRoutes: false,
          canRepairRoutes: false,
          canOpenLocalLogs: false,
          canCreateSupportBundle: false,
          canUseSystemTray: false,
          canActAsLocalVpnNode: false,
          canManageRemoteDevices: true,
        );
    }
  }

  /// Baseline for the current runtime platform (uses `dart:io`).
  factory PlatformCapabilities.current() {
    return PlatformCapabilities.fromPlatform(_currentOs());
  }

  /// Intersect with the daemon's authoritative runtime capabilities. A daemon
  /// report can only turn a capability OFF (e.g. no elevation, TUN disabled),
  /// never turn a platform-incompatible one ON. Returns `this` when the report
  /// is absent (daemon not yet reached).
  PlatformCapabilities withDaemonCapabilities(Map<String, bool>? reported) {
    if (reported == null || reported.isEmpty) return this;
    bool off(String key) => reported[key] == false;
    return PlatformCapabilities(
      canControlLocalDaemon:
          canControlLocalDaemon && !off('canControlLocalDaemon'),
      canRequestElevation: canRequestElevation && !off('canRequestElevation'),
      canVerifyRoutes: canVerifyRoutes && !off('canVerifyRoutes'),
      canRepairRoutes: canRepairRoutes && !off('canRepairRoutes'),
      canOpenLocalLogs: canOpenLocalLogs && !off('canOpenLocalLogs'),
      canCreateSupportBundle:
          canCreateSupportBundle && !off('canCreateSupportBundle'),
      canUseSystemTray: canUseSystemTray,
      canActAsLocalVpnNode:
          canActAsLocalVpnNode && !off('canActAsLocalVpnNode'),
      canManageRemoteDevices: canManageRemoteDevices,
    );
  }
}

/// Map `dart:io`'s `Platform.operatingSystem` to our normalized names, handling
/// the Flutter-web case where `Platform` is unavailable (returns `web`).
String _currentOs() {
  try {
    final os = Platform.operatingSystem;
    if (os == 'windows' ||
        os == 'macos' ||
        os == 'linux' ||
        os == 'android' ||
        os == 'ios' ||
        os == 'fuchsia') {
      return os;
    }
    return 'web';
  } catch (_) {
    return 'web';
  }
}
