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
// Mobile platforms expose local VPN control only when their native bridge is
// implemented; remote management remains independent of local VPN support.
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
    this.canReceiveRoomLinks = false,
    this.canOpenExternalUrls = false,
    this.canReadNativeBuildInfo = false,
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

  /// The `app_links` plugin has a registered implementation on this platform.
  final bool canReceiveRoomLinks;

  /// The `url_launcher` plugin has a registered implementation on this platform.
  final bool canOpenExternalUrls;

  /// The OHOS host registers the read-only native engine build-info method.
  final bool canReadNativeBuildInfo;

  /// Baseline capabilities for a normalized OS name.
  ///
  /// Platform names include windows, macos, linux, android, ios, fuchsia,
  /// ohos, and web. Android uses the native VpnService bridge. OHOS permits
  /// remote management, native build info, and native VPN lifecycle control.
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
          canReceiveRoomLinks: true,
          canOpenExternalUrls: true,
        );
      case 'android':
        return const PlatformCapabilities(
          canControlLocalDaemon: true,
          canRequestElevation: false,
          canVerifyRoutes: true,
          canRepairRoutes: false,
          canOpenLocalLogs: false,
          canCreateSupportBundle: false,
          canUseSystemTray: false,
          canActAsLocalVpnNode: true,
          canManageRemoteDevices: true,
          canReceiveRoomLinks: true,
          canOpenExternalUrls: true,
        );
      case 'ios':
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
          canReceiveRoomLinks: true,
          canOpenExternalUrls: true,
        );
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
          canReceiveRoomLinks: false,
          canOpenExternalUrls: false,
        );
      case 'ohos':
        return const PlatformCapabilities(
          canControlLocalDaemon: true,
          canRequestElevation: false,
          canVerifyRoutes: false,
          canRepairRoutes: false,
          canOpenLocalLogs: false,
          canCreateSupportBundle: false,
          canUseSystemTray: false,
          canActAsLocalVpnNode: true,
          canManageRemoteDevices: true,
          canReceiveRoomLinks: false,
          canOpenExternalUrls: false,
          canReadNativeBuildInfo: true,
        );
      case 'web':
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
          canReceiveRoomLinks: true,
          canOpenExternalUrls: true,
        );
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
          canReceiveRoomLinks: false,
          canOpenExternalUrls: false,
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
      canReceiveRoomLinks: canReceiveRoomLinks,
      canOpenExternalUrls: canOpenExternalUrls,
      canReadNativeBuildInfo: canReadNativeBuildInfo,
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
        os == 'fuchsia' ||
        os == 'ohos') {
      return os;
    }
    return 'web';
  } catch (_) {
    return 'web';
  }
}
