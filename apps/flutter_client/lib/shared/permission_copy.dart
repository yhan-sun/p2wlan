/// Localized presentation for permission preflight results.
///
/// The core `PermissionPreflight` keeps raw technical messages (in any
/// language) for diagnostics; this layer translates the structured facts
/// (`reasonCode`, `platform`, and each check's machine `code` + `status`) into
/// user-facing copy via [AppStrings]. It never matches on raw message text.
library;

import '../app/app_strings.dart';
import '../core/capabilities/permission_preflight.dart';

/// Localized recommendation for the whole preflight, keyed by `reasonCode`.
String permissionRecommendedAction(
  AppStrings strings,
  PermissionPreflight preflight,
) {
  switch (preflight.reasonCode) {
    case 'elevation_required':
      return strings.permActionElevationRequired();
    case 'tun_runtime_verification':
      return strings.permActionTunRuntimeVerification();
    case 'tun_device_missing':
      return strings.permActionTunDeviceMissing();
    case 'ready':
      return strings.permActionReady();
    case 'wintun_missing':
      return strings.permActionWintunMissing();
    case 'platform_unsupported':
      return strings.permActionPlatformUnsupported();
    default:
      return strings.permActionGeneric(preflight.platform);
  }
}

/// Localized copy for a single check, keyed by its machine `code`.
class PermissionCheckPresentation {
  const PermissionCheckPresentation({
    required this.status,
    required this.title,
    required this.statusLabel,
    required this.detail,
  });

  /// Raw machine status (`pass` / `warn` / `fail`) for tone mapping.
  final String status;
  final String title;
  final String statusLabel;
  final String detail;
}

List<PermissionCheckPresentation> permissionCheckPresentations(
  AppStrings strings,
  PermissionPreflight preflight,
) {
  return [for (final check in preflight.checks) _presentCheck(strings, check)];
}

PermissionCheckPresentation _presentCheck(
  AppStrings strings,
  PermissionCheck check,
) {
  final title = switch (check.code) {
    'euid' => strings.permCheckEuid,
    'tun_node' => strings.permCheckTunNode,
    'dev_net_tun' => strings.permCheckDevNetTun,
    'daemon_cap' => strings.permCheckDaemonCap,
    'admin' => strings.permCheckAdmin,
    'wintun' => strings.permCheckWintun,
    'platform' => strings.permCheckPlatform,
    _ => strings.permCheckTitleGeneric,
  };
  final statusLabel = switch (check.status) {
    'pass' => strings.permCheckStatusPass(),
    'fail' => strings.permCheckStatusFail(),
    _ => strings.permCheckStatusWarn(),
  };
  final detail = _checkDetail(strings, check);
  return PermissionCheckPresentation(
    status: check.status,
    title: title,
    statusLabel: statusLabel,
    detail: detail,
  );
}

String _checkDetail(AppStrings strings, PermissionCheck check) {
  final status = check.status;
  switch (check.code) {
    case 'euid':
      return status == 'pass'
          ? strings.permCheckEuidPass()
          : status == 'fail'
          ? strings.permCheckEuidFail()
          : strings.permCheckEuidWarn();
    case 'tun_node':
      return status == 'pass'
          ? strings.permCheckTunNodePass()
          : strings.permCheckTunNodeWarn();
    case 'dev_net_tun':
      return status == 'pass'
          ? strings.permCheckDevNetTunPass()
          : strings.permCheckDevNetTunFail();
    case 'daemon_cap':
      return status == 'pass'
          ? strings.permCheckDaemonCapPass()
          : strings.permCheckDaemonCapWarn();
    case 'admin':
      return status == 'pass'
          ? strings.permCheckAdminPass()
          : strings.permCheckAdminFail();
    case 'wintun':
      return status == 'pass'
          ? strings.permCheckWintunPass()
          : strings.permCheckWintunFail();
    case 'platform':
      return strings.permCheckPlatformFail();
    default:
      return status == 'pass'
          ? strings.permCheckStatusPass()
          : status == 'fail'
          ? strings.permCheckStatusFail()
          : strings.permCheckStatusWarn();
  }
}
