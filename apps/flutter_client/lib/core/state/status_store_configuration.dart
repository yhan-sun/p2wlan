part of 'status_store.dart';

typedef _PrimaryLaunchConfiguration = ({
  String networkId,
  String virtualIp,
  String deviceName,
  String overlayCidr,
  String interfaceName,
  int mtu,
  String udpBind,
  String udpAdvertise,
  String socketPool,
  String relayServers,
});

_PrimaryLaunchConfiguration _primaryLaunchConfiguration(
  AppSettings settings, {
  String? assignedVirtualIp,
}) => (
  networkId: settings.networkId.trim(),
  virtualIp: isRoomNetwork(settings.networkId)
      ? ''
      : assignedVirtualIp ?? settings.virtualIp.trim(),
  deviceName: settings.deviceName.trim(),
  overlayCidr: settings.overlayCidr.trim(),
  interfaceName: settings.effectiveTunInterface,
  mtu: settings.mtu,
  udpBind: settings.udpBind.trim(),
  udpAdvertise: settings.udpAdvertise.trim(),
  socketPool: normalizeSocketPool(settings.socketPool),
  relayServers: settings.relayServers.trim(),
);

/// One bounded witness for the post-start catalog refresh. The first accepted
/// runtime may replace the pre-start process; a later replacement has no proof
/// that it received this launch's configuration.
class _PrimaryStartWitness {
  _PrimaryStartWitness(this.revision);
  final int revision;
  (int?, int?)? _runtime;
  bool _replaced = false;

  void observe(DiagnosticsSnapshot snapshot, int currentRevision) {
    if (currentRevision != revision) return;
    final runtime = (snapshot.processId, snapshot.runtimeIncarnation);
    if (runtime == (null, null) || (_runtime != null && _runtime != runtime)) {
      _replaced = true;
    }
    _runtime ??= runtime;
  }

  bool matches(DiagnosticsSnapshot? snapshot) =>
      !_replaced &&
      _runtime != null &&
      snapshot != null &&
      _runtime == (snapshot.processId, snapshot.runtimeIncarnation);
}

extension StatusStorePrimaryConfiguration on StatusStore {
  /// Connection settings notify only after persistence succeeds. For an
  /// externally started daemon, its launch configuration remains unknown;
  /// remember only the subsequent saved changes that still need applying.
  bool _observePrimaryConfiguration({required bool ownerChanged}) {
    final wasPending = _primaryConfigurationPending;
    final next = _primaryLaunchConfiguration(settingsStore.settings);
    if (ownerChanged) {
      _committedPrimaryConfiguration = next;
      _appliedPrimaryConfiguration = null;
      _primaryConfigurationPending = false;
    } else if (next != _committedPrimaryConfiguration) {
      _committedPrimaryConfiguration = next;
      final applied = _appliedPrimaryConfiguration;
      _primaryConfigurationPending = applied != null
          ? next != applied
          : wasPending || daemonReachable || daemonStarting;
    }
    return wasPending != _primaryConfigurationPending;
  }

  /// Called only after a successful start whose account, endpoint and revision
  /// still match. Confirm the captured launch input, never the newest settings
  /// merely because a start finished while another save was in progress.
  void _confirmPrimaryConfiguration(AppSettings launched) {
    final assignedIp = _snapshot?.virtualIp.trim() ?? '';
    final runtimeAssignedIp =
        Platform.isAndroid &&
            launched.virtualIp.trim().isEmpty &&
            assignedIp.isNotEmpty &&
            settingsStore.settings.virtualIp.trim() == assignedIp
        ? assignedIp
        : null;
    _appliedPrimaryConfiguration = _primaryLaunchConfiguration(
      launched,
      assignedVirtualIp: runtimeAssignedIp,
    );
    final wasPending = _primaryConfigurationPending;
    _primaryConfigurationPending =
        _committedPrimaryConfiguration != _appliedPrimaryConfiguration;
    if (wasPending != _primaryConfigurationPending) _notifySessionChanged();
  }

  Future<DaemonCommandResult> _stopPrimaryRuntime() async {
    final revision = _refreshGeneration;
    final url = settingsStore.settings.diagnosticsUrl;
    final result = await daemonController.stop(url);
    if (result.ok &&
        !_disposed &&
        revision == _refreshGeneration &&
        url == settingsStore.settings.diagnosticsUrl) {
      // Stopping invalidates launch evidence, not the saved apply intent.
      _appliedPrimaryConfiguration = null;
    }
    return result;
  }
}
