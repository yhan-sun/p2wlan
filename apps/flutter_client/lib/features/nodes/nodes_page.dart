import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/api/control_api.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/security/redactor.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/layout/app_breakpoints.dart';
import '../../shared/widgets/app_back_button.dart';
import '../../shared/widgets/device_type_icon.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

part 'nodes/local_node.dart';
part 'nodes/toolbar.dart';
part 'nodes/peer_list.dart';
part 'nodes/peer_detail.dart';
part 'nodes/peer_dialogs.dart';
part 'nodes/helpers.dart';
part 'nodes/speed_test.dart';
part 'nodes/remote_only.dart';

enum _NodesLayout { compact, medium, expanded }

class NodesPage extends StatefulWidget {
  const NodesPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
    this.controlApi,
    this.capabilities,
    this.initialPeerId,
    this.onInitialPeerOpened,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  /// Control-plane API override (primarily for tests); defaults to a real
  /// [ControlApi].
  final ControlApi? controlApi;

  /// Platform capability override. Mobile clients do not own a local daemon
  /// or TUN, so they render an explicit remote-management state instead of a
  /// fabricated offline local node.
  final PlatformCapabilities? capabilities;

  /// Optional peer requested by another shell surface (Home). The page opens
  /// it through the exact same list interaction after the Devices page has
  /// mounted, so detail actions never diverge by entry point.
  final String? initialPeerId;
  final VoidCallback? onInitialPeerOpened;

  @override
  State<NodesPage> createState() => _NodesPageState();
}

class _NodesPageState extends State<NodesPage> {
  late final ControlApi _controlApi;
  final _hiddenPeerIds = <String>{};
  final _searchController = TextEditingController();
  final _searchFocusNode = FocusNode();
  var _filter = _NodeFilter.all;
  var _sort = _NodeSort.recommended;
  String? _copiedKey;
  String? _busyPeerId;
  String? _openedInitialPeerId;
  var _initialPeerOpenScheduled = false;

  @override
  void initState() {
    super.initState();
    _controlApi = widget.controlApi ?? ControlApi();
    widget.statusStore.addListener(_pruneHiddenPeers);
  }

  @override
  void didUpdateWidget(covariant NodesPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.statusStore != widget.statusStore) {
      oldWidget.statusStore.removeListener(_pruneHiddenPeers);
      widget.statusStore.addListener(_pruneHiddenPeers);
    }
    if (oldWidget.initialPeerId != widget.initialPeerId) {
      _openedInitialPeerId = null;
      _scheduleInitialPeerOpen();
    }
  }

  @override
  void dispose() {
    widget.statusStore.removeListener(_pruneHiddenPeers);
    _searchController.dispose();
    _searchFocusNode.dispose();
    _controlApi.close();
    super.dispose();
  }

  void _pruneHiddenPeers() {
    final snapshot = widget.statusStore.snapshot;
    if (!mounted || snapshot == null) return;
    final currentPeerIds = snapshot.peers.map((peer) => peer.nodeId).toSet();
    final before = _hiddenPeerIds.length;
    _hiddenPeerIds.removeWhere((nodeId) => !currentPeerIds.contains(nodeId));
    var changed = _hiddenPeerIds.length != before;
    if (changed) setState(() {});
  }

  void _focusSearch() {
    _searchFocusNode.requestFocus();
  }

  void _scheduleInitialPeerOpen() {
    final requestedId = widget.initialPeerId?.trim();
    if (requestedId == null ||
        requestedId.isEmpty ||
        requestedId == _openedInitialPeerId ||
        _initialPeerOpenScheduled) {
      return;
    }
    _initialPeerOpenScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _initialPeerOpenScheduled = false;
      if (!mounted || widget.initialPeerId?.trim() != requestedId) return;
      final peers =
          widget.statusStore.snapshot?.peers ?? const <PeerSnapshot>[];
      PeerSnapshot? requestedPeer;
      for (final peer in peers) {
        if (peer.nodeId == requestedId) {
          requestedPeer = peer;
          break;
        }
      }
      if (requestedPeer == null) return;
      _openedInitialPeerId = requestedId;
      _openPeer(requestedPeer);
      widget.onInitialPeerOpened?.call();
    });
  }

  @override
  Widget build(BuildContext context) {
    _scheduleInitialPeerOpen();
    return CallbackShortcuts(
      bindings: {
        const SingleActivator(LogicalKeyboardKey.keyF, control: true):
            _focusSearch,
        const SingleActivator(LogicalKeyboardKey.keyF, meta: true):
            _focusSearch,
      },
      child: Focus(
        autofocus: true,
        child: AnimatedBuilder(
          animation: Listenable.merge([
            widget.statusStore,
            widget.settingsStore,
          ]),
          builder: (context, _) {
            final capabilities =
                widget.capabilities ?? PlatformCapabilities.current();
            final remoteOnly = !capabilities.canActAsLocalVpnNode;
            final snapshot = widget.statusStore.snapshot;
            final allPeers = _dedupeAndSortPeers(
              snapshot?.peers ?? const <PeerSnapshot>[],
            ).where((peer) => !_hiddenPeerIds.contains(peer.nodeId)).toList();
            final query = _searchController.text;
            final visiblePeers = _applySort(
              _applySearch(allPeers, query),
              _sort,
            ).where((peer) => _filterMatches(_filter, peer)).toList();
            final peerTransferRates = widget.statusStore.snapshotStale
                ? const <String, int>{}
                : widget.statusStore.peerTransferRatesBytesPerSecond;
            final settings = widget.settingsStore.settings;
            return PageScaffold(
              title: stringsOf(context).nodes,
              subtitle: stringsOf(context).nodesSubtitle,
              showHeader: widget.showHeader,
              maxWidth: nodesPageMaxWidth,
              children: remoteOnly
                  ? const [_RemoteOnlyNodesState()]
                  : [
                      _NodeToolbar(
                        searchController: _searchController,
                        searchFocusNode: _searchFocusNode,
                        filter: _filter,
                        sort: _sort,
                        allPeers: allPeers,
                        onFilterChanged: (filter) =>
                            setState(() => _filter = filter),
                        onSortChanged: (sort) => setState(() => _sort = sort),
                        onQueryChanged: () => setState(() {}),
                        onClearSearch: () => setState(_searchController.clear),
                      ),
                      if (widget.statusStore.snapshotStale) ...[
                        const SizedBox(height: AppTokens.space8),
                        Row(
                          children: [
                            Container(
                              width: 7,
                              height: 7,
                              decoration: BoxDecoration(
                                color: P2WlanColors.of(context).warningDot,
                                shape: BoxShape.circle,
                              ),
                            ),
                            const SizedBox(width: 7),
                            Text(
                              stringsOf(context).stale,
                              style: TextStyle(
                                color: P2WlanColors.of(context).warningText,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                      ],
                      const SizedBox(height: AppTokens.space14),
                      _LocalNodePanel(
                        snapshot: snapshot,
                        settings: settings,
                        daemonReachable: widget.statusStore.daemonReachable,
                        onEdit: () => _editLocalNode(snapshot),
                      ),
                      const SizedBox(height: AppTokens.space12),
                      if (allPeers.isEmpty)
                        _NodesEmptyState(
                          icon: Icons.devices_other_rounded,
                          title: stringsOf(context).noPeersTitle,
                          body: stringsOf(context).noPeersBody,
                        )
                      else if (visiblePeers.isEmpty)
                        _NodesEmptyState(
                          icon: query.trim().isNotEmpty
                              ? Icons.search_off_rounded
                              : Icons.filter_alt_off_rounded,
                          title: query.trim().isNotEmpty
                              ? stringsOf(context).noSearchResultsTitle
                              : stringsOf(context).noFilterResultsTitle,
                          body: query.trim().isNotEmpty
                              ? stringsOf(context).noSearchResultsBody
                              : stringsOf(context).noFilterResultsBody,
                          actionLabel: query.trim().isNotEmpty
                              ? stringsOf(context).clearSearch
                              : stringsOf(context).clearFilter,
                          onAction: query.trim().isNotEmpty
                              ? () => setState(_searchController.clear)
                              : () => setState(() => _filter = _NodeFilter.all),
                        )
                      else
                        LayoutBuilder(
                          builder: (context, constraints) {
                            final layout =
                                constraints.maxWidth >= nodesInspectorMinWidth
                                ? _NodesLayout.expanded
                                : constraints.maxWidth <
                                      AppBreakpoints.compactMaxWidth
                                ? _NodesLayout.compact
                                : _NodesLayout.medium;
                            return _PeerList(
                              peers: visiblePeers,
                              peerTransferRates: peerTransferRates,
                              compact: layout == _NodesLayout.compact,
                              onTap: _openPeer,
                            );
                          },
                        ),
                    ],
            );
          },
        ),
      ),
    );
  }

  void _openPeer(PeerSnapshot peer) {
    final capabilities = widget.capabilities ?? PlatformCapabilities.current();
    _showPeerDetails(peer, mobile: !capabilities.canUseSystemTray);
  }

  Future<void> _copy(String value, String key) async {
    if (value.trim().isEmpty) return;
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    setState(() => _copiedKey = key);
    Future<void>.delayed(const Duration(milliseconds: 1400), () {
      if (mounted && _copiedKey == key) setState(() => _copiedKey = null);
    });
  }

  void _showSnack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _editLocalNode(DiagnosticsSnapshot? snapshot) async {
    final strings = stringsOf(context);
    final settings = widget.settingsStore.settings;
    final initialName = settings.deviceName.trim().isEmpty
        ? await resolveDefaultDeviceName()
        : settings.deviceName.trim();
    final initialVirtualIp = settings.virtualIp.trim().isNotEmpty
        ? settings.virtualIp.trim()
        : snapshot?.virtualIp.trim() ?? '';
    if (!mounted) return;
    final result = await _promptLocalNodeProfile(
      initialName: initialName,
      initialVirtualIp: initialVirtualIp,
    );
    if (result == null) return;

    final nodeId = snapshot?.nodeId.trim() ?? '';
    final canSync =
        !settings.manualMode &&
        settings.authToken.trim().isNotEmpty &&
        nodeId.isNotEmpty;
    var savedName = result.deviceName;
    var savedVirtualIp = result.virtualIp;
    try {
      if (canSync) {
        final saved = await _controlApi.updateDevice(
          controlServer: settings.controlServer,
          authToken: settings.authToken,
          deviceId: nodeId,
          deviceName: result.deviceName,
          virtualIp: result.virtualIp,
        );
        savedName = saved.deviceName.trim().isEmpty
            ? result.deviceName
            : saved.deviceName;
        savedVirtualIp = saved.virtualIp.trim().isEmpty
            ? result.virtualIp
            : saved.virtualIp;
      }
      await widget.settingsStore.updateSettings(
        settings.copyWith(deviceName: savedName, virtualIp: savedVirtualIp),
      );
      await widget.statusStore.refresh();
      if (!mounted) return;
      _showSnack(
        canSync
            ? strings.nodeSynced(savedName, dash(savedVirtualIp))
            : strings.nodeSaved(savedName, dash(savedVirtualIp)),
      );
    } catch (error) {
      if (!mounted) return;
      _showSnack(strings.deviceSaveFailed);
    }
  }

  Future<void> _editPeer(PeerSnapshot peer) async {
    if (_busyPeerId != null) return;
    final strings = stringsOf(context);
    final result = await _promptDeviceName(
      initialName: peer.displayName,
      title: strings.renameDevice,
    );
    if (result == null) return;
    final settings = widget.settingsStore.settings;
    setState(() => _busyPeerId = peer.nodeId);
    try {
      final savedName = await _controlApi.renameDevice(
        controlServer: settings.controlServer,
        authToken: settings.authToken,
        deviceId: peer.nodeId,
        deviceName: result,
      );
      if (!mounted) return;
      _showSnack(strings.deviceNameSynced(savedName));
      await widget.statusStore.refresh();
    } catch (error) {
      if (!mounted) return;
      _showSnack(strings.deviceRenameFailed);
    } finally {
      if (mounted && _busyPeerId == peer.nodeId) {
        setState(() => _busyPeerId = null);
      }
    }
  }

  /// Removes a device from the control plane. Returns true only when the
  /// control-plane deletion succeeded and the peer is now hidden; false when
  /// the user cancelled or the deletion failed.
  Future<bool> _deletePeer(PeerSnapshot peer) async {
    if (_busyPeerId != null) return false;
    final strings = stringsOf(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(strings.removeDevice),
        content: _RemoveDeviceDialogContent(peer: peer, strings: strings),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(strings.cancel),
          ),
          FilledButton.icon(
            style: FilledButton.styleFrom(
              backgroundColor: P2WlanColors.of(context).dangerText,
              foregroundColor: P2WlanColors.of(context).dangerSurface,
            ),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            icon: const Icon(Icons.delete_outline_rounded, size: 17),
            label: Text(strings.removeDevice),
          ),
        ],
      ),
    );
    if (confirmed != true) return false;
    final settings = widget.settingsStore.settings;
    setState(() => _busyPeerId = peer.nodeId);
    try {
      await _controlApi.deleteDevice(
        controlServer: settings.controlServer,
        authToken: settings.authToken,
        deviceId: peer.nodeId,
      );
      if (mounted) setState(() => _hiddenPeerIds.add(peer.nodeId));
      await widget.statusStore.refresh();
      if (!mounted) return true;
      _showSnack(strings.deviceRemoved(peer.displayName));
      return true;
    } catch (error) {
      if (!mounted) return false;
      _showSnack(strings.deviceRemoveFailed);
      return false;
    } finally {
      if (mounted && _busyPeerId == peer.nodeId) {
        setState(() => _busyPeerId = null);
      }
    }
  }

  Future<void> _showPeerDetails(
    PeerSnapshot peer, {
    required bool mobile,
  }) async {
    if (mobile) {
      await Navigator.of(context, rootNavigator: true).push(
        MaterialPageRoute<void>(
          settings: RouteSettings(name: '/devices/${peer.nodeId}'),
          builder: (_) => _MobilePeerDetails(
            peer: peer,
            strings: stringsOf(context),
            statusStore: widget.statusStore,
            copiedKey: _copiedKey,
            busyPeerId: _busyPeerId,
            onCopy: _copy,
            onEdit: _editPeer,
            onDelete: _deletePeer,
            onSpeedTest: _showSpeedTest,
          ),
        ),
      );
      return;
    }
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => _PeerDetailsDialog(
        peer: peer,
        strings: stringsOf(context),
        statusStore: widget.statusStore,
        copiedKey: _copiedKey,
        busyPeerId: _busyPeerId,
        onCopy: _copy,
        onEdit: _editPeer,
        onDelete: _deletePeer,
        onSpeedTest: _showSpeedTest,
      ),
    );
  }

  Future<void> _showSpeedTest(PeerSnapshot peer) async {
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => _SpeedTestDialog(
        peer: peer,
        statusStore: widget.statusStore,
        strings: stringsOf(context),
      ),
    );
  }

  Future<String?> _promptDeviceName({
    required String initialName,
    required String title,
  }) async {
    final strings = stringsOf(context);
    final controller = TextEditingController(text: initialName);
    String? error;
    try {
      final result = await showDialog<String>(
        context: context,
        builder: (dialogContext) {
          return StatefulBuilder(
            builder: (context, setDialogState) {
              return AlertDialog(
                title: Text(title),
                content: TextField(
                  controller: controller,
                  autofocus: true,
                  decoration: InputDecoration(
                    labelText: strings.deviceName,
                    errorText: error,
                  ),
                  onSubmitted: (value) =>
                      Navigator.of(dialogContext).pop(value),
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.of(dialogContext).pop(),
                    child: Text(strings.cancel),
                  ),
                  FilledButton(
                    onPressed: () {
                      final name = controller.text.trim();
                      if (name.isEmpty) {
                        setDialogState(() {
                          error = strings.deviceNameRequired;
                        });
                        return;
                      }
                      Navigator.of(dialogContext).pop(name);
                    },
                    child: Text(strings.save),
                  ),
                ],
              );
            },
          );
        },
      );
      final name = result?.trim();
      if (name == null || name.isEmpty) return null;
      return name;
    } finally {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        controller.dispose();
      });
    }
  }

  Future<_LocalNodeProfileResult?> _promptLocalNodeProfile({
    required String initialName,
    required String initialVirtualIp,
  }) async {
    final strings = stringsOf(context);
    final nameController = TextEditingController(text: initialName);
    final ipController = TextEditingController(text: initialVirtualIp);
    String? error;
    try {
      final result = await showDialog<_LocalNodeProfileResult>(
        context: context,
        builder: (dialogContext) {
          return StatefulBuilder(
            builder: (context, setDialogState) {
              return AlertDialog(
                title: Text(strings.editThisDevice),
                content: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 420),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      TextField(
                        controller: nameController,
                        autofocus: true,
                        decoration: InputDecoration(
                          labelText: strings.deviceName,
                        ),
                      ),
                      const SizedBox(height: AppTokens.space12),
                      TextField(
                        controller: ipController,
                        decoration: InputDecoration(
                          labelText: strings.requestedVirtualIp,
                          helperText: strings.requestedVirtualIpHelper,
                          errorText: error,
                        ),
                        keyboardType: TextInputType.number,
                      ),
                    ],
                  ),
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.of(dialogContext).pop(),
                    child: Text(strings.cancel),
                  ),
                  FilledButton(
                    onPressed: () {
                      final name = nameController.text.trim();
                      final virtualIp = ipController.text.trim();
                      if (name.isEmpty) {
                        setDialogState(() {
                          error = strings.deviceNameRequired;
                        });
                        return;
                      }
                      final parsedIp = virtualIp.isEmpty
                          ? null
                          : InternetAddress.tryParse(virtualIp);
                      if (virtualIp.isNotEmpty &&
                          parsedIp?.type != InternetAddressType.IPv4) {
                        setDialogState(() {
                          error = strings.virtualIpFormatHint;
                        });
                        return;
                      }
                      Navigator.of(dialogContext).pop(
                        _LocalNodeProfileResult(
                          deviceName: name,
                          virtualIp: virtualIp,
                        ),
                      );
                    },
                    child: Text(strings.save),
                  ),
                ],
              );
            },
          );
        },
      );
      return result;
    } finally {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        nameController.dispose();
        ipController.dispose();
      });
    }
  }
}

AppStrings stringsOf(BuildContext context) => AppStringsScope.of(context);
