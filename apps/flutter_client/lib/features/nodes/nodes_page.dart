import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/api/control_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/layout/app_breakpoints.dart';
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

enum _NodesLayout { compact, medium, expanded }

class NodesPage extends StatefulWidget {
  const NodesPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
    this.controlApi,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  /// Control-plane API override (primarily for tests); defaults to a real
  /// [ControlApi].
  final ControlApi? controlApi;

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
  String? _selectedPeerId;
  String? _copiedKey;
  String? _busyPeerId;

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
    if (_selectedPeerId != null && !currentPeerIds.contains(_selectedPeerId)) {
      _selectedPeerId = null;
      changed = true;
    }
    if (changed) setState(() {});
  }

  void _focusSearch() {
    _searchFocusNode.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
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
            final snapshot = widget.statusStore.snapshot;
            final allPeers = _dedupeAndSortPeers(
              snapshot?.peers ?? const <PeerSnapshot>[],
            ).where((peer) => !_hiddenPeerIds.contains(peer.nodeId)).toList();
            final query = _searchController.text;
            final visiblePeers = _applySort(
              _applySearch(allPeers, query),
              _sort,
            ).where((peer) => _filterMatches(_filter, peer)).toList();
            final selectedPeer = _resolveSelectedPeer(visiblePeers);
            final settings = widget.settingsStore.settings;
            return PageScaffold(
              title: stringsOf(context).nodes,
              subtitle: stringsOf(context).nodesSubtitle,
              showHeader: widget.showHeader,
              maxWidth: nodesPageMaxWidth,
              children: [
                _LocalNodePanel(
                  snapshot: snapshot,
                  settings: settings,
                  daemonReachable: widget.statusStore.daemonReachable,
                  onEdit: () => _editLocalNode(snapshot),
                ),
                const SizedBox(height: AppTokens.space14),
                _NodeToolbar(
                  searchController: _searchController,
                  searchFocusNode: _searchFocusNode,
                  filter: _filter,
                  sort: _sort,
                  allPeers: allPeers,
                  onFilterChanged: (filter) => setState(() => _filter = filter),
                  onSortChanged: (sort) => setState(() => _sort = sort),
                  onQueryChanged: () => setState(() {}),
                  onClearSearch: () => setState(_searchController.clear),
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
                          constraints.maxWidth >=
                              AppBreakpoints.expandedMinWidth
                          ? _NodesLayout.expanded
                          : constraints.maxWidth <
                                AppBreakpoints.compactMaxWidth
                          ? _NodesLayout.compact
                          : _NodesLayout.medium;
                      if (layout == _NodesLayout.expanded) {
                        return Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(
                              flex: 6,
                              child: _PeerList(
                                peers: visiblePeers,
                                showGroups:
                                    _showGroupsForFilter(_filter) &&
                                    _sort == _NodeSort.recommended,
                                selectedPeerId: selectedPeer?.nodeId,
                                copiedKey: _copiedKey,
                                busyPeerId: _busyPeerId,
                                compact: false,
                                onCopy: _copy,
                                onEdit: _editPeer,
                                onDelete: _deletePeer,
                                onSpeedTest: _showSpeedTest,
                                onTap: (peer) => _openPeer(peer, layout),
                              ),
                            ),
                            const SizedBox(width: AppTokens.space16),
                            Expanded(
                              flex: 4,
                              child: _PeerDetailPane(
                                key: const Key('nodes-detail-pane'),
                                peer: selectedPeer,
                                strings: stringsOf(context),
                                copiedKey: _copiedKey,
                                busyPeerId: _busyPeerId,
                                onCopy: _copy,
                                onEdit: _editPeer,
                                onDelete: _deletePeer,
                                onSpeedTest: _showSpeedTest,
                              ),
                            ),
                          ],
                        );
                      }
                      return _PeerList(
                        peers: visiblePeers,
                        showGroups:
                            _showGroupsForFilter(_filter) &&
                            _sort == _NodeSort.recommended,
                        selectedPeerId: null,
                        copiedKey: _copiedKey,
                        busyPeerId: _busyPeerId,
                        compact: layout == _NodesLayout.compact,
                        onCopy: _copy,
                        onEdit: _editPeer,
                        onDelete: _deletePeer,
                        onSpeedTest: _showSpeedTest,
                        onTap: (peer) => _openPeer(peer, layout),
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

  /// Derived selection: the effective detail peer must always belong to the
  /// current search/filter results. `_selectedPeerId` stays as a persistent
  /// preference so clearing the filter can restore it, but a hidden peer is
  /// never rendered as selected.
  PeerSnapshot? _resolveSelectedPeer(List<PeerSnapshot> visiblePeers) {
    final id = _selectedPeerId;
    if (id != null) {
      for (final peer in visiblePeers) {
        if (peer.nodeId == id) return peer;
      }
    }
    return visiblePeers.isEmpty ? null : visiblePeers.first;
  }

  void _openPeer(PeerSnapshot peer, _NodesLayout layout) {
    setState(() => _selectedPeerId = peer.nodeId);
    switch (layout) {
      case _NodesLayout.expanded:
        break;
      case _NodesLayout.medium:
        _showPeerDetails(peer, mobile: false);
      case _NodesLayout.compact:
        _showPeerDetails(peer, mobile: true);
    }
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
            ? (strings.isZh
                  ? '本机节点已同步：$savedName / ${dash(savedVirtualIp)}。重启 P2WLAN 后 IP 生效。'
                  : 'This device synced: $savedName / ${dash(savedVirtualIp)}. Restart P2WLAN to apply IP changes.')
            : (strings.isZh
                  ? '本机节点已保存：$savedName / ${dash(savedVirtualIp)}。启动后生效。'
                  : 'This device saved: $savedName / ${dash(savedVirtualIp)}. Applies on next start.'),
      );
    } catch (error) {
      if (!mounted) return;
      _showSnack(error.toString());
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
      _showSnack(
        strings.isZh ? '设备名称已同步：$savedName' : 'Device name synced: $savedName',
      );
      await widget.statusStore.refresh();
    } catch (error) {
      if (!mounted) return;
      _showSnack(error.toString());
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
      _showSnack(
        strings.isZh
            ? '设备已移除：${peer.displayName}'
            : 'Device removed: ${peer.displayName}',
      );
      return true;
    } catch (error) {
      if (!mounted) return false;
      _showSnack(error.toString());
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
      await Navigator.of(context).push(
        MaterialPageRoute<void>(
          fullscreenDialog: true,
          builder: (_) => _MobilePeerDetails(
            peer: peer,
            strings: stringsOf(context),
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
                          error = strings.isZh
                              ? '设备名称不能为空'
                              : 'Device name is required';
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
                title: Text(strings.isZh ? '编辑本机节点' : 'Edit this device'),
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
                          labelText: strings.isZh
                              ? '期望虚拟 IP'
                              : 'Requested virtual IP',
                          helperText: strings.isZh
                              ? '留空由控制面自动分配；修改后重启 P2WLAN 生效。'
                              : 'Leave blank for automatic assignment; restart P2WLAN after changing it.',
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
                          error = strings.isZh
                              ? '设备名称不能为空'
                              : 'Device name is required';
                        });
                        return;
                      }
                      final parsedIp = virtualIp.isEmpty
                          ? null
                          : InternetAddress.tryParse(virtualIp);
                      if (virtualIp.isNotEmpty &&
                          parsedIp?.type != InternetAddressType.IPv4) {
                        setDialogState(() {
                          error = strings.isZh
                              ? '虚拟 IP 格式不正确，例如 10.20.0.42'
                              : 'Virtual IP must look like 10.20.0.42';
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
