import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/api/control_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

part 'nodes/local_node.dart';
part 'nodes/peer_dialogs.dart';
part 'nodes/peer_table.dart';
part 'nodes/peer_list.dart';
part 'nodes/peer_details_widgets.dart';
part 'nodes/helpers.dart';
part 'nodes/speed_test.dart';

class NodesPage extends StatefulWidget {
  const NodesPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  @override
  State<NodesPage> createState() => _NodesPageState();
}

class _NodesPageState extends State<NodesPage> {
  final _controlApi = ControlApi();
  final _hiddenPeerIds = <String>{};
  String? _copiedKey;
  String? _busyPeerId;

  @override
  void initState() {
    super.initState();
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
    _controlApi.close();
    super.dispose();
  }

  void _pruneHiddenPeers() {
    final snapshot = widget.statusStore.snapshot;
    if (!mounted || snapshot == null || _hiddenPeerIds.isEmpty) return;
    final currentPeerIds = snapshot.peers.map((peer) => peer.nodeId).toSet();
    final before = _hiddenPeerIds.length;
    _hiddenPeerIds.removeWhere((nodeId) => !currentPeerIds.contains(nodeId));
    if (_hiddenPeerIds.length != before) {
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: Listenable.merge([widget.statusStore, widget.settingsStore]),
      builder: (context, _) {
        final snapshot = widget.statusStore.snapshot;
        final peers = _dedupeAndSortPeers(
          snapshot?.peers ?? const <PeerSnapshot>[],
        ).where((peer) => !_hiddenPeerIds.contains(peer.nodeId)).toList();
        final settings = widget.settingsStore.settings;
        return PageScaffold(
          title: strings.nodes,
          subtitle: strings.nodesSubtitle,
          showHeader: widget.showHeader,
          children: [
            _LocalNodePanel(
              snapshot: snapshot,
              settings: settings,
              onEdit: () => _editLocalNode(snapshot),
            ),
            const SizedBox(height: 14),
            _PeerSummary(peers: peers),
            const SizedBox(height: 14),
            if (peers.isEmpty)
              AppPanel(
                title: strings.isZh ? '其他设备' : 'Other devices',
                child: Text(
                  strings.noPeers,
                  style: const TextStyle(
                    fontSize: 13,
                    color: AppTokens.colorTextSecondary,
                  ),
                ),
              )
            else
              _PeerList(
                peers: peers,
                copiedKey: _copiedKey,
                busyPeerId: _busyPeerId,
                onCopy: _copy,
                onDetails: _showPeerDetails,
                onEdit: _editPeer,
                onDelete: _deletePeer,
                onSpeedTest: _showSpeedTest,
              ),
          ],
        );
      },
    );
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
    final strings = AppStringsScope.of(context);
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
    final strings = AppStringsScope.of(context);
    final result = await _promptDeviceName(
      initialName: peer.displayName,
      title: strings.isZh ? '编辑设备名称' : 'Edit device name',
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

  Future<void> _deletePeer(PeerSnapshot peer) async {
    if (_busyPeerId != null) return;
    final strings = AppStringsScope.of(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(strings.isZh ? '移除设备' : 'Remove device'),
        content: _RemoveDeviceDialogContent(peer: peer, strings: strings),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(strings.cancel),
          ),
          FilledButton.icon(
            style: FilledButton.styleFrom(
              backgroundColor: AppTokens.colorBadText,
              foregroundColor: AppTokens.colorSurface,
            ),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            icon: const Icon(Icons.delete_outline_rounded, size: 17),
            label: Text(strings.isZh ? '移除设备' : 'Remove device'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
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
      if (!mounted) return;
      _showSnack(
        strings.isZh
            ? '设备已移除：${peer.displayName}'
            : 'Device removed: ${peer.displayName}',
      );
    } catch (error) {
      if (!mounted) return;
      _showSnack(error.toString());
    } finally {
      if (mounted && _busyPeerId == peer.nodeId) {
        setState(() => _busyPeerId = null);
      }
    }
  }

  Future<void> _showPeerDetails(PeerSnapshot peer) async {
    final strings = AppStringsScope.of(context);
    await showDialog<void>(
      context: context,
      builder: (dialogContext) =>
          _PeerDetailsDialog(peer: peer, strings: strings),
    );
  }

  Future<void> _showSpeedTest(PeerSnapshot peer) async {
    final strings = AppStringsScope.of(context);
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => _SpeedTestDialog(
        peer: peer,
        statusStore: widget.statusStore,
        strings: strings,
      ),
    );
  }

  Future<String?> _promptDeviceName({
    required String initialName,
    required String title,
  }) async {
    final strings = AppStringsScope.of(context);
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
    final strings = AppStringsScope.of(context);
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
                      const SizedBox(height: 12),
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
