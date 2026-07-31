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
        final relayFallbackLatencyMs = snapshot?.relayConnected == true
            ? snapshot?.relaySelection.latencyMs
            : null;
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
                relayFallbackLatencyMs: relayFallbackLatencyMs,
                onDetails: (peer) => _showPeerDetails(
                  peer,
                  relayFallbackLatencyMs: relayFallbackLatencyMs,
                ),
                onEdit: _editPeer,
                onDelete: _deletePeer,
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

  Future<void> _showPeerDetails(
    PeerSnapshot peer, {
    required int? relayFallbackLatencyMs,
  }) async {
    final strings = AppStringsScope.of(context);
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => _PeerDetailsDialog(
        peer: peer,
        strings: strings,
        relayFallbackLatencyMs: relayFallbackLatencyMs,
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
                onSubmitted: (value) => Navigator.of(dialogContext).pop(value),
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
    controller.dispose();
    final name = result?.trim();
    if (name == null || name.isEmpty) return null;
    return name;
  }

  Future<_LocalNodeProfileResult?> _promptLocalNodeProfile({
    required String initialName,
    required String initialVirtualIp,
  }) async {
    final strings = AppStringsScope.of(context);
    final nameController = TextEditingController(text: initialName);
    final ipController = TextEditingController(text: initialVirtualIp);
    String? error;
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
    nameController.dispose();
    ipController.dispose();
    return result;
  }
}

class _LocalNodeProfileResult {
  const _LocalNodeProfileResult({
    required this.deviceName,
    required this.virtualIp,
  });

  final String deviceName;
  final String virtualIp;
}

class _LocalNodePanel extends StatelessWidget {
  const _LocalNodePanel({
    required this.snapshot,
    required this.settings,
    required this.onEdit,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final deviceName = settings.deviceName.trim();
    final nodeId = snapshot?.nodeId.trim() ?? '';
    final virtualIp = snapshot?.virtualIp.trim() ?? '';
    final canSync =
        !settings.manualMode &&
        settings.authToken.trim().isNotEmpty &&
        nodeId.isNotEmpty;
    final syncText = canSync
        ? (strings.isZh ? '服务端同步已就绪' : 'Control sync ready')
        : (strings.isZh
              ? '本地保存，启动并登录后同步'
              : 'Saved locally; sync after sign-in');

    return AppPanel(
      title: strings.isZh ? '本机节点' : 'This device',
      trailing: OutlinedButton.icon(
        onPressed: onEdit,
        icon: const Icon(Icons.edit_outlined, size: 16),
        label: Text(strings.isZh ? '修改名称' : 'Rename'),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                  border: Border.all(color: theme.colorScheme.outlineVariant),
                ),
                child: Icon(
                  Icons.computer_rounded,
                  size: 20,
                  color: theme.colorScheme.primary,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      dash(deviceName),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                        color: theme.colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      strings.isZh
                          ? '修改后会同步到控制面，其他设备刷新后会看到新名称。'
                          : 'Renames sync to the control plane and appear on other devices after refresh.',
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 12,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              StatusBadge(
                label: snapshot == null ? strings.offline : strings.connected,
                tone: snapshot == null ? StatusTone.neutral : StatusTone.good,
              ),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 24,
            runSpacing: 2,
            children: [
              MetricTile(
                label: strings.virtualIp,
                value: virtualIp.isEmpty ? '—' : virtualIp,
              ),
              MetricTile(
                label: strings.nodeId,
                value: nodeId.isEmpty ? '—' : shortId(nodeId),
              ),
              MetricTile(
                label: strings.isZh ? '同步状态' : 'Sync',
                value: syncText,
                minWidth: 210,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _PeerDetailsDialog extends StatelessWidget {
  const _PeerDetailsDialog({
    required this.peer,
    required this.strings,
    required this.relayFallbackLatencyMs,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final int? relayFallbackLatencyMs;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final size = MediaQuery.sizeOf(context);
    final usableWidth = size.width > 64 ? size.width - 32 : size.width;
    final usableHeight = size.height > 96 ? size.height - 48 : size.height;
    final dialogWidth = usableWidth < 520 ? usableWidth : 520.0;
    final maxDialogHeight = usableHeight < 620 ? usableHeight : 620.0;

    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
      backgroundColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: dialogWidth,
          maxHeight: maxDialogHeight,
        ),
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: colorScheme.surface,
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            border: Border.all(color: colorScheme.outlineVariant),
            boxShadow: AppTokens.shadowBorder,
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(18, 16, 10, 14),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              dash(peer.displayName),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: colorScheme.onSurface,
                                fontSize: 16,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            const SizedBox(height: 5),
                            Text(
                              dash(peer.virtualIp),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: colorScheme.onSurfaceVariant,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                                fontFeatures: AppTokens.tabularFontFeatures,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      Padding(
                        padding: const EdgeInsets.only(top: 1),
                        child: _PathBadge(peer: peer),
                      ),
                      const SizedBox(width: 2),
                      IconButton(
                        tooltip: strings.cancel,
                        onPressed: () => Navigator.of(context).pop(),
                        icon: const Icon(Icons.close_rounded, size: 20),
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1),
                Flexible(
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.fromLTRB(18, 12, 18, 14),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _DetailLine(
                          label: strings.virtualIp,
                          value: dash(peer.virtualIp),
                        ),
                        _DetailLine(
                          label: strings.isZh ? '版本' : 'Version',
                          value: dash(peer.appVersion),
                        ),
                        _DetailLine(label: strings.nodeId, value: peer.nodeId),
                        _DetailLine(
                          label: strings.connectionType,
                          value: _connectionLabel(strings, peer),
                        ),
                        _DetailLine(
                          label: strings.latency,
                          value: formatLatency(
                            _displayLatencyMs(peer, relayFallbackLatencyMs),
                          ),
                        ),
                        _DetailLine(
                          label: strings.isZh ? '在线状态' : 'Online state',
                          value: peer.online ? strings.online : strings.offline,
                        ),
                        _DetailLine(
                          label: strings.isZh ? '最后在线' : 'Last seen',
                          value: _formatLastSeen(peer),
                        ),
                        _DetailLine(
                          label: strings.state,
                          value: dash(peer.state),
                        ),
                        _DetailLine(
                          label: strings.type,
                          value: dash(peer.connectionType),
                        ),
                        _DetailLine(
                          label: strings.endpoint,
                          value: dash(peer.endpoint),
                        ),
                        _DetailLine(
                          label: strings.relay,
                          value: dash(peer.relayServer),
                        ),
                        if (peer.currentPathSelection?.reason.isNotEmpty ==
                            true)
                          _DetailLine(
                            label: strings.isZh ? '路径判定' : 'Path decision',
                            value: peer.currentPathSelection!.reason,
                          ),
                        if (peer.lastError != null)
                          _DetailLine(
                            label: strings.lastError,
                            value: peer.lastError!,
                          ),
                      ],
                    ),
                  ),
                ),
                const Divider(height: 1),
                Padding(
                  padding: const EdgeInsets.fromLTRB(18, 10, 18, 12),
                  child: Align(
                    alignment: Alignment.centerRight,
                    child: TextButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: Text(strings.cancel),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _RemoveDeviceDialogContent extends StatelessWidget {
  const _RemoveDeviceDialogContent({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 420),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DecoratedBox(
            decoration: BoxDecoration(
              color: AppTokens.colorBadBg,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              border: Border.all(color: AppTokens.colorBadBorder),
            ),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(
                    Icons.warning_amber_rounded,
                    size: 20,
                    color: AppTokens.colorBadText,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      strings.isZh
                          ? '该设备会从控制面移除，之后需要重新登录/注册才能加入网络。'
                          : 'This removes the device from the control plane. It must sign in or register again to rejoin.',
                      style: const TextStyle(
                        color: AppTokens.colorBadText,
                        fontSize: 13,
                        height: 1.35,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          _RemoveDeviceMetaRow(
            label: strings.isZh ? '设备名称' : 'Device',
            value: peer.displayName,
          ),
          _RemoveDeviceMetaRow(
            label: strings.virtualIp,
            value: dash(peer.virtualIp),
          ),
          _RemoveDeviceMetaRow(
            label: strings.nodeId,
            value: shortId(peer.nodeId),
          ),
          const SizedBox(height: 4),
          Text(
            strings.isZh
                ? '如果只是临时离线，不需要移除；离线设备已自动排在列表底部。'
                : 'If it is only temporarily offline, leave it. Offline devices already sort to the bottom.',
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 12,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}

class _RemoveDeviceMetaRow extends StatelessWidget {
  const _RemoveDeviceMetaRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 88,
            child: Text(
              label,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              value,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 12,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerSummary extends StatelessWidget {
  const _PeerSummary({required this.peers});

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final directCount = peers.where((peer) => peer.path == 'direct').length;
    final relayCount = peers.where((peer) => peer.path == 'relay').length;
    final onlineCount = peers.where((peer) => peer.online).length;
    final offlineCount = peers.where((peer) => !peer.online).length;
    final attentionCount = peers.where(_peerNeedsAttention).length;
    return AppPanel(
      title: strings.peerSummary,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(label: strings.peerCount, value: formatInt(peers.length)),
          MetricTile(
            label: strings.onlineDevices,
            value: formatInt(onlineCount),
          ),
          MetricTile(label: strings.directPaths, value: formatInt(directCount)),
          MetricTile(label: strings.relayPaths, value: formatInt(relayCount)),
          MetricTile(
            label: strings.offlineDevices,
            value: formatInt(offlineCount),
          ),
          MetricTile(
            label: strings.attentionDevices,
            value: formatInt(attentionCount),
          ),
        ],
      ),
    );
  }
}

class _PeerTable extends StatelessWidget {
  const _PeerTable({
    required this.peers,
    required this.copiedKey,
    required this.relayFallbackLatencyMs,
    required this.onCopy,
    required this.onDetails,
    required this.onEdit,
    required this.onDelete,
  });

  final List<PeerSnapshot> peers;
  final String? copiedKey;
  final int? relayFallbackLatencyMs;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onDetails;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<void> Function(PeerSnapshot peer) onDelete;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final bodyHeight = (peers.length * _rowHeight)
        .clamp(_rowHeight, _maxBodyHeight)
        .toDouble();
    return AppPanel(
      title: strings.isZh ? '其他设备' : 'Other devices',
      flushContent: true,
      child: ClipRRect(
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(AppTokens.radiusLg),
          bottomRight: Radius.circular(AppTokens.radiusLg),
        ),
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: SizedBox(
            width: _tableWidth,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                _PeerHeader(strings: strings),
                SizedBox(
                  height: bodyHeight,
                  child: ListView.builder(
                    padding: EdgeInsets.zero,
                    primary: false,
                    itemExtent: _rowHeight,
                    itemCount: peers.length,
                    itemBuilder: (context, index) {
                      return _PeerRow(
                        peer: peers[index],
                        strings: strings,
                        shaded: index.isOdd,
                        copiedKey: copiedKey,
                        relayFallbackLatencyMs: relayFallbackLatencyMs,
                        onCopy: onCopy,
                        onEdit: onEdit,
                      );
                    },
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  static const _tableWidth = 1196.0;
  static const _maxBodyHeight = 520.0;
  static const _rowHeight = 44.0;
  static const _deviceWidth = 142.0;
  static const _peerIdWidth = 118.0;
  static const _virtualIpWidth = 112.0;
  static const _versionWidth = 96.0;
  static const _stateWidth = 94.0;
  static const _pathWidth = 92.0;
  static const _typeWidth = 122.0;
  static const _routeWidth = 92.0;
  static const _latencyWidth = 86.0;
  static const _endpointWidth = 122.0;
  static const _actionWidth = 120.0;

  static const _columnHeaderStyle = TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w600,
    color: AppTokens.colorTextSecondary,
  );

  static const _cellStyle = TextStyle(
    fontSize: 13,
    fontWeight: FontWeight.w400,
    color: AppTokens.colorTextPrimary,
  );

  static const _cellStyleBold = TextStyle(
    fontSize: 13,
    fontWeight: FontWeight.w600,
    color: AppTokens.colorTextPrimary,
  );

  static const _cellMonoStyle = TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w500,
    color: AppTokens.colorTextPrimary,
    fontFeatures: AppTokens.tabularFontFeatures,
  );
}

class _PeerHeader extends StatelessWidget {
  const _PeerHeader({required this.strings});

  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 38,
      decoration: const BoxDecoration(
        color: AppTokens.colorSurfaceSubtle,
        border: Border(bottom: BorderSide(color: AppTokens.colorBorderSubtle)),
      ),
      child: Row(
        children: [
          _PeerCell(
            width: _PeerTable._deviceWidth,
            child: Text(strings.device, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._peerIdWidth,
            child: Text(strings.peerId, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._virtualIpWidth,
            child: Text(
              strings.virtualIp,
              style: _PeerTable._columnHeaderStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._versionWidth,
            child: Text(
              strings.isZh ? '版本' : 'Version',
              style: _PeerTable._columnHeaderStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._stateWidth,
            child: Text(strings.state, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._pathWidth,
            child: Text(strings.path, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._typeWidth,
            child: Text(strings.type, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._routeWidth,
            child: Text(strings.route, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._latencyWidth,
            child: Text(strings.latency, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._endpointWidth,
            child: Text(strings.endpoint, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._actionWidth,
            child: Text(
              strings.isZh ? '操作' : 'Actions',
              style: _PeerTable._columnHeaderStyle,
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerRow extends StatelessWidget {
  const _PeerRow({
    required this.peer,
    required this.strings,
    required this.shaded,
    required this.copiedKey,
    required this.relayFallbackLatencyMs,
    required this.onCopy,
    required this.onEdit,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;
  final String? copiedKey;
  final int? relayFallbackLatencyMs;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: shaded ? AppTokens.colorSurfaceSubtle : AppTokens.colorSurface,
        border: const Border(
          bottom: BorderSide(color: AppTokens.colorBorderSubtle),
        ),
      ),
      child: Row(
        children: [
          _PeerCell(
            width: _PeerTable._deviceWidth,
            child: Text(
              dash(peer.displayName),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyleBold,
            ),
          ),
          _PeerCell(
            width: _PeerTable._peerIdWidth,
            child: Text(shortId(peer.nodeId), style: _PeerTable._cellMonoStyle),
          ),
          _PeerCell(
            width: _PeerTable._virtualIpWidth,
            child: Text(dash(peer.virtualIp), style: _PeerTable._cellMonoStyle),
          ),
          _PeerCell(
            width: _PeerTable._versionWidth,
            child: Text(
              dash(peer.appVersion),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellMonoStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._stateWidth,
            child: Text(
              dash(peer.state),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._pathWidth,
            child: _PathBadge(peer: peer),
          ),
          _PeerCell(
            width: _PeerTable._typeWidth,
            child: Text(
              dash(peer.connectionType),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._routeWidth,
            child: Text(
              _routeLabel(strings, peer),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._latencyWidth,
            child: Text(
              formatLatency(_displayLatencyMs(peer, relayFallbackLatencyMs)),
              style: _PeerTable._cellMonoStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._endpointWidth,
            child: Text(
              dash(peer.endpoint ?? peer.relayServer),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellMonoStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._actionWidth,
            child: _PeerActions(
              peer: peer,
              copiedKey: copiedKey,
              onCopy: onCopy,
              onEdit: onEdit,
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerCell extends StatelessWidget {
  const _PeerCell({required this.width, required this.child});

  final double width;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Align(alignment: Alignment.centerLeft, child: child),
      ),
    );
  }
}

class _PeerList extends StatelessWidget {
  const _PeerList({
    required this.peers,
    required this.copiedKey,
    required this.busyPeerId,
    required this.relayFallbackLatencyMs,
    required this.onCopy,
    required this.onDetails,
    required this.onEdit,
    required this.onDelete,
  });

  final List<PeerSnapshot> peers;
  final String? copiedKey;
  final String? busyPeerId;
  final int? relayFallbackLatencyMs;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onDetails;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<void> Function(PeerSnapshot peer) onDelete;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.isZh ? '其他设备' : 'Other devices',
      flushContent: true,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final compact = constraints.maxWidth < 430;
          final rowHeight = compact ? _compactRowHeight : _rowHeight;
          final maxBodyHeight = compact
              ? _compactMaxBodyHeight
              : _maxBodyHeight;
          final groups = _buildPeerGroups(peers, strings);
          final items = <_PeerListItem>[
            for (final group in groups) ...[
              _PeerListItem.group(group),
              for (final peer in group.peers) _PeerListItem.peer(peer),
            ],
          ];
          final contentHeight =
              (groups.length * _groupHeaderHeight) + (peers.length * rowHeight);
          final bodyHeight = contentHeight
              .clamp(rowHeight + _groupHeaderHeight, maxBodyHeight)
              .toDouble();
          return ClipRRect(
            borderRadius: const BorderRadius.only(
              bottomLeft: Radius.circular(AppTokens.radiusLg),
              bottomRight: Radius.circular(AppTokens.radiusLg),
            ),
            child: SizedBox(
              height: bodyHeight,
              child: ListView.builder(
                padding: EdgeInsets.zero,
                primary: false,
                itemCount: items.length,
                itemBuilder: (context, index) {
                  final item = items[index];
                  final group = item.group;
                  if (group != null) {
                    return SizedBox(
                      height: _groupHeaderHeight,
                      child: _PeerGroupHeader(group: group),
                    );
                  }
                  final peer = item.peer!;
                  return SizedBox(
                    height: rowHeight,
                    child: _PeerListRow(
                      peer: peer,
                      strings: strings,
                      shaded: index.isOdd,
                      compact: compact,
                      copiedKey: copiedKey,
                      busy: busyPeerId == peer.nodeId,
                      relayFallbackLatencyMs: relayFallbackLatencyMs,
                      onCopy: onCopy,
                      onDetails: onDetails,
                      onEdit: onEdit,
                      onDelete: onDelete,
                    ),
                  );
                },
              ),
            ),
          );
        },
      ),
    );
  }

  static const _rowHeight = 68.0;
  static const _maxBodyHeight = 456.0;
  static const _compactRowHeight = 96.0;
  static const _compactMaxBodyHeight = 520.0;
  static const _groupHeaderHeight = 34.0;
}

class _PeerListItem {
  const _PeerListItem.group(this.group) : peer = null;
  const _PeerListItem.peer(this.peer) : group = null;

  final _PeerGroup? group;
  final PeerSnapshot? peer;
}

class _PeerGroup {
  const _PeerGroup({
    required this.title,
    required this.tone,
    required this.peers,
  });

  final String title;
  final StatusTone tone;
  final List<PeerSnapshot> peers;
}

class _PeerGroupHeader extends StatelessWidget {
  const _PeerGroupHeader({required this.group});

  final _PeerGroup group;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        border: Border(
          bottom: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              group.title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          const SizedBox(width: 8),
          StatusBadge(label: formatInt(group.peers.length), tone: group.tone),
        ],
      ),
    );
  }
}

class _PeerListRow extends StatelessWidget {
  const _PeerListRow({
    required this.peer,
    required this.strings,
    required this.shaded,
    required this.compact,
    required this.copiedKey,
    required this.busy,
    required this.relayFallbackLatencyMs,
    required this.onCopy,
    required this.onDetails,
    required this.onEdit,
    required this.onDelete,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;
  final bool compact;
  final String? copiedKey;
  final bool busy;
  final int? relayFallbackLatencyMs;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onDetails;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<void> Function(PeerSnapshot peer) onDelete;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final menu = _actionsMenu(ipKey, pingKey);
    final rowColor = shaded
        ? theme.colorScheme.surfaceContainerHighest
        : theme.colorScheme.surface;
    return Material(
      color: rowColor,
      child: InkWell(
        onTap: () => onDetails(peer),
        child: Container(
          padding: EdgeInsets.symmetric(
            horizontal: 14,
            vertical: compact ? 8 : 0,
          ),
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(color: theme.colorScheme.outlineVariant),
            ),
          ),
          child: compact
              ? Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Expanded(child: _PeerPrimaryText(peer: peer)),
                        const SizedBox(width: 8),
                        menu,
                      ],
                    ),
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        _LatencyText(
                          peer: peer,
                          relayFallbackLatencyMs: relayFallbackLatencyMs,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Align(
                            alignment: Alignment.centerRight,
                            child: _PathBadge(peer: peer),
                          ),
                        ),
                      ],
                    ),
                  ],
                )
              : Row(
                  children: [
                    Expanded(flex: 3, child: _PeerPrimaryText(peer: peer)),
                    const SizedBox(width: 12),
                    SizedBox(
                      width: 92,
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: _LatencyText(
                          peer: peer,
                          relayFallbackLatencyMs: relayFallbackLatencyMs,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    SizedBox(
                      width: 116,
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: _PathBadge(peer: peer),
                      ),
                    ),
                    const SizedBox(width: 4),
                    menu,
                  ],
                ),
        ),
      ),
    );
  }

  Widget _actionsMenu(String ipKey, String pingKey) {
    if (busy) {
      return SizedBox.square(
        dimension: AppTokens.minTouchTarget,
        child: const Center(child: _TinySpinner()),
      );
    }
    return SizedBox.square(
      dimension: AppTokens.minTouchTarget,
      child: PopupMenuButton<String>(
        padding: EdgeInsets.zero,
        iconSize: 20,
        tooltip: strings.isZh ? '设备操作' : 'Device actions',
        onSelected: (value) {
          switch (value) {
            case 'copy_ip':
              onCopy(peer.virtualIp, ipKey);
              break;
            case 'copy_ping':
              onCopy('ping ${peer.virtualIp}', pingKey);
              break;
            case 'edit':
              onEdit(peer);
              break;
            case 'delete':
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onDelete(peer);
              });
              break;
            case 'details':
              WidgetsBinding.instance.addPostFrameCallback((_) {
                onDetails(peer);
              });
              break;
          }
        },
        itemBuilder: (context) => [
          PopupMenuItem(
            value: 'details',
            child: Text(strings.isZh ? '查看详情' : 'View details'),
          ),
          PopupMenuItem(
            value: 'copy_ip',
            child: Text(strings.isZh ? '复制虚拟 IP' : 'Copy virtual IP'),
          ),
          PopupMenuItem(
            value: 'copy_ping',
            child: Text(strings.isZh ? '复制 ping 命令' : 'Copy ping command'),
          ),
          PopupMenuItem(
            value: 'edit',
            child: Text(strings.isZh ? '修改名称' : 'Rename'),
          ),
          PopupMenuItem(
            value: 'delete',
            child: Text(strings.isZh ? '移除设备' : 'Remove device'),
          ),
        ],
      ),
    );
  }
}

class _LatencyText extends StatelessWidget {
  const _LatencyText({
    required this.peer,
    required this.relayFallbackLatencyMs,
  });

  final PeerSnapshot peer;
  final int? relayFallbackLatencyMs;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Text(
      formatLatency(_displayLatencyMs(peer, relayFallbackLatencyMs)),
      textAlign: TextAlign.right,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        fontSize: 12,
        fontWeight: FontWeight.w700,
        color: theme.colorScheme.onSurfaceVariant,
        fontFeatures: AppTokens.tabularFontFeatures,
      ),
    );
  }
}

int? _displayLatencyMs(PeerSnapshot peer, int? relayFallbackLatencyMs) {
  final peerLatency = peer.latencyMs;
  if (peerLatency != null) return peerLatency;
  if (peer.online && peer.path == 'relay') return relayFallbackLatencyMs;
  return null;
}

class _TinySpinner extends StatelessWidget {
  const _TinySpinner();

  @override
  Widget build(BuildContext context) {
    return const SizedBox.square(
      dimension: 16,
      child: CircularProgressIndicator(strokeWidth: 2),
    );
  }
}

class _PeerPrimaryText extends StatelessWidget {
  const _PeerPrimaryText({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final error = peer.lastError?.trim();
    final detail = error != null && error.isNotEmpty
        ? error
        : peer.appVersion.trim().isEmpty
        ? dash(peer.virtualIp)
        : '${dash(peer.virtualIp)} · v${peer.appVersion.trim()}';
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          dash(peer.displayName),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 13.5,
            fontWeight: FontWeight.w700,
            color: theme.colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          detail,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: error != null && error.isNotEmpty
                ? theme.colorScheme.error
                : theme.colorScheme.onSurfaceVariant,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}

class _PeerActions extends StatelessWidget {
  const _PeerActions({
    required this.peer,
    required this.copiedKey,
    required this.onCopy,
    required this.onEdit,
  });

  final PeerSnapshot peer;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final ipCopied = copiedKey == ipKey;
    final pingCopied = copiedKey == pingKey;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconButton(
          tooltip: ipCopied
              ? (strings.isZh ? '已复制' : 'Copied')
              : (strings.isZh ? '复制虚拟 IP' : 'Copy virtual IP'),
          onPressed: () => onCopy(peer.virtualIp, ipKey),
          icon: Icon(
            ipCopied ? Icons.check_circle_outline : Icons.copy_outlined,
            size: 18,
          ),
        ),
        IconButton(
          tooltip: pingCopied
              ? (strings.isZh ? '已复制' : 'Copied')
              : (strings.isZh ? '复制 ping 命令' : 'Copy ping command'),
          onPressed: () => onCopy('ping ${peer.virtualIp}', pingKey),
          icon: Icon(
            pingCopied ? Icons.check_circle_outline : Icons.terminal_outlined,
            size: 18,
          ),
        ),
        IconButton(
          tooltip: strings.isZh ? '编辑设备' : 'Edit device',
          onPressed: () => onEdit(peer),
          icon: const Icon(Icons.edit_outlined, size: 18),
        ),
      ],
    );
  }
}

String _routeLabel(AppStrings strings, PeerSnapshot peer) =>
    strings.routeLabel(peer.path, peer.isRelay);

List<_PeerGroup> _buildPeerGroups(
  List<PeerSnapshot> peers,
  AppStrings strings,
) {
  final attention = <PeerSnapshot>[];
  final direct = <PeerSnapshot>[];
  final relay = <PeerSnapshot>[];
  final offline = <PeerSnapshot>[];

  for (final peer in peers) {
    if (_peerNeedsAttention(peer)) {
      attention.add(peer);
    } else if (peer.path == 'direct') {
      direct.add(peer);
    } else if (peer.path == 'relay') {
      relay.add(peer);
    } else {
      offline.add(peer);
    }
  }

  return [
    if (attention.isNotEmpty)
      _PeerGroup(
        title: strings.attentionDevices,
        tone: StatusTone.bad,
        peers: attention,
      ),
    if (direct.isNotEmpty)
      _PeerGroup(
        title: strings.directDevices,
        tone: StatusTone.good,
        peers: direct,
      ),
    if (relay.isNotEmpty)
      _PeerGroup(
        title: strings.relayDevices,
        tone: StatusTone.warn,
        peers: relay,
      ),
    if (offline.isNotEmpty)
      _PeerGroup(
        title: strings.offlineDevices,
        tone: StatusTone.neutral,
        peers: offline,
      ),
  ];
}

List<PeerSnapshot> _dedupeAndSortPeers(List<PeerSnapshot> peers) {
  final byKey = <String, PeerSnapshot>{};
  for (final peer in peers) {
    final key = _peerDedupeKey(peer);
    final known = byKey[key];
    if (known == null || _comparePeers(peer, known) < 0) {
      byKey[key] = peer;
    }
  }
  final sorted = byKey.values.toList(growable: false);
  sorted.sort(_comparePeers);
  return sorted;
}

String _peerDedupeKey(PeerSnapshot peer) {
  final ip = peer.virtualIp.trim();
  if (ip.isNotEmpty) return 'ip:$ip';
  return 'node:${peer.nodeId}';
}

int _comparePeers(PeerSnapshot left, PeerSnapshot right) {
  final rank = _peerSortRank(left).compareTo(_peerSortRank(right));
  if (rank != 0) return rank;
  final recent = right.sortTimestampMs.compareTo(left.sortTimestampMs);
  if (recent != 0) return recent;
  return left.displayName.compareTo(right.displayName);
}

int _peerSortRank(PeerSnapshot peer) {
  if (_peerNeedsAttention(peer)) return 0;
  if (peer.path == 'direct') return 1;
  if (peer.path == 'relay') return 2;
  return 3;
}

bool _peerNeedsAttention(PeerSnapshot peer) {
  if (peer.lastError != null) return true;
  return peer.online && (peer.path == 'probing' || peer.path == 'direct_trial');
}

String _connectionLabel(AppStrings strings, PeerSnapshot peer) {
  if (!peer.online || peer.path == 'offline') return strings.offline;
  if (peer.path == 'relay') return strings.relay;
  if (peer.path == 'direct_trial' || peer.path == 'probing') {
    return strings.probing;
  }
  if (peer.path == 'direct') {
    return switch (peer.connectionType) {
      'public_udp' => strings.isZh ? '公网直连' : 'Public direct',
      'lan' => strings.isZh ? '局域网直连' : 'LAN direct',
      'overlay' => strings.isZh ? 'Overlay 直连' : 'Overlay direct',
      _ => strings.direct,
    };
  }
  return strings.pathLabel(peer.path);
}

String _formatLastSeen(PeerSnapshot peer) {
  final value = peer.lastSeenAt;
  if (value == null) return '—';
  final local = value.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${local.year}-${two(local.month)}-${two(local.day)} ${two(local.hour)}:${two(local.minute)}';
}

class _DetailLine extends StatelessWidget {
  const _DetailLine({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final labelText = Text(
            label,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          );
          final valueText = SelectableText(
            value,
            style: TextStyle(
              fontSize: 12,
              color: theme.colorScheme.onSurface,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          );
          if (constraints.maxWidth < 340) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [labelText, const SizedBox(height: 3), valueText],
            );
          }
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: 96, child: labelText),
              Expanded(child: valueText),
            ],
          );
        },
      ),
    );
  }
}

class _PathBadge extends StatelessWidget {
  const _PathBadge({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final tone = _peerNeedsAttention(peer)
        ? StatusTone.bad
        : switch (peer.path) {
            'direct' => StatusTone.good,
            'relay' => StatusTone.warn,
            'direct_trial' || 'probing' => StatusTone.warn,
            _ => StatusTone.neutral,
          };
    return StatusBadge(
      label: _connectionLabel(AppStringsScope.of(context), peer),
      tone: tone,
    );
  }
}
