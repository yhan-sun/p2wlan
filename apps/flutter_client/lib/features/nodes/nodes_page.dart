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
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  @override
  State<NodesPage> createState() => _NodesPageState();
}

class _NodesPageState extends State<NodesPage> {
  final _controlApi = ControlApi();
  String? _copiedKey;
  String? _busyPeerId;

  @override
  void dispose() {
    _controlApi.close();
    super.dispose();
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
        );
        final relayFallbackLatencyMs = snapshot?.relayConnected == true
            ? snapshot?.relaySelection.latencyMs
            : null;
        final settings = widget.settingsStore.settings;
        return PageScaffold(
          title: strings.nodes,
          subtitle: strings.nodesSubtitle,
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
    if (!mounted) return;
    final result = await _promptDeviceName(
      initialName: initialName,
      title: strings.isZh ? '编辑本机节点名称' : 'Edit this device name',
    );
    if (result == null) return;

    final nodeId = snapshot?.nodeId.trim() ?? '';
    final canSync =
        !settings.manualMode &&
        settings.authToken.trim().isNotEmpty &&
        nodeId.isNotEmpty;
    var savedName = result;
    try {
      if (canSync) {
        savedName = await _controlApi.renameDevice(
          controlServer: settings.controlServer,
          authToken: settings.authToken,
          deviceId: nodeId,
          deviceName: result,
        );
      }
      await widget.settingsStore.updateSettings(
        settings.copyWith(deviceName: savedName),
      );
      await widget.statusStore.refresh();
      if (!mounted) return;
      _showSnack(
        canSync
            ? (strings.isZh
                  ? '本机节点名称已同步：$savedName'
                  : 'This device name synced: $savedName')
            : (strings.isZh
                  ? '本机节点名称已保存：$savedName'
                  : 'This device name saved: $savedName'),
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
      builder: (dialogContext) => AlertDialog(
        title: Text(peer.displayName),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              _DetailLine(
                label: strings.virtualIp,
                value: dash(peer.virtualIp),
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
              _DetailLine(label: strings.state, value: dash(peer.state)),
              _DetailLine(
                label: strings.type,
                value: dash(peer.connectionType),
              ),
              _DetailLine(label: strings.endpoint, value: dash(peer.endpoint)),
              _DetailLine(label: strings.relay, value: dash(peer.relayServer)),
              if (peer.lastError != null)
                _DetailLine(label: strings.lastError, value: peer.lastError!),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: Text(strings.cancel),
          ),
        ],
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
                  color: AppTokens.colorNeutralBg,
                  borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                  border: Border.all(color: AppTokens.colorNeutralBorder),
                ),
                child: const Icon(
                  Icons.computer_rounded,
                  size: 20,
                  color: AppTokens.colorAccent,
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
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                        color: AppTokens.colorTextPrimary,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      strings.isZh
                          ? '修改后会同步到控制面，其他设备刷新后会看到新名称。'
                          : 'Renames sync to the control plane and appear on other devices after refresh.',
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        fontSize: 12,
                        color: AppTokens.colorTextSecondary,
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
              style: const TextStyle(
                color: AppTokens.colorTextPrimary,
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
    return AppPanel(
      title: strings.peerSummary,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(label: strings.peerCount, value: formatInt(peers.length)),
          MetricTile(label: strings.directPaths, value: formatInt(directCount)),
          MetricTile(label: strings.relayPaths, value: formatInt(relayCount)),
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

  static const _tableWidth = 1100.0;
  static const _maxBodyHeight = 520.0;
  static const _rowHeight = 44.0;
  static const _deviceWidth = 142.0;
  static const _peerIdWidth = 118.0;
  static const _virtualIpWidth = 112.0;
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
          final bodyHeight = (peers.length * rowHeight)
              .clamp(rowHeight, maxBodyHeight)
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
                itemExtent: rowHeight,
                itemCount: peers.length,
                itemBuilder: (context, index) {
                  return _PeerListRow(
                    peer: peers[index],
                    strings: strings,
                    shaded: index.isOdd,
                    compact: compact,
                    copiedKey: copiedKey,
                    busy: busyPeerId == peers[index].nodeId,
                    relayFallbackLatencyMs: relayFallbackLatencyMs,
                    onCopy: onCopy,
                    onDetails: onDetails,
                    onEdit: onEdit,
                    onDelete: onDelete,
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
  static const _compactRowHeight = 90.0;
  static const _compactMaxBodyHeight = 520.0;
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
    final ipKey = '${peer.nodeId}:ip';
    final pingKey = '${peer.nodeId}:ping';
    final menu = _actionsMenu(ipKey, pingKey);
    return Material(
      color: shaded ? AppTokens.colorSurfaceSubtle : AppTokens.colorSurface,
      child: InkWell(
        onTap: () => onDetails(peer),
        child: Container(
          padding: EdgeInsets.symmetric(
            horizontal: 14,
            vertical: compact ? 8 : 0,
          ),
          decoration: const BoxDecoration(
            border: Border(
              bottom: BorderSide(color: AppTokens.colorBorderSubtle),
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
        dimension: compact ? 36 : 40,
        child: const Center(child: _TinySpinner()),
      );
    }
    return SizedBox.square(
      dimension: compact ? 36 : 40,
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
              onDetails(peer);
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
    return Text(
      formatLatency(_displayLatencyMs(peer, relayFallbackLatencyMs)),
      textAlign: TextAlign.right,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: const TextStyle(
        fontSize: 12,
        fontWeight: FontWeight.w700,
        color: AppTokens.colorTextSecondary,
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
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          dash(peer.displayName),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(
            fontSize: 13.5,
            fontWeight: FontWeight.w700,
            color: AppTokens.colorTextPrimary,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          dash(peer.virtualIp),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: AppTokens.colorTextSecondary,
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
          visualDensity: VisualDensity.compact,
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
          visualDensity: VisualDensity.compact,
          onPressed: () => onCopy('ping ${peer.virtualIp}', pingKey),
          icon: Icon(
            pingCopied ? Icons.check_circle_outline : Icons.terminal_outlined,
            size: 18,
          ),
        ),
        IconButton(
          tooltip: strings.isZh ? '编辑设备' : 'Edit device',
          visualDensity: VisualDensity.compact,
          onPressed: () => onEdit(peer),
          icon: const Icon(Icons.edit_outlined, size: 18),
        ),
      ],
    );
  }
}

String _routeLabel(AppStrings strings, PeerSnapshot peer) =>
    strings.routeLabel(peer.path, peer.isRelay);

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
  if (left.online != right.online) return left.online ? -1 : 1;
  final recent = right.sortTimestampMs.compareTo(left.sortTimestampMs);
  if (recent != 0) return recent;
  return left.displayName.compareTo(right.displayName);
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
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final labelText = Text(
            label,
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: AppTokens.colorTextSecondary,
            ),
          );
          final valueText = SelectableText(
            value,
            style: const TextStyle(
              fontSize: 12,
              color: AppTokens.colorTextPrimary,
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
    final tone = switch (peer.path) {
      'direct' => StatusTone.good,
      'relay' => StatusTone.warn,
      _ => StatusTone.neutral,
    };
    return StatusBadge(
      label: _connectionLabel(AppStringsScope.of(context), peer),
      tone: tone,
    );
  }
}
