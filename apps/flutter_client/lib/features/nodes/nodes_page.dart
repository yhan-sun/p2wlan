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
        final peers = snapshot?.peers ?? const <PeerSnapshot>[];
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
            _PeerSummary(snapshot: snapshot, peerCount: peers.length),
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
                onCopy: _copy,
                onEdit: _editPeer,
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
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            canSync
                ? (strings.isZh
                      ? '本机节点名称已同步：$savedName'
                      : 'This device name synced: $savedName')
                : (strings.isZh
                      ? '本机节点名称已保存：$savedName'
                      : 'This device name saved: $savedName'),
          ),
        ),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.toString())));
    }
  }

  Future<void> _editPeer(PeerSnapshot peer) async {
    final strings = AppStringsScope.of(context);
    final result = await _promptDeviceName(
      initialName: peer.displayName,
      title: strings.isZh ? '编辑设备名称' : 'Edit device name',
    );
    if (result == null) return;
    final settings = widget.settingsStore.settings;
    try {
      final savedName = await _controlApi.renameDevice(
        controlServer: settings.controlServer,
        authToken: settings.authToken,
        deviceId: peer.nodeId,
        deviceName: result,
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            strings.isZh
                ? '设备名称已同步：$savedName'
                : 'Device name synced: $savedName',
          ),
        ),
      );
      await widget.statusStore.refresh();
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.toString())));
    }
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

class _PeerSummary extends StatelessWidget {
  const _PeerSummary({required this.snapshot, required this.peerCount});

  final DiagnosticsSnapshot? snapshot;
  final int peerCount;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final stats = snapshot?.stats;
    return AppPanel(
      title: strings.peerSummary,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(label: strings.peerCount, value: formatInt(peerCount)),
          MetricTile(
            label: strings.directPaths,
            value: stats == null ? '—' : formatInt(stats.directConnections),
          ),
          MetricTile(
            label: strings.relayPaths,
            value: stats == null ? '—' : formatInt(stats.relayConnections),
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
    required this.onCopy,
    required this.onEdit,
  });

  final List<PeerSnapshot> peers;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

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
    required this.onCopy,
    required this.onEdit,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;
  final String? copiedKey;
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
              formatLatency(peer.latencyMs),
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
    required this.onCopy,
    required this.onEdit,
  });

  final List<PeerSnapshot> peers;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

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
        child: SizedBox(
          height: bodyHeight,
          child: ListView.builder(
            padding: EdgeInsets.zero,
            primary: false,
            itemExtent: _rowHeight,
            itemCount: peers.length,
            itemBuilder: (context, index) {
              return _PeerListRow(
                peer: peers[index],
                strings: strings,
                shaded: index.isOdd,
                copiedKey: copiedKey,
                onCopy: onCopy,
                onEdit: onEdit,
              );
            },
          ),
        ),
      ),
    );
  }

  static const _rowHeight = 76.0;
  static const _maxBodyHeight = 456.0;
}

class _PeerListRow extends StatelessWidget {
  const _PeerListRow({
    required this.peer,
    required this.strings,
    required this.shaded,
    required this.copiedKey,
    required this.onCopy,
    required this.onEdit,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

  @override
  Widget build(BuildContext context) {
    final route = _routeLabel(strings, peer);
    final endpoint = dash(peer.endpoint ?? peer.relayServer);
    final detail =
        '${dash(peer.state)} / ${dash(peer.connectionType)} / $route';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      decoration: BoxDecoration(
        color: shaded ? AppTokens.colorSurfaceSubtle : AppTokens.colorSurface,
        border: const Border(
          bottom: BorderSide(color: AppTokens.colorBorderSubtle),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
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
                const SizedBox(height: 3),
                Text(
                  '${shortId(peer.nodeId)} / ${dash(peer.virtualIp)}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                    color: AppTokens.colorTextSecondary,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  endpoint == '—' ? detail : '$detail / $endpoint',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w400,
                    color: AppTokens.colorTextMuted,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              _PathBadge(peer: peer),
              const SizedBox(height: 5),
              Text(
                formatLatency(peer.latencyMs),
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
          ),
          const SizedBox(width: 8),
          _PeerActions(
            peer: peer,
            copiedKey: copiedKey,
            onCopy: onCopy,
            onEdit: onEdit,
          ),
        ],
      ),
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
      label: AppStringsScope.of(context).pathLabel(peer.path),
      tone: tone,
    );
  }
}
