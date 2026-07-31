import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

class DiagnosticsPage extends StatelessWidget {
  const DiagnosticsPage({
    super.key,
    required this.statusStore,
    this.showHeader = true,
  });

  final StatusStore statusStore;
  final bool showHeader;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        return PageScaffold(
          title: strings.diagnostics,
          subtitle: strings.diagnosticsSubtitle,
          showHeader: showHeader,
          children: [
            _DiagnosticsActions(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 14),
            _Summary(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 14),
            _IssuesPanel(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 14),
            _PlatformPanel(),
            const SizedBox(height: 14),
            _BoundaryPanel(snapshot: snapshot),
            const SizedBox(height: 14),
            _TaskPanel(snapshot: snapshot),
            const SizedBox(height: 14),
            _RecentLogsPanel(),
            const SizedBox(height: 14),
            _RawJson(statusStore: statusStore, snapshot: snapshot),
          ],
        );
      },
    );
  }
}

class _DiagnosticsActions extends StatelessWidget {
  const _DiagnosticsActions({
    required this.statusStore,
    required this.snapshot,
  });

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Wrap(
      spacing: 10,
      runSpacing: 8,
      children: [
        OutlinedButton.icon(
          onPressed: () => _copySummary(context),
          icon: const Icon(Icons.copy_all_outlined, size: 17),
          label: Text(strings.isZh ? '复制摘要' : 'Copy summary'),
        ),
        OutlinedButton.icon(
          onPressed: () => _openLogs(context),
          icon: const Icon(Icons.folder_open_outlined, size: 17),
          label: Text(strings.openLogs),
        ),
        FilledButton.icon(
          onPressed: statusStore.refreshing ? null : statusStore.refresh,
          icon: statusStore.refreshing
              ? const SizedBox.square(
                  dimension: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.refresh_rounded, size: 17),
          label: Text(
            statusStore.refreshing ? strings.refreshing : strings.refreshNow,
          ),
        ),
      ],
    );
  }

  Future<void> _copySummary(BuildContext context) async {
    final strings = AppStringsScope.of(context);
    final health = snapshot?.health;
    final stats = snapshot?.stats;
    final lines = [
      'P2WLAN diagnostics',
      'platform=${_platformName()}',
      'health_endpoint=${statusStore.healthReachable}',
      'status_endpoint=${statusStore.statusReachable}',
      'service_health=${health?.status ?? "n/a"}',
      'control_connected=${health?.controlConnected ?? false}',
      'reauth_required=${health?.reauthRequired ?? false}',
      'node_id=${snapshot?.nodeId ?? "n/a"}',
      'virtual_ip=${snapshot?.virtualIp ?? "n/a"}',
      'network=${snapshot?.networkId ?? "n/a"}',
      'udp=${snapshot?.udpLocalAddr ?? "n/a"}',
      'peers=${stats?.totalPeers ?? 0} direct=${stats?.directConnections ?? 0} relay=${stats?.relayConnections ?? 0}',
      if (statusStore.lastError != null) 'last_error=${statusStore.lastError}',
      if (health?.reason != null) 'health_reason=${health!.reason}',
    ];
    await Clipboard.setData(ClipboardData(text: lines.join('\n')));
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(strings.isZh ? '诊断摘要已复制' : 'Diagnostics summary copied'),
      ),
    );
  }

  Future<void> _openLogs(BuildContext context) async {
    final strings = AppStringsScope.of(context);
    final dir = _defaultLogDir();
    await dir.create(recursive: true);
    if (Platform.isMacOS) {
      await Process.start('open', [dir.path]);
    } else if (Platform.isWindows) {
      await Process.start('explorer', [dir.path]);
    } else {
      await Process.start('xdg-open', [dir.path]);
    }
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text('${strings.openLogs}: ${dir.path}')));
  }
}

class _PlatformPanel extends StatefulWidget {
  const _PlatformPanel();

  @override
  State<_PlatformPanel> createState() => _PlatformPanelState();
}

class _PlatformPanelState extends State<_PlatformPanel> {
  late Future<_PermissionSnapshot> _permissionFuture;

  @override
  void initState() {
    super.initState();
    _permissionFuture = _checkPermissions();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return FutureBuilder<_PermissionSnapshot>(
      future: _permissionFuture,
      builder: (context, snapshot) {
        final permission = snapshot.data;
        final tone = permission == null
            ? StatusTone.warn
            : permission.bad
            ? StatusTone.bad
            : permission.warn
            ? StatusTone.warn
            : StatusTone.good;
        final label = permission == null
            ? (strings.isZh ? '检查中' : 'Checking')
            : permission.bad
            ? (strings.isZh ? '需处理' : 'Action needed')
            : permission.warn
            ? (strings.isZh ? '需确认' : 'Review')
            : strings.loaded;
        return AppPanel(
          title: strings.platformPermissions,
          trailing: Wrap(
            spacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              StatusBadge(label: label, tone: tone),
              IconButton(
                tooltip: strings.refresh,
                onPressed: _refresh,
                icon: const Icon(Icons.refresh_rounded, size: 18),
              ),
            ],
          ),
          child: permission == null
              ? const SizedBox(
                  height: 72,
                  child: Center(
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Wrap(
                      spacing: 24,
                      runSpacing: 12,
                      children: [
                        MetricTile(
                          label: strings.isZh ? '平台' : 'Platform',
                          value: permission.platform,
                        ),
                        MetricTile(
                          label: strings.isZh ? '创建 TUN' : 'Create TUN',
                          value: permission.canCreateTun,
                        ),
                        MetricTile(
                          label: strings.isZh ? '修改路由' : 'Modify routes',
                          value: permission.canModifyRoutes,
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    for (final check in permission.checks)
                      _PermissionCheckRow(check: check),
                    const SizedBox(height: 10),
                    Text(
                      permission.recommendedAction,
                      style: const TextStyle(
                        fontSize: 13,
                        height: 1.4,
                        color: AppTokens.colorTextSecondary,
                      ),
                    ),
                    if (permission.sudoCommand != null) ...[
                      const SizedBox(height: 8),
                      _CommandLine(command: permission.sudoCommand!),
                    ],
                  ],
                ),
        );
      },
    );
  }

  void _refresh() {
    setState(() {
      _permissionFuture = _checkPermissions();
    });
  }
}

class _PermissionCheckRow extends StatelessWidget {
  const _PermissionCheckRow({required this.check});

  final _PermissionCheck check;

  @override
  Widget build(BuildContext context) {
    final tone = switch (check.status) {
      'pass' => StatusTone.good,
      'warn' => StatusTone.warn,
      _ => StatusTone.bad,
    };
    final label = check.status.toUpperCase();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final details = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                check.label,
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                check.detail,
                style: const TextStyle(
                  fontSize: 12,
                  height: 1.35,
                  color: AppTokens.colorTextSecondary,
                ),
              ),
            ],
          );
          if (constraints.maxWidth < 360) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                StatusBadge(label: label, tone: tone),
                const SizedBox(height: 6),
                details,
              ],
            );
          }
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 76,
                child: StatusBadge(label: label, tone: tone),
              ),
              const SizedBox(width: 10),
              Expanded(child: details),
            ],
          );
        },
      ),
    );
  }
}

class _CommandLine extends StatelessWidget {
  const _CommandLine({required this.command});

  final String command;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppTokens.colorConsoleBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: AppTokens.colorConsoleBorder),
      ),
      child: Row(
        children: [
          Expanded(
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Text(
                command,
                style: const TextStyle(
                  color: AppTokens.colorConsoleText,
                  fontFamily: 'monospace',
                  fontSize: 12,
                ),
              ),
            ),
          ),
          IconButton(
            tooltip: strings.copy,
            onPressed: () => Clipboard.setData(ClipboardData(text: command)),
            icon: const Icon(Icons.copy_all_outlined, size: 17),
          ),
        ],
      ),
    );
  }
}

class _BoundaryPanel extends StatelessWidget {
  const _BoundaryPanel({required this.snapshot});

  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final protocol = _map(snapshot?.raw['protocol']);
    final mtu = _map(snapshot?.raw['mtu']);
    if (protocol.isEmpty && mtu.isEmpty) {
      return AppPanel(
        title: strings.protocolAndMtu,
        child: Text(
          strings.isZh
              ? '当前快照未上报协议边界或 MTU 策略。'
              : 'The current snapshot has no protocol boundary or MTU policy data.',
          style: const TextStyle(
            fontSize: 13,
            color: AppTokens.colorTextSecondary,
          ),
        ),
      );
    }
    return AppPanel(
      title: strings.protocolAndMtu,
      child: Wrap(
        spacing: 24,
        runSpacing: 12,
        children: [
          if (protocol.isNotEmpty) ...[
            MetricTile(
              label: strings.isZh ? '数据面' : 'Data plane',
              value: _value(protocol['data_plane']),
            ),
            MetricTile(
              label: strings.isZh ? '握手' : 'Handshake',
              value: _value(protocol['handshake']),
            ),
            MetricTile(
              label: strings.isZh ? 'AEAD' : 'AEAD',
              value: _value(protocol['aead']),
            ),
            MetricTile(
              label: strings.isZh ? '安全审计' : 'Security audit',
              value: _value(protocol['security_audit']),
            ),
          ],
          if (mtu.isNotEmpty) ...[
            MetricTile(
              label: strings.isZh ? '运行 MTU' : 'Runtime MTU',
              value: _value(mtu['configured_mtu']),
            ),
            MetricTile(label: 'Profile', value: _value(mtu['profile'])),
            MetricTile(
              label: strings.isZh ? 'Relay-safe' : 'Relay-safe',
              value: _value(mtu['relay_safe_mtu']),
            ),
            MetricTile(
              label: strings.isZh ? '自动 PMTU' : 'Auto PMTU',
              value: _value(mtu['automatic_pmtu']),
            ),
          ],
        ],
      ),
    );
  }
}

class _TaskPanel extends StatelessWidget {
  const _TaskPanel({required this.snapshot});

  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final tasks =
        snapshot?.health.criticalTasks ?? const <TaskStatusSnapshot>[];
    return AppPanel(
      title: strings.criticalTasks,
      child: tasks.isEmpty
          ? Text(
              strings.isZh
                  ? '当前快照没有关键任务明细。'
                  : 'No critical task details in the current snapshot.',
              style: const TextStyle(
                fontSize: 13,
                color: AppTokens.colorTextSecondary,
              ),
            )
          : Column(children: [for (final task in tasks) _TaskRow(task: task)]),
    );
  }
}

class _TaskRow extends StatelessWidget {
  const _TaskRow({required this.task});

  final TaskStatusSnapshot task;

  @override
  Widget build(BuildContext context) {
    final ok = task.error == null && (task.running || task.finished);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final badge = StatusBadge(
            label: ok ? 'OK' : 'WARN',
            tone: ok ? StatusTone.good : StatusTone.warn,
          );
          final name = Text(
            task.name,
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
          );
          final error = task.error;
          if (constraints.maxWidth < 380 && error != null) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(child: name),
                    const SizedBox(width: 10),
                    badge,
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  error,
                  style: const TextStyle(
                    fontSize: 12,
                    color: AppTokens.colorBadText,
                  ),
                ),
              ],
            );
          }
          return Row(
            children: [
              Expanded(child: name),
              if (error != null)
                Expanded(
                  child: Text(
                    error,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 12,
                      color: AppTokens.colorBadText,
                    ),
                  ),
                ),
              badge,
            ],
          );
        },
      ),
    );
  }
}

class _Summary extends StatelessWidget {
  const _Summary({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final health = snapshot?.health;
    return AppPanel(
      title: strings.summary,
      trailing: StatusBadge(
        label: statusStore.online ? strings.statusLoaded : strings.noSnapshot,
        tone: statusStore.online ? StatusTone.good : StatusTone.bad,
      ),
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(
            label: 'GET /health',
            value: statusStore.healthReachable
                ? strings.reachable
                : strings.offline,
            detail: strings.statusMessage(statusStore.lastHealthError),
          ),
          MetricTile(
            label: 'GET /status',
            value: strings.endpointStatusLabel(
              statusReachable: statusStore.statusReachable,
              healthReachable: statusStore.healthReachable,
            ),
            detail: strings.statusMessage(statusStore.lastStatusError),
          ),
          MetricTile(
            label: strings.serviceHealth,
            value: health == null
                ? '—'
                : strings.healthStatusLabel(health.status),
          ),
          MetricTile(
            label: strings.controlConnected,
            value: strings.optionalBoolLabel(health?.controlConnected),
          ),
          MetricTile(
            label: strings.reauthRequired,
            value: strings.optionalBoolLabel(health?.reauthRequired),
          ),
          MetricTile(
            label: strings.udpSockets,
            value: snapshot == null ? '—' : formatInt(snapshot!.udpSocketCount),
          ),
          MetricTile(
            label: strings.socketPoolActive,
            value: strings.optionalBoolLabel(snapshot?.udpSocketPoolActive),
          ),
          MetricTile(
            label: strings.relayConnected,
            value: strings.optionalBoolLabel(snapshot?.relayConnected),
          ),
          MetricTile(
            label: strings.peerCount,
            value: snapshot == null
                ? '—'
                : formatInt(snapshot!.stats.totalPeers),
          ),
          MetricTile(
            label: strings.lastRefresh,
            value: formatDateTime(statusStore.lastFetchedAt),
          ),
          MetricTile(
            label: strings.requestDuration,
            value: formatDuration(statusStore.lastRequestDuration),
          ),
          if (statusStore.lastError != null)
            MetricTile(
              label: strings.lastError,
              value:
                  strings.statusMessage(statusStore.lastError) ??
                  statusStore.lastError!,
            ),
          if (health?.reason != null)
            MetricTile(label: strings.healthReason, value: health!.reason!),
        ],
      ),
    );
  }
}

class _IssuesPanel extends StatelessWidget {
  const _IssuesPanel({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final issues = _collectIssues(strings);
    return AppPanel(
      title: strings.diagnosticIssues,
      trailing: StatusBadge(
        label: issues.isEmpty ? strings.noActionNeeded : strings.needsAttention,
        tone: issues.isEmpty ? StatusTone.good : StatusTone.warn,
      ),
      child: issues.isEmpty
          ? _IssueRow(
              title: strings.noActionNeeded,
              detail: strings.diagnosticNoIssues,
              tone: StatusTone.good,
            )
          : Column(
              children: [
                for (var index = 0; index < issues.length; index++) ...[
                  issues[index],
                  if (index != issues.length - 1)
                    Divider(
                      color: Theme.of(context).colorScheme.outlineVariant,
                    ),
                ],
              ],
            ),
    );
  }

  List<_IssueRow> _collectIssues(AppStrings strings) {
    final issues = <_IssueRow>[];
    if (!statusStore.healthReachable) {
      issues.add(
        _IssueRow(
          title: 'GET /health',
          detail:
              strings.statusMessage(statusStore.lastHealthError) ??
              statusStore.lastHealthError ??
              strings.offline,
          tone: StatusTone.bad,
        ),
      );
    }
    if (statusStore.healthReachable && !statusStore.statusReachable) {
      issues.add(
        _IssueRow(
          title: 'GET /status',
          detail:
              strings.statusMessage(statusStore.lastStatusError) ??
              statusStore.lastStatusError ??
              strings.unavailable,
          tone: StatusTone.warn,
        ),
      );
    }

    final health = snapshot?.health;
    if (health?.reauthRequired == true) {
      issues.add(
        _IssueRow(
          title: strings.reauthRequired,
          detail: strings.issueReauthRequired,
          tone: StatusTone.bad,
        ),
      );
    }
    if (health != null && !health.controlConnected) {
      issues.add(
        _IssueRow(
          title: strings.controlPlane,
          detail: strings.issueControlDisconnected,
          tone: StatusTone.warn,
        ),
      );
    }
    final reason = health?.reason?.trim();
    if (reason != null && reason.isNotEmpty) {
      issues.add(
        _IssueRow(
          title: strings.healthReason,
          detail: reason,
          tone: StatusTone.warn,
        ),
      );
    }
    if (snapshot != null && !snapshot!.relayConnected) {
      issues.add(
        _IssueRow(
          title: strings.relay,
          detail: strings.issueRelayDisconnected,
          tone: StatusTone.warn,
        ),
      );
    }
    final failedTasks =
        health?.criticalTasks
            .where((task) => task.error != null && task.error!.isNotEmpty)
            .toList(growable: false) ??
        const <TaskStatusSnapshot>[];
    for (final task in failedTasks.take(3)) {
      issues.add(
        _IssueRow(
          title: '${strings.criticalTasks}: ${task.name}',
          detail: task.error!,
          tone: StatusTone.bad,
        ),
      );
    }
    final peerWarnings =
        snapshot?.peers.where((peer) => peer.lastError != null).length ?? 0;
    if (peerWarnings > 0) {
      issues.add(
        _IssueRow(
          title: strings.attentionDevices,
          detail: strings.peerWarnings(peerWarnings),
          tone: StatusTone.warn,
        ),
      );
    }
    if (statusStore.lastError != null && issues.isEmpty) {
      issues.add(
        _IssueRow(
          title: strings.lastError,
          detail:
              strings.statusMessage(statusStore.lastError) ??
              statusStore.lastError!,
          tone: StatusTone.warn,
        ),
      );
    }
    return issues;
  }
}

class _IssueRow extends StatelessWidget {
  const _IssueRow({
    required this.title,
    required this.detail,
    required this.tone,
  });

  final String title;
  final String detail;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final iconColor = switch (tone) {
      StatusTone.good =>
        theme.brightness == Brightness.dark
            ? AppTokens.colorDarkGoodText
            : AppTokens.colorGoodText,
      StatusTone.warn =>
        theme.brightness == Brightness.dark
            ? AppTokens.colorDarkWarnText
            : AppTokens.colorWarnText,
      StatusTone.bad =>
        theme.brightness == Brightness.dark
            ? AppTokens.colorDarkBadText
            : AppTokens.colorBadText,
      StatusTone.neutral => theme.colorScheme.onSurfaceVariant,
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 1),
            child: Icon(
              tone == StatusTone.good
                  ? Icons.check_circle_outline
                  : Icons.info_outline_rounded,
              color: iconColor,
              size: 18,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  detail,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 12,
                    height: 1.35,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _RawJson extends StatefulWidget {
  const _RawJson({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  State<_RawJson> createState() => _RawJsonState();
}

class _RawJsonState extends State<_RawJson> {
  var _copied = false;
  var _expanded = false;
  DiagnosticsSnapshot? _cachedSnapshot;
  String? _cachedPrettyJson;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.rawStatusJson,
      trailing: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          OutlinedButton.icon(
            onPressed: () => setState(() => _expanded = !_expanded),
            icon: Icon(
              _expanded
                  ? Icons.unfold_less_outlined
                  : Icons.unfold_more_outlined,
              size: 16,
            ),
            label: Text(_expanded ? strings.hideRawJson : strings.showRawJson),
          ),
          OutlinedButton.icon(
            onPressed: () => _copy(_rawJson()),
            icon: Icon(
              _copied ? Icons.check_circle_outline : Icons.copy_all_outlined,
              size: 16,
            ),
            label: Text(_copied ? strings.copied : strings.copy),
          ),
        ],
      ),
      child: _expanded
          ? _RawJsonConsole(raw: _rawJson())
          : Text(
              strings.rawJsonCollapsed,
              style: const TextStyle(
                fontSize: 13,
                height: 1.35,
                color: AppTokens.colorTextSecondary,
              ),
            ),
    );
  }

  String _rawJson() {
    final snapshot = widget.snapshot;
    if (snapshot == null) return _readableErrorJson();
    if (!identical(snapshot, _cachedSnapshot)) {
      _cachedSnapshot = snapshot;
      _cachedPrettyJson = snapshot.prettyJson;
    }
    return _cachedPrettyJson!;
  }

  String _readableErrorJson() {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert({
      'status': widget.statusStore.healthReachable
          ? 'status_unavailable'
          : 'offline',
      'health_endpoint': widget.statusStore.healthReachable
          ? 'reachable'
          : 'offline',
      'status_endpoint': widget.statusStore.statusReachable
          ? 'loaded'
          : widget.statusStore.healthReachable
          ? 'error'
          : 'skipped',
      if (widget.statusStore.lastError != null)
        'error': widget.statusStore.lastError,
      if (widget.statusStore.lastFetchedAt != null)
        'last_refresh': widget.statusStore.lastFetchedAt!.toIso8601String(),
      if (widget.statusStore.lastRequestDuration != null)
        'request_duration_ms':
            widget.statusStore.lastRequestDuration!.inMilliseconds,
    });
  }

  Future<void> _copy(String raw) async {
    final strings = AppStringsScope.of(context);
    await Clipboard.setData(ClipboardData(text: raw));
    if (!mounted) return;
    setState(() => _copied = true);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(strings.copiedDiagnosticsJson),
        duration: const Duration(seconds: 2),
      ),
    );
    await Future<void>.delayed(const Duration(seconds: 2));
    if (mounted) {
      setState(() => _copied = false);
    }
  }
}

class _RawJsonConsole extends StatelessWidget {
  const _RawJsonConsole({required this.raw});

  final String raw;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      constraints: const BoxConstraints(minHeight: 220),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTokens.colorConsoleBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: AppTokens.colorConsoleBorder),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Text(
          raw,
          style: const TextStyle(
            color: AppTokens.colorConsoleText,
            fontFamily: 'monospace',
            fontSize: 12.5,
            height: 1.4,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ),
    );
  }
}

class _RecentLogsPanel extends StatefulWidget {
  const _RecentLogsPanel();

  @override
  State<_RecentLogsPanel> createState() => _RecentLogsPanelState();
}

class _RecentLogsPanelState extends State<_RecentLogsPanel> {
  late Future<_LogPreview> _previewFuture;

  @override
  void initState() {
    super.initState();
    _previewFuture = _loadLogPreview();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.recentDaemonLogs,
      trailing: OutlinedButton.icon(
        onPressed: _refresh,
        icon: const Icon(Icons.refresh_rounded, size: 16),
        label: Text(strings.refresh),
      ),
      child: FutureBuilder<_LogPreview>(
        future: _previewFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const SizedBox(
              height: 72,
              child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
            );
          }
          final preview = snapshot.data;
          if (preview == null) {
            return _LogMessage(
              message: strings.isZh
                  ? '无法读取日志目录。'
                  : 'Unable to read the log directory.',
            );
          }
          if (preview.error != null) {
            return _LogMessage(message: preview.error!);
          }
          if (preview.content.isEmpty) {
            return _LogMessage(
              message: strings.isZh
                  ? '尚未找到 daemon 日志文件：${preview.path}'
                  : 'No daemon log file found yet: ${preview.path}',
            );
          }
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Wrap(
                spacing: 8,
                runSpacing: 8,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(
                    strings.isZh
                        ? '显示最后 ${preview.shownLineCount}/${preview.lineCount} 行'
                        : 'Showing last ${preview.shownLineCount}/${preview.lineCount} lines',
                    style: const TextStyle(
                      fontSize: 12,
                      color: AppTokens.colorTextSecondary,
                      fontFeatures: AppTokens.tabularFontFeatures,
                    ),
                  ),
                  OutlinedButton.icon(
                    onPressed: () => _copyLogs(preview.content),
                    icon: const Icon(Icons.copy_all_outlined, size: 15),
                    label: Text(strings.copy),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Container(
                width: double.infinity,
                constraints: const BoxConstraints(maxHeight: 280),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppTokens.colorConsoleBg,
                  borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                  border: Border.all(color: AppTokens.colorConsoleBorder),
                ),
                child: SingleChildScrollView(
                  child: SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Text(
                      preview.content,
                      style: const TextStyle(
                        color: AppTokens.colorConsoleText,
                        fontFamily: 'monospace',
                        fontSize: 12,
                        height: 1.35,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 8),
              Text(
                preview.path,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontSize: 11,
                  color: AppTokens.colorTextSecondary,
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  void _refresh() {
    setState(() {
      _previewFuture = _loadLogPreview();
    });
  }

  Future<void> _copyLogs(String content) async {
    final strings = AppStringsScope.of(context);
    await Clipboard.setData(ClipboardData(text: content));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(strings.isZh ? '日志片段已复制' : 'Log excerpt copied')),
    );
  }
}

class _LogMessage extends StatelessWidget {
  const _LogMessage({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Text(
      message,
      style: const TextStyle(
        fontSize: 13,
        height: 1.4,
        color: AppTokens.colorTextSecondary,
      ),
    );
  }
}

class _LogPreview {
  const _LogPreview({
    required this.path,
    required this.content,
    required this.lineCount,
    required this.shownLineCount,
    this.error,
  });

  final String path;
  final String content;
  final int lineCount;
  final int shownLineCount;
  final String? error;
}

class _PermissionSnapshot {
  const _PermissionSnapshot({
    required this.platform,
    required this.canCreateTun,
    required this.canModifyRoutes,
    required this.needsElevation,
    required this.recommendedAction,
    required this.checks,
    this.sudoCommand,
  });

  final String platform;
  final String canCreateTun;
  final String canModifyRoutes;
  final bool needsElevation;
  final String recommendedAction;
  final List<_PermissionCheck> checks;
  final String? sudoCommand;

  bool get bad =>
      needsElevation || checks.any((check) => check.status == 'fail');
  bool get warn =>
      checks.any((check) => check.status == 'warn') ||
      canCreateTun == 'unknown' ||
      canModifyRoutes == 'unknown';
}

class _PermissionCheck {
  const _PermissionCheck({
    required this.label,
    required this.status,
    required this.detail,
  });

  final String label;
  final String status;
  final String detail;
}

Future<_PermissionSnapshot> _checkPermissions() async {
  if (Platform.isWindows) return _checkWindowsPermissions();
  if (Platform.isLinux) return _checkLinuxPermissions();
  if (Platform.isMacOS) return _checkMacosPermissions();
  return _PermissionSnapshot(
    platform: _platformName(),
    canCreateTun: 'unknown',
    canModifyRoutes: 'unknown',
    needsElevation: true,
    recommendedAction:
        'Local daemon process control is not supported on this platform yet.',
    checks: const [
      _PermissionCheck(
        label: 'Desktop platform',
        status: 'fail',
        detail: 'Use macOS, Linux, or Windows for local TUN control.',
      ),
    ],
  );
}

_PermissionSnapshot _checkMacosPermissions() {
  final euid = _effectiveUserId();
  final isRoot = euid == 0;
  final hasDevTun =
      File('/dev/net/tun').existsSync() || File('/dev/tun').existsSync();
  return _PermissionSnapshot(
    platform: 'macOS',
    canCreateTun: isRoot ? 'unknown' : 'false',
    canModifyRoutes: isRoot ? 'true' : 'false',
    needsElevation: !isRoot,
    recommendedAction: isRoot
        ? '权限已满足；macOS utun 创建仍会在 daemon 启动时做运行时验证。'
        : '启动 TUN 时需要管理员授权；P2WLAN 会使用系统授权弹窗，不读取或保存密码。',
    sudoCommand: isRoot ? null : _suggestedSudoCommand(),
    checks: [
      _PermissionCheck(
        label: '有效用户权限',
        status: isRoot ? 'pass' : 'fail',
        detail: isRoot
            ? '已以 root 身份运行 (euid=$euid)。'
            : '当前是普通用户 (euid=${euid ?? 'unknown'})。',
      ),
      _PermissionCheck(
        label: 'TUN 设备节点',
        status: hasDevTun ? 'pass' : 'warn',
        detail: hasDevTun
            ? '/dev 中存在 TUN 设备节点。'
            : 'macOS 通常动态创建 utun；未找到静态 /dev/net/tun 属于正常情况。',
      ),
    ],
  );
}

_PermissionSnapshot _checkLinuxPermissions() {
  final euid = _effectiveUserId();
  final isRoot = euid == 0;
  final devTun = File('/dev/net/tun');
  final hasDevTun = devTun.existsSync();
  final daemonBinary = _resolveDaemonBinaryForPermissions();
  final hasCapNetAdmin = _hasNetAdminCapability(daemonBinary);
  final privileged = isRoot || hasCapNetAdmin;
  return _PermissionSnapshot(
    platform: 'Linux',
    canCreateTun: hasDevTun && privileged
        ? 'true'
        : hasDevTun
        ? 'unknown'
        : 'false',
    canModifyRoutes: privileged ? 'true' : 'unknown',
    needsElevation: !privileged,
    recommendedAction: privileged && hasDevTun
        ? '权限已满足，daemon 可以创建 TUN 并维护路由。'
        : '请使用 pkexec/sudo 启动 daemon，或对 p2wlan-daemon 设置 CAP_NET_ADMIN。',
    sudoCommand: privileged ? null : _suggestedSudoCommand(),
    checks: [
      _PermissionCheck(
        label: '有效用户权限',
        status: isRoot
            ? 'pass'
            : hasCapNetAdmin
            ? 'warn'
            : 'fail',
        detail: isRoot
            ? '已以 root 身份运行 (euid=$euid)。'
            : hasCapNetAdmin
            ? '当前不是 root，但 daemon 二进制带 cap_net_admin。'
            : '当前是普通用户 (euid=${euid ?? 'unknown'})，需要提权或 setcap。',
      ),
      _PermissionCheck(
        label: '/dev/net/tun',
        status: hasDevTun ? 'pass' : 'fail',
        detail: hasDevTun
            ? '/dev/net/tun 设备节点可访问。'
            : '未找到 /dev/net/tun，无法创建 Linux TUN。',
      ),
      _PermissionCheck(
        label: 'daemon capability',
        status: hasCapNetAdmin
            ? 'pass'
            : daemonBinary == null
            ? 'warn'
            : 'warn',
        detail: daemonBinary == null
            ? '未定位到 p2wlan-daemon，无法检查 cap_net_admin。'
            : hasCapNetAdmin
            ? '${daemonBinary.path} 具备 cap_net_admin。'
            : '${daemonBinary.path} 未检测到 cap_net_admin。',
      ),
    ],
  );
}

_PermissionSnapshot _checkWindowsPermissions() {
  final isAdmin = _isWindowsAdministrator();
  final wintun = _findWintunDll();
  return _PermissionSnapshot(
    platform: 'Windows',
    canCreateTun: isAdmin && wintun != null ? 'true' : 'false',
    canModifyRoutes: isAdmin ? 'true' : 'false',
    needsElevation: !isAdmin,
    recommendedAction: isAdmin && wintun != null
        ? 'Windows 管理员权限和 Wintun 运行库均已就绪。'
        : !isAdmin
        ? '启动 TUN 时请确认 Windows UAC 授权，并确保 wintun.dll 与客户端/daemon 同级或在 PATH 中。'
        : '请把 wintun.dll 放到客户端/daemon 同级目录，或设置 P2WLAN_WINTUN_DLL。',
    checks: [
      _PermissionCheck(
        label: 'Windows 管理员权限',
        status: isAdmin ? 'pass' : 'fail',
        detail: isAdmin ? '当前已具备管理员权限。' : '安装 Wintun 虚拟网卡和更新路由需要管理员权限。',
      ),
      _PermissionCheck(
        label: 'Wintun 运行库',
        status: wintun == null ? 'fail' : 'pass',
        detail: wintun == null
            ? '未在客户端/daemon 同级目录、P2WLAN_WINTUN_DLL 或 PATH 中找到 wintun.dll。'
            : '已找到 ${wintun.path}',
      ),
    ],
  );
}

Future<_LogPreview> _loadLogPreview() async {
  final path =
      '${_defaultLogDir().path}${Platform.pathSeparator}p2wlan-daemon.log';
  final file = File(path);
  try {
    if (!await file.exists()) {
      return _LogPreview(
        path: path,
        content: '',
        lineCount: 0,
        shownLineCount: 0,
      );
    }
    final lines = await file.readAsLines();
    final start = lines.length > 120 ? lines.length - 120 : 0;
    final shown = lines.sublist(start);
    return _LogPreview(
      path: path,
      content: shown.join('\n'),
      lineCount: lines.length,
      shownLineCount: shown.length,
    );
  } catch (error) {
    return _LogPreview(
      path: path,
      content: '',
      lineCount: 0,
      shownLineCount: 0,
      error: 'Failed to read $path: $error',
    );
  }
}

Directory _defaultLogDir() {
  if (Platform.isMacOS) {
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/Library/Logs/p2wlan');
    }
  }
  if (Platform.isWindows) {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    if (localAppData != null && localAppData.isNotEmpty) {
      return Directory('$localAppData\\p2wlan\\logs');
    }
  }
  final home = Platform.environment['HOME'];
  if (home != null && home.isNotEmpty) {
    return Directory('$home/.local/state/p2wlan');
  }
  return Directory(
    '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
  );
}

String _platformName() {
  if (Platform.isMacOS) return 'macOS';
  if (Platform.isWindows) return 'Windows';
  if (Platform.isLinux) return 'Linux';
  if (Platform.isAndroid) return 'Android';
  if (Platform.isIOS) return 'iOS';
  if (Platform.isFuchsia) return 'Fuchsia';
  return Platform.operatingSystem;
}

int? _effectiveUserId() {
  if (!Platform.isMacOS && !Platform.isLinux) return null;
  try {
    final result = Process.runSync('id', ['-u']);
    if (result.exitCode != 0) return null;
    return int.tryParse(result.stdout.toString().trim());
  } catch (_) {
    return Platform.environment['USER'] == 'root' ? 0 : null;
  }
}

bool _isWindowsAdministrator() {
  if (!Platform.isWindows) return false;
  try {
    final result = Process.runSync('net', ['session']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

File? _findWintunDll() {
  if (!Platform.isWindows) return null;
  final candidates = <String>{};
  final envPath = Platform.environment['P2WLAN_WINTUN_DLL']?.trim();
  if (envPath != null && envPath.isNotEmpty) candidates.add(envPath);

  final exeDir = File(Platform.resolvedExecutable).parent.path;
  candidates.add('$exeDir${Platform.pathSeparator}wintun.dll');
  candidates.add(
    '${Directory.current.path}${Platform.pathSeparator}wintun.dll',
  );

  final pathValue = Platform.environment['PATH'];
  if (pathValue != null && pathValue.isNotEmpty) {
    for (final dir in pathValue.split(';')) {
      final trimmed = dir.trim();
      if (trimmed.isNotEmpty) {
        candidates.add('$trimmed${Platform.pathSeparator}wintun.dll');
      }
    }
  }

  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) return file;
  }
  return null;
}

File? _resolveDaemonBinaryForPermissions() {
  final envPath = Platform.environment['P2WLAN_DAEMON_BIN']?.trim();
  if (envPath != null && envPath.isNotEmpty) {
    final file = File(envPath);
    if (file.existsSync()) return file;
  }

  final extension = Platform.isWindows ? '.exe' : '';
  final name = 'p2wlan-daemon$extension';
  final candidates = <File>[];
  final exeDir = File(Platform.resolvedExecutable).parent;
  candidates.add(File('${exeDir.path}${Platform.pathSeparator}$name'));
  candidates.add(
    File(
      '${exeDir.parent.path}${Platform.pathSeparator}Resources${Platform.pathSeparator}$name',
    ),
  );

  var dir = Directory.current;
  for (var depth = 0; depth < 6; depth += 1) {
    candidates.add(
      File('${dir.path}${Platform.pathSeparator}target/release/$name'),
    );
    candidates.add(
      File('${dir.path}${Platform.pathSeparator}target/debug/$name'),
    );
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }

  for (final candidate in candidates) {
    if (candidate.existsSync()) return candidate;
  }
  return _whichFile(name);
}

File? _whichFile(String name) {
  try {
    final result = Process.runSync(Platform.isWindows ? 'where' : 'which', [
      name,
    ]);
    if (result.exitCode != 0) return null;
    final first = result.stdout.toString().split('\n').first.trim();
    if (first.isEmpty) return null;
    final file = File(first);
    return file.existsSync() ? file : null;
  } catch (_) {
    return null;
  }
}

bool _hasNetAdminCapability(File? binary) {
  if (binary == null || !Platform.isLinux) return false;
  try {
    final result = Process.runSync('getcap', [binary.path]);
    if (result.exitCode != 0) return false;
    return result.stdout.toString().contains('cap_net_admin');
  } catch (_) {
    return false;
  }
}

String _suggestedSudoCommand() {
  final envPath = Platform.environment['P2WLAN_DAEMON_BIN']?.trim();
  final binary = envPath != null && envPath.isNotEmpty
      ? envPath
      : 'p2wlan-daemon';
  final quoted = _shellQuote(binary);
  return 'sudo -E P2WLAN_DAEMON_BIN=$quoted $quoted --diagnostics-bind 127.0.0.1:39277';
}

String _shellQuote(String value) => "'${value.replaceAll("'", "'\\''")}'";

JsonMap _map(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return {};
}

String _value(dynamic value) {
  if (value == null) return '—';
  if (value is bool) return value ? 'yes' : 'no';
  if (value is num) return value.toString();
  if (value is Iterable) return value.join(', ');
  if (value is Map) return jsonEncode(value);
  final text = value.toString().trim();
  return text.isEmpty ? '—' : text;
}
