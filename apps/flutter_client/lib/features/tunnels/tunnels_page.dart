import 'package:flutter/material.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

class TunnelsPage extends StatefulWidget {
  const TunnelsPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  @override
  State<TunnelsPage> createState() => _TunnelsPageState();
}

class _TunnelsPageState extends State<TunnelsPage> {
  String? _message;
  var _rebuilding = false;
  // Authoritative overlay-route state, fetched from the daemon (never inferred
  // from "daemon running + virtual IP"). `null` = not yet verified.
  Map<String, dynamic>? _routeState;
  var _verifying = false;
  var _repairing = false;

  @override
  void initState() {
    super.initState();
    _verifyRoutes();
  }

  /// Read-only authoritative check of the live system routing table.
  Future<void> _verifyRoutes() async {
    final url = widget.settingsStore.settings.diagnosticsUrl;
    if (!widget.statusStore.daemonReachable) return;
    setState(() {
      _verifying = true;
    });
    try {
      final result = await widget.statusStore.diagnosticsApi.verifyRoutes(url);
      if (!mounted) return;
      setState(() => _routeState = result.toJson());
    } catch (_) {
      // Daemon may not expose /routes/verify yet; leave state unknown.
    } finally {
      if (mounted) setState(() => _verifying = false);
    }
  }

  /// Repair the overlay route in place — no daemon/TUN/session restart.
  Future<void> _repairRoutes() async {
    final strings = AppStringsScope.of(context);
    final url = widget.settingsStore.settings.diagnosticsUrl;
    setState(() {
      _repairing = true;
      _message = null;
    });
    try {
      final result = await widget.statusStore.diagnosticsApi.repairRoutes(url);
      final changed = result.changed;
      final after = result.after;
      if (!mounted) return;
      setState(() {
        _routeState = result.toJson();
        _message = changed
            ? (strings.isZh
                  ? '路由已就地修复（状态：$after），未重启 daemon。'
                  : 'Route repaired in place (state: $after) without restarting the daemon.')
            : (strings.isZh
                  ? '路由已正确安装，无需修复。'
                  : 'Route was already correctly installed; no change needed.');
      });
    } catch (error) {
      if (mounted) {
        setState(() => _message = '路由修复失败：$error');
      }
    } finally {
      if (mounted) setState(() => _repairing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: Listenable.merge([widget.settingsStore, widget.statusStore]),
      builder: (context, _) {
        final snapshot = widget.statusStore.snapshot;
        final settings = widget.settingsStore.settings;
        final running = widget.statusStore.daemonReachable && snapshot != null;
        return PageScaffold(
          title: strings.tunnels,
          subtitle: strings.isZh
              ? '查看虚拟网卡、UDP 绑定和 Overlay 路由生命周期。'
              : 'Inspect virtual adapter, UDP bind, and overlay route lifecycle.',
          showHeader: widget.showHeader,
          maxWidth: tunnelsPageMaxWidth,
          children: [
            if (_message != null) ...[
              _InfoBanner(message: _message!),
              const SizedBox(height: AppTokens.space14),
            ],
            _SummaryStrip(
              running: running,
              snapshot: snapshot,
              settings: settings,
            ),
            const SizedBox(height: AppTokens.space14),
            LayoutBuilder(
              builder: (context, constraints) {
                final tunnelPanel = _TunnelPanel(
                  snapshot: snapshot,
                  settings: settings,
                  running: running,
                );
                final routePanel = _RoutePanel(
                  snapshot: snapshot,
                  settings: settings,
                  running: running,
                  routeState: _routeState,
                  verifying: _verifying,
                  repairing: _repairing,
                  rebuilding: _rebuilding,
                  onVerify: _verifyRoutes,
                  onRepair: _repairRoutes,
                  onRebuild: _rebuildRoutes,
                );
                if (constraints.maxWidth < 760) {
                  return Column(
                    children: [
                      tunnelPanel,
                      const SizedBox(height: AppTokens.space14),
                      routePanel,
                    ],
                  );
                }
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: tunnelPanel),
                    const SizedBox(width: AppTokens.space14),
                    Expanded(child: routePanel),
                  ],
                );
              },
            ),
          ],
        );
      },
    );
  }

  Future<void> _rebuildRoutes() async {
    final strings = AppStringsScope.of(context);
    setState(() {
      _rebuilding = true;
      _message = null;
    });
    try {
      final stop = await widget.statusStore.stopDaemon();
      if (!stop.ok) {
        setState(() => _message = stop.message);
        return;
      }
      final start = await widget.statusStore.startDaemon();
      setState(() {
        _message = start.ok
            ? (strings.isZh
                  ? '已通过重启 daemon 触发 Overlay 路由重装。'
                  : 'Daemon restarted to reinstall overlay routes.')
            : start.message;
      });
    } finally {
      if (mounted) setState(() => _rebuilding = false);
    }
  }
}

class _SummaryStrip extends StatelessWidget {
  const _SummaryStrip({
    required this.running,
    required this.snapshot,
    required this.settings,
  });

  final bool running;
  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.isZh ? '隧道摘要' : 'Tunnel summary',
      child: Wrap(
        spacing: 24,
        runSpacing: 10,
        children: [
          MetricTile(
            label: strings.isZh ? '启动网卡配置' : 'Startup interface',
            value: settings.effectiveTunInterface,
          ),
          MetricTile(
            label: strings.virtualIp,
            value: _dash(snapshot?.virtualIp),
          ),
          MetricTile(
            label: strings.isZh ? '启动 MTU 配置' : 'Startup MTU',
            value: settings.mtu.toString(),
          ),
          MetricTile(
            label: strings.isZh ? '状态' : 'State',
            value: running ? strings.connected : strings.offline,
          ),
        ],
      ),
    );
  }
}

class _TunnelPanel extends StatelessWidget {
  const _TunnelPanel({
    required this.snapshot,
    required this.settings,
    required this.running,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool running;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.isZh ? '虚拟网卡' : 'Virtual Adapter',
      trailing: StatusBadge(
        label: running ? 'UP' : 'DOWN',
        tone: running ? StatusTone.good : StatusTone.bad,
      ),
      child: Column(
        children: [
          _Kv(
            label: strings.isZh ? '启动网卡配置' : 'Startup interface',
            value: settings.effectiveTunInterface,
          ),
          _Kv(label: 'Overlay CIDR', value: settings.overlayCidr),
          _Kv(label: strings.virtualIp, value: _dash(snapshot?.virtualIp)),
          _Kv(
            label: strings.isZh ? '启动 MTU 配置' : 'Startup MTU',
            value: settings.mtu.toString(),
          ),
          _Kv(
            label: strings.udpLocalAddr,
            value: _dash(snapshot?.udpLocalAddr ?? settings.udpBind),
          ),
          _Kv(
            label: strings.isZh ? 'UDP sockets' : 'UDP sockets',
            value: (snapshot?.udpSocketCount ?? 0).toString(),
          ),
        ],
      ),
    );
  }
}

class _RoutePanel extends StatelessWidget {
  const _RoutePanel({
    required this.snapshot,
    required this.settings,
    required this.running,
    required this.routeState,
    required this.verifying,
    required this.repairing,
    required this.rebuilding,
    required this.onVerify,
    required this.onRepair,
    required this.onRebuild,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool running;
  final Map<String, dynamic>? routeState;
  final bool verifying;
  final bool repairing;
  final bool rebuilding;
  final Future<void> Function() onVerify;
  final Future<void> Function() onRepair;
  final Future<void> Function() onRebuild;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final isZh = strings.isZh;

    // Authoritative state comes from the daemon when available; otherwise we
    // report "unknown" rather than guessing from daemon-running + virtual IP.
    final state =
        routeState?['entries'] is List &&
            (routeState?['entries'] as List).isNotEmpty
        ? ((routeState?['entries']) as List).first as Map<String, dynamic>
        : null;
    final routeOk = state?['state'] == 'installed';
    final routeConflict = state?['state'] == 'conflict';
    final actual = state?['actual_interface']?.toString();
    final expected = state?['expected_interface']?.toString();

    String badgeLabel;
    StatusTone badgeTone;
    if (!running) {
      badgeLabel = isZh ? '离线' : 'Offline';
      badgeTone = StatusTone.neutral;
    } else if (state == null) {
      badgeLabel = isZh ? '未知（未校验）' : 'Unknown (unverified)';
      badgeTone = StatusTone.warn;
    } else if (routeOk) {
      badgeLabel = isZh ? '已安装' : 'Installed';
      badgeTone = StatusTone.good;
    } else if (routeConflict) {
      badgeLabel = isZh ? '冲突' : 'Conflict';
      badgeTone = StatusTone.bad;
    } else {
      badgeLabel = isZh ? '缺失' : 'Missing';
      badgeTone = StatusTone.bad;
    }

    return AppPanel(
      title: strings.route,
      trailing: StatusBadge(label: badgeLabel, tone: badgeTone),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Kv(
            label: isZh ? '目标网段' : 'Destination',
            value: settings.overlayCidr,
          ),
          _Kv(
            label: isZh ? '期望网卡' : 'Expected interface',
            value: expected ?? settings.effectiveTunInterface,
          ),
          if (actual != null)
            _Kv(
              label: isZh ? '系统实际网卡' : 'Actual (system table)',
              value: actual,
            ),
          _Kv(
            label: isZh ? '状态说明' : 'Detail',
            value: state == null
                ? (isZh
                      ? '尚未从 daemon 读取系统路由表；点击"检查路由"。'
                      : 'Not yet read from the daemon; tap "Check routes".')
                : (isZh
                      ? '权威状态：${routeState?['state'] ?? state['state']}。'
                      : 'Authoritative state: ${routeState?['state'] ?? state['state']}.'),
          ),
          const SizedBox(height: AppTokens.space12),
          // Check (read-only, safe anytime) + Repair (in place, no restart).
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: running && !verifying ? onVerify : null,
                  icon: verifying
                      ? const SizedBox.square(
                          dimension: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.check_circle_outline_rounded),
                  label: Text(isZh ? '检查路由' : 'Check routes'),
                ),
              ),
              const SizedBox(width: AppTokens.space10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: running && !repairing ? onRepair : null,
                  icon: repairing
                      ? const SizedBox.square(
                          dimension: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.build_rounded),
                  label: Text(isZh ? '修复路由' : 'Repair routes'),
                ),
              ),
            ],
          ),
          const SizedBox(height: AppTokens.space8),
          // Restarting the daemon is a heavier, distinct action — keep it
          // available but clearly secondary (it interrupts the connection).
          Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              onPressed: running && !(verifying || repairing)
                  ? onRebuild
                  : null,
              icon: rebuilding
                  ? const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.restart_alt_rounded, size: 16),
              label: Text(
                isZh
                    ? '重启网络服务（会短暂断开）'
                    : 'Restart network service (brief disconnect)',
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Kv extends StatelessWidget {
  const _Kv({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final labelText = Text(
            label,
            style: TextStyle(
              fontSize: 12,
              color: c.textSecondary,
              fontWeight: FontWeight.w600,
            ),
          );
          final valueText = Text(
            value,
            style: TextStyle(
              fontSize: 13,
              color: c.textPrimary,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          );
          if (constraints.maxWidth < 360) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [labelText, const SizedBox(height: 3), valueText],
            );
          }
          final labelWidth = constraints.maxWidth < 460 ? 104.0 : 132.0;
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: labelWidth, child: labelText),
              Expanded(child: valueText),
            ],
          );
        },
      ),
    );
  }
}

class _InfoBanner extends StatelessWidget {
  const _InfoBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: c.warningSurface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: c.warningBorder),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space12),
        child: Text(
          message,
          style: TextStyle(color: c.warningText, fontSize: 13, height: 1.35),
        ),
      ),
    );
  }
}

String _dash(String? value) {
  final trimmed = value?.trim() ?? '';
  return trimmed.isEmpty ? '—' : trimmed;
}
