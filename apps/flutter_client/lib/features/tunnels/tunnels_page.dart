import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
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
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  @override
  State<TunnelsPage> createState() => _TunnelsPageState();
}

class _TunnelsPageState extends State<TunnelsPage> {
  String? _message;
  var _rebuilding = false;

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
          children: [
            if (_message != null) ...[
              _InfoBanner(message: _message!),
              const SizedBox(height: 14),
            ],
            _SummaryStrip(
              running: running,
              snapshot: snapshot,
              settings: settings,
            ),
            const SizedBox(height: 14),
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
                  rebuilding: _rebuilding,
                  onRebuild: _rebuildRoutes,
                );
                if (constraints.maxWidth < 760) {
                  return Column(
                    children: [
                      tunnelPanel,
                      const SizedBox(height: 14),
                      routePanel,
                    ],
                  );
                }
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: tunnelPanel),
                    const SizedBox(width: 14),
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
            label: strings.isZh ? '网卡' : 'Interface',
            value: settings.effectiveTunInterface,
          ),
          MetricTile(
            label: strings.virtualIp,
            value: _dash(snapshot?.virtualIp),
          ),
          MetricTile(label: 'MTU', value: settings.mtu.toString()),
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
            label: strings.isZh ? '网卡名称' : 'Interface',
            value: settings.effectiveTunInterface,
          ),
          _Kv(label: 'Overlay CIDR', value: settings.overlayCidr),
          _Kv(label: strings.virtualIp, value: _dash(snapshot?.virtualIp)),
          _Kv(label: 'MTU', value: settings.mtu.toString()),
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
    required this.rebuilding,
    required this.onRebuild,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool running;
  final bool rebuilding;
  final Future<void> Function() onRebuild;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final installed = running && snapshot?.virtualIp.trim().isNotEmpty == true;
    return AppPanel(
      title: strings.route,
      trailing: StatusBadge(
        label: installed
            ? (strings.isZh ? '已安装' : 'Installed')
            : (strings.isZh ? '未知' : 'Unknown'),
        tone: installed ? StatusTone.good : StatusTone.neutral,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Kv(
            label: strings.isZh ? '目标网段' : 'Destination',
            value: settings.overlayCidr,
          ),
          _Kv(
            label: strings.isZh ? '目标网卡' : 'Interface',
            value: settings.effectiveTunInterface,
          ),
          _Kv(
            label: strings.isZh ? '状态说明' : 'Detail',
            value: installed
                ? (strings.isZh
                      ? '守护进程在线，Overlay 路由应由 daemon 维护。'
                      : 'Daemon is online; overlay routes are maintained by the daemon.')
                : (strings.isZh
                      ? '守护进程离线或尚未分配虚拟 IP。'
                      : 'Daemon is offline or virtual IP is not assigned.'),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              onPressed: rebuilding ? null : onRebuild,
              icon: rebuilding
                  ? const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.restart_alt_rounded),
              label: Text(
                strings.isZh
                    ? '重启 daemon 重装路由'
                    : 'Restart daemon to rebuild routes',
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
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 132,
            child: Text(
              label,
              style: const TextStyle(
                fontSize: 12,
                color: AppTokens.colorTextSecondary,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(
                fontSize: 13,
                color: AppTokens.colorTextPrimary,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _InfoBanner extends StatelessWidget {
  const _InfoBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: AppTokens.colorWarnBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: AppTokens.colorWarnBorder),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Text(
          message,
          style: const TextStyle(
            color: AppTokens.colorWarnText,
            fontSize: 13,
            height: 1.35,
          ),
        ),
      ),
    );
  }
}

String _dash(String? value) {
  final trimmed = value?.trim() ?? '';
  return trimmed.isEmpty ? '—' : trimmed;
}
