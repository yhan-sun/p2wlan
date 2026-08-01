part of '../diagnostics_page.dart';

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
