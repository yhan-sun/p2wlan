part of '../diagnostics_page.dart';

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
                          value: permission.canCreateTunLabel,
                        ),
                        MetricTile(
                          label: strings.isZh ? '修改路由' : 'Modify routes',
                          value: permission.canModifyRoutesLabel,
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
