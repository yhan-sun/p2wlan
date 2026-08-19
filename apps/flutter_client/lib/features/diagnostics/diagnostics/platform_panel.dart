part of '../diagnostics_page.dart';

class _PlatformPanel extends StatefulWidget {
  const _PlatformPanel({this.permissionCheck});

  /// Test seam: replaces the real platform permission preflight.
  final Future<PermissionPreflight> Function()? permissionCheck;

  @override
  State<_PlatformPanel> createState() => _PlatformPanelState();
}

class _PlatformPanelState extends State<_PlatformPanel> {
  late Future<_PermissionSnapshot> _permissionFuture;

  @override
  void initState() {
    super.initState();
    _permissionFuture = (widget.permissionCheck ?? _checkPermissions)();
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
                    const SizedBox(height: AppTokens.space4),
                    for (final check in permissionCheckPresentations(
                      strings,
                      permission,
                    ))
                      _PermissionCheckRow(presentation: check),
                    const SizedBox(height: AppTokens.space10),
                    Text(
                      permissionRecommendedAction(strings, permission),
                      style: TextStyle(
                        fontSize: 13,
                        height: 1.4,
                        color: themeTextSecondary(context),
                      ),
                    ),
                    if (permission.sudoCommand != null) ...[
                      const SizedBox(height: AppTokens.space8),
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
      _permissionFuture = (widget.permissionCheck ?? _checkPermissions)();
    });
  }
}

class _PermissionCheckRow extends StatelessWidget {
  const _PermissionCheckRow({required this.presentation});

  final PermissionCheckPresentation presentation;

  @override
  Widget build(BuildContext context) {
    final tone = switch (presentation.status) {
      'pass' => StatusTone.good,
      'warn' => StatusTone.warn,
      _ => StatusTone.bad,
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final details = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                presentation.title,
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                presentation.detail,
                style: TextStyle(
                  fontSize: 12,
                  height: 1.35,
                  color: themeTextSecondary(context),
                ),
              ),
            ],
          );
          if (constraints.maxWidth < 360) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                StatusBadge(label: presentation.statusLabel, tone: tone),
                const SizedBox(height: AppTokens.space6),
                details,
              ],
            );
          }
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 76,
                child: StatusBadge(label: presentation.statusLabel, tone: tone),
              ),
              const SizedBox(width: AppTokens.space10),
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
      padding: const EdgeInsets.all(AppTokens.space10),
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
