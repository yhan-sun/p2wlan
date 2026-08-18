part of '../diagnostics_page.dart';

class _RecentLogsPanel extends StatefulWidget {
  const _RecentLogsPanel({this.logPreviewLoader, this.openLogs});

  /// Test seam: replaces the bounded log-tail loader. When null the real
  /// loader runs. Either way the panel redacts content before display.
  final Future<DiagnosticsLogPreview> Function()? logPreviewLoader;

  /// Test seam: replaces the "open logs directory" action.
  final Future<void> Function()? openLogs;

  @override
  State<_RecentLogsPanel> createState() => _RecentLogsPanelState();
}

class _RecentLogsPanelState extends State<_RecentLogsPanel> {
  late Future<DiagnosticsLogPreview> _previewFuture;

  @override
  void initState() {
    super.initState();
    // Lazy mount: this panel is only constructed once the advanced section is
    // expanded, so the log tail read starts here, never while collapsed.
    _previewFuture = (widget.logPreviewLoader ?? _loadLogPreview)();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.recentDaemonLogs,
      trailing: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          OutlinedButton.icon(
            onPressed: _openLogs,
            icon: const Icon(Icons.folder_open_outlined, size: 16),
            label: Text(strings.openLogs),
          ),
          OutlinedButton.icon(
            onPressed: _refresh,
            icon: const Icon(Icons.refresh_rounded, size: 16),
            label: Text(strings.refresh),
          ),
        ],
      ),
      child: FutureBuilder<DiagnosticsLogPreview>(
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
            return _LogMessage(message: strings.cannotReadLogs);
          }
          if (preview.error != null) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _LogMessage(message: strings.cannotReadLogs),
                if (preview.error != null) ...[
                  const SizedBox(height: AppTokens.space4),
                  _LogMessage(
                    message: redactSensitive(preview.error!),
                    muted: true,
                  ),
                ],
              ],
            );
          }
          if (preview.content.isEmpty) {
            return _LogMessage(
              message: strings.isZh
                  ? '尚未找到 daemon 日志文件：${preview.path}'
                  : 'No daemon log file found yet: ${preview.path}',
            );
          }
          final safeContent = redactSensitive(preview.content);
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
                        ? '显示最后 ${preview.shownLineCount} 行（有界尾读，内存与文件大小无关）'
                        : 'Showing last ${preview.shownLineCount} lines (bounded tail; memory independent of file size)',
                    style: TextStyle(
                      fontSize: 12,
                      color: themeTextSecondary(context),
                      fontFeatures: AppTokens.tabularFontFeatures,
                    ),
                  ),
                  OutlinedButton.icon(
                    onPressed: () => _copyLogs(safeContent),
                    icon: const Icon(Icons.copy_all_outlined, size: 15),
                    label: Text(strings.copy),
                  ),
                ],
              ),
              const SizedBox(height: AppTokens.space10),
              Container(
                width: double.infinity,
                constraints: const BoxConstraints(maxHeight: 280),
                padding: const EdgeInsets.all(AppTokens.space12),
                decoration: BoxDecoration(
                  color: AppTokens.colorConsoleBg,
                  borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                  border: Border.all(color: AppTokens.colorConsoleBorder),
                ),
                child: SingleChildScrollView(
                  child: SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Text(
                      safeContent,
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
              const SizedBox(height: AppTokens.space8),
              Text(
                preview.path,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 11,
                  color: themeTextSecondary(context),
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
      _previewFuture = (widget.logPreviewLoader ?? _loadLogPreview)();
    });
  }

  Future<void> _openLogs() async {
    final strings = AppStringsScope.of(context);
    try {
      await (widget.openLogs ?? _openLogsDefault)();
    } catch (_) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            '${strings.cannotOpenLogsTitle}\n${strings.cannotOpenLogsDetail}',
          ),
        ),
      );
      return;
    }
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(strings.logsOpened)));
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
  const _LogMessage({required this.message, this.muted = false});

  final String message;
  final bool muted;

  @override
  Widget build(BuildContext context) {
    return Text(
      message,
      style: TextStyle(
        fontSize: 13,
        height: 1.4,
        color: muted ? themeTextMuted(context) : themeTextSecondary(context),
      ),
    );
  }
}

Color themeTextSecondary(BuildContext context) {
  return P2WlanColors.of(context).textSecondary;
}

Color themeTextMuted(BuildContext context) {
  return P2WlanColors.of(context).textMuted;
}
