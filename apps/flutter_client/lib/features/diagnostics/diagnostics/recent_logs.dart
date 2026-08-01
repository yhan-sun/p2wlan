part of '../diagnostics_page.dart';

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
