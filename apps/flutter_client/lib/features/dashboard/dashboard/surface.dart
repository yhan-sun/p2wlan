part of '../dashboard_page.dart';

class _DashboardSurface extends StatelessWidget {
  const _DashboardSurface({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: theme.colorScheme.outline, width: 1),
        boxShadow: isDark ? const [] : AppTokens.shadowBorder,
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space16),
        child: child,
      ),
    );
  }
}

class _ManualDaemonCommand extends StatelessWidget {
  const _ManualDaemonCommand({required this.command});

  final String command;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: AppTokens.colorConsoleBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: AppTokens.colorConsoleBorder),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    strings.manualLaunchCommand,
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      color: AppTokens.colorConsoleText,
                    ),
                  ),
                ),
                TextButton.icon(
                  onPressed: () => _copy(context, strings),
                  icon: const Icon(Icons.copy_rounded, size: 16),
                  label: Text(strings.copyLaunchCommand),
                ),
              ],
            ),
            const SizedBox(height: AppTokens.space6),
            Text(
              strings.manualLaunchCommandBody,
              style: const TextStyle(
                fontSize: 12,
                color: AppTokens.colorConsoleText,
                height: 1.35,
              ),
            ),
            const SizedBox(height: AppTokens.space10),
            SelectableText(
              command,
              style: const TextStyle(
                fontSize: 12,
                height: 1.35,
                color: AppTokens.colorConsoleText,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _copy(BuildContext context, AppStrings strings) async {
    await Clipboard.setData(ClipboardData(text: command));
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(strings.copiedLaunchCommand)));
  }
}
