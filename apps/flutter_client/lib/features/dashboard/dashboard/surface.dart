part of '../dashboard_page.dart';

/// Supporting Home sections use the same restrained surface treatment as the
/// rest of the product. On wide layouts they form the dashboard's two-column
/// information grid; on narrow layouts they stack with unchanged reading
/// order.
class _DashboardSectionSurface extends StatelessWidget {
  const _DashboardSectionSurface({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Container(
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border),
        boxShadow: theme.brightness == Brightness.dark
            ? const []
            : AppTokens.shadowBorder,
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space16),
        child: child,
      ),
    );
  }
}

/// Manual daemon recovery command behind progressive disclosure: only a quiet
/// "manual start needed" header by default; the terminal block appears on
/// demand, never on a healthy page.
class _ManualCommandCard extends StatefulWidget {
  const _ManualCommandCard({required this.command});

  final String command;

  @override
  State<_ManualCommandCard> createState() => _ManualCommandCardState();
}

class _ManualCommandCardState extends State<_ManualCommandCard> {
  var _expanded = false;

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
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    strings.manualStartNeeded,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      color: AppTokens.colorConsoleText,
                    ),
                  ),
                ),
                TextButton(
                  key: const Key('home-manual-command-toggle'),
                  onPressed: () => setState(() => _expanded = !_expanded),
                  style: TextButton.styleFrom(
                    visualDensity: VisualDensity.compact,
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        _expanded ? strings.hideCommand : strings.viewCommand,
                      ),
                      Icon(
                        _expanded
                            ? Icons.keyboard_arrow_up_rounded
                            : Icons.keyboard_arrow_down_rounded,
                        size: 16,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            AnimatedSize(
              duration: AppTokens.durationMedium,
              curve: AppTokens.curveEase,
              alignment: Alignment.topCenter,
              child: _expanded
                  ? Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
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
                            widget.command,
                            style: const TextStyle(
                              fontSize: 12,
                              height: 1.35,
                              color: AppTokens.colorConsoleText,
                              fontFeatures: AppTokens.tabularFontFeatures,
                            ),
                          ),
                          const SizedBox(height: AppTokens.space8),
                          Align(
                            alignment: Alignment.centerRight,
                            child: TextButton.icon(
                              key: const Key('home-manual-command-copy'),
                              onPressed: () => _copy(context, strings),
                              icon: const Icon(Icons.copy_rounded, size: 16),
                              label: Text(strings.copyLaunchCommand),
                            ),
                          ),
                        ],
                      ),
                    )
                  : const SizedBox(width: double.infinity),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _copy(BuildContext context, AppStrings strings) async {
    await Clipboard.setData(ClipboardData(text: widget.command));
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(strings.copiedLaunchCommand)));
  }
}
