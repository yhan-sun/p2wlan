part of '../dashboard_page.dart';

/// User-level issue CTA: visible only when a real problem exists, routes to
/// Troubleshooting, and never shouts.
class _HomeIssueBanner extends StatelessWidget {
  const _HomeIssueBanner({
    required this.message,
    required this.tone,
    this.onOpenTroubleshooting,
  });

  final String message;
  final StatusTone tone;
  final VoidCallback? onOpenTroubleshooting;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = _tonePanelColors(context, tone);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border, width: 1),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Container(
              width: 6,
              height: 6,
              decoration: BoxDecoration(
                color: colors.text,
                shape: BoxShape.circle,
              ),
            ),
            const SizedBox(width: 9),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    strings.homeIssueTitle,
                    style: TextStyle(
                      color: colors.text,
                      fontSize: 12,
                      height: 1.25,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    message,
                    style: TextStyle(
                      color: colors.text,
                      fontSize: 12,
                      height: 1.35,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            ),
            if (onOpenTroubleshooting != null) ...[
              const SizedBox(width: AppTokens.space8),
              TextButton(
                key: const Key('home-check-issues'),
                onPressed: onOpenTroubleshooting,
                style: TextButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(strings.checkIssues),
                    const SizedBox(width: 2),
                    const Icon(Icons.chevron_right_rounded, size: 16),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
