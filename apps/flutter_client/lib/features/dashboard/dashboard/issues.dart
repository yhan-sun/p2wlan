part of '../dashboard_page.dart';

/// One compact, tinted issue strip with the next useful action.
class _HomeIssueBanner extends StatelessWidget {
  const _HomeIssueBanner({
    super.key,
    required this.message,
    required this.tone,
    this.title,
    this.onOpenTroubleshooting,
    this.onReauthenticate,
    this.actionLabel,
    this.actionKey,
    this.primaryAction = false,
  });

  final String message;
  final StatusTone tone;
  final String? title;
  final VoidCallback? onOpenTroubleshooting;
  final VoidCallback? onReauthenticate;
  final String? actionLabel;
  final Key? actionKey;
  final bool primaryAction;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = _tonePanelColors(context, tone);
    final onAction = onReauthenticate ?? onOpenTroubleshooting;
    final label =
        actionLabel ??
        (onReauthenticate != null
            ? (strings.isZh ? '重新登录' : 'Sign in again')
            : strings.checkIssues);
    final key =
        actionKey ??
        Key(
          onReauthenticate != null
              ? 'home-reauthenticate'
              : 'home-check-issues',
        );
    final Widget? action = onAction == null
        ? null
        : primaryAction
        ? FilledButton(key: key, onPressed: onAction, child: Text(label))
        : TextButton(key: key, onPressed: onAction, child: Text(label));
    final explanation = Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(top: 2),
          child: Icon(
            tone == StatusTone.bad
                ? Icons.error_outline_rounded
                : Icons.warning_amber_rounded,
            color: colors.text,
            size: 20,
          ),
        ),
        const SizedBox(width: AppTokens.space8),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title ?? strings.homeIssueTitle,
                style: TextStyle(
                  color: colors.text,
                  fontSize: 12,
                  height: 1.3,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: AppTokens.space4),
              Text(
                message,
                style: TextStyle(color: colors.text, fontSize: 13, height: 1.4),
              ),
            ],
          ),
        ),
      ],
    );
    return Semantics(
      liveRegion: true,
      child: Container(
        padding: const EdgeInsets.all(AppTokens.space12),
        decoration: BoxDecoration(
          color: colors.bg,
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          border: Border.all(color: colors.border),
        ),
        child: LayoutBuilder(
          builder: (context, constraints) {
            if (action != null &&
                constraints.maxWidth >= 430 &&
                MediaQuery.textScalerOf(context).scale(14) <= 18) {
              return Row(
                children: [
                  Expanded(child: explanation),
                  const SizedBox(width: AppTokens.space12),
                  action,
                ],
              );
            }
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                explanation,
                if (action != null) ...[
                  const SizedBox(height: AppTokens.space8),
                  action,
                ],
              ],
            );
          },
        ),
      ),
    );
  }
}
