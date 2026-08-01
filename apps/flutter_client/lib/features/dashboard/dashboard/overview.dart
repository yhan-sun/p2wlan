part of '../dashboard_page.dart';

class _ConnectionOverview extends StatelessWidget {
  const _ConnectionOverview({
    required this.snapshot,
    required this.daemonAvailable,
    required this.tone,
    required this.healthReachable,
    required this.statusReachable,
  });

  final DiagnosticsSnapshot? snapshot;
  final bool daemonAvailable;
  final StatusTone tone;
  final bool healthReachable;
  final bool statusReachable;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = _tonePanelColors(context, tone);
    final virtualIp = dash(snapshot?.virtualIp);
    final controlConnected = snapshot?.health.controlConnected == true;
    final controlTone = snapshot == null
        ? StatusTone.neutral
        : controlConnected
        ? StatusTone.good
        : StatusTone.warn;
    final controlLabel = snapshot == null
        ? strings.unavailable
        : controlConnected
        ? strings.connected
        : strings.degraded;
    final title = daemonAvailable
        ? strings.virtualNetworkRunning
        : strings.virtualNetworkStopped;
    final subtitle = snapshot == null
        ? strings.virtualNetworkStoppedDetail
        : '${strings.networkId} ${dash(snapshot!.networkId)} · ${strings.endpointState} ${healthReachable || statusReachable ? strings.reachable : strings.unavailable}';

    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: LayoutBuilder(
          builder: (context, constraints) {
            final statusBadges = Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                StatusBadge(
                  label: daemonAvailable ? strings.connected : strings.offline,
                  tone: tone,
                ),
                if (daemonAvailable)
                  StatusBadge(label: controlLabel, tone: controlTone),
              ],
            );
            final ipBlock = Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 15,
                    fontWeight: FontWeight.w800,
                    height: 1.15,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  subtitle,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 12,
                    height: 1.3,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
                const SizedBox(height: 14),
                Text(
                  strings.virtualIp,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  virtualIp,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: constraints.maxWidth < 420 ? 24 : 28,
                    fontWeight: FontWeight.w800,
                    height: 1.05,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
              ],
            );
            final icon = Container(
              width: 46,
              height: 46,
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                border: Border.all(color: colors.border),
              ),
              child: Icon(
                daemonAvailable
                    ? Icons.hub_outlined
                    : Icons.power_settings_new_rounded,
                color: colors.text,
                size: 24,
              ),
            );

            if (constraints.maxWidth < 560) {
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      icon,
                      const SizedBox(width: 12),
                      Expanded(child: ipBlock),
                    ],
                  ),
                  const SizedBox(height: 12),
                  statusBadges,
                ],
              );
            }

            return Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                icon,
                const SizedBox(width: 14),
                Expanded(child: ipBlock),
                const SizedBox(width: 18),
                ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 260),
                  child: statusBadges,
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}
