part of '../dashboard_page.dart';

class _NatProfilePanel extends StatelessWidget {
  const _NatProfilePanel({required this.snapshot});

  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final profile = snapshot?.natProfile;
    final type = profile?.traversalType ?? NatTraversalType.unknown;
    final maxProbabilities =
        profile?.maxTypeProbabilities ?? const <NatTypeProbability>[];
    final maxProbability = maxProbabilities.isEmpty
        ? null
        : _formatProbability(maxProbabilities.first.probability);
    final effectiveToneType = maxProbabilities.length == 1
        ? maxProbabilities.first.type
        : type;
    final tone = _natTone(effectiveToneType, profile != null);
    final colors = _tonePanelColors(context, tone);
    final title = profile == null
        ? strings.natDetectionUnavailable
        : _natCurrentTypeTitle(strings, maxProbabilities, type, maxProbability);

    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                border: Border.all(color: colors.border),
              ),
              child: Icon(
                Icons.network_check_rounded,
                color: colors.text,
                size: 22,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    strings.natNetworkType,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: theme.colorScheme.onSurfaceVariant,
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 5),
                  Text(
                    title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: theme.colorScheme.onSurface,
                      fontSize: 18,
                      fontWeight: FontWeight.w800,
                      height: 1.15,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

StatusTone _natTone(NatTraversalType type, bool hasProfile) {
  if (!hasProfile) return StatusTone.neutral;
  return switch (type) {
    NatTraversalType.fullCone ||
    NatTraversalType.restrictedCone ||
    NatTraversalType.openInternet => StatusTone.good,
    NatTraversalType.portRestrictedCone ||
    NatTraversalType.symmetric ||
    NatTraversalType.unknown => StatusTone.warn,
    NatTraversalType.udpBlocked => StatusTone.bad,
  };
}

String _natCurrentTypeTitle(
  AppStrings strings,
  List<NatTypeProbability> probabilities,
  NatTraversalType fallbackType,
  String? probability,
) {
  if (probability == null || probabilities.isEmpty) {
    return strings.natTraversalTypeLabel(fallbackType);
  }
  final labels = probabilities
      .map((item) => strings.natTraversalShortLabel(item.type))
      .join(' / ');
  return strings.isZh ? '$labels（$probability）' : '$labels ($probability)';
}

String _formatProbability(double value) {
  final bounded = value.clamp(0, 100).toDouble();
  final rounded = bounded.round();
  if ((bounded - rounded).abs() < 0.05) return '$rounded%';
  return '${bounded.toStringAsFixed(1)}%';
}
