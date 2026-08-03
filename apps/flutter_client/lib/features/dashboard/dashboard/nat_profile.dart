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
    final probabilities =
        profile?.typeProbabilities ?? const <NatTypeProbability>[];
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
        : maxProbability == null
        ? strings.natTraversalTypeLabel(type)
        : strings.natMostLikelyTitle(
            maxProbabilities.map((item) => item.type).toList(),
            maxProbability,
          );
    final detail = profile == null
        ? strings.natDetectionUnavailableDetail
        : strings.natTraversalTypeDescription(type);
    final adviceType = maxProbabilities.length == 1
        ? maxProbabilities.first.type
        : type;

    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
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
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              strings.natNetworkType,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: theme.colorScheme.onSurfaceVariant,
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                          if (profile != null) ...[
                            const SizedBox(width: 8),
                            StatusBadge(
                              label: strings.natAutoDetected,
                              tone: tone,
                            ),
                          ],
                        ],
                      ),
                      const SizedBox(height: 5),
                      Text(
                        title,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: theme.colorScheme.onSurface,
                          fontSize: 17,
                          fontWeight: FontWeight.w800,
                          height: 1.15,
                        ),
                      ),
                    ],
                  ),
                ),
                Tooltip(
                  message: strings.natGuideAction,
                  child: IconButton(
                    onPressed: () => _showNatGuide(context),
                    icon: const Icon(Icons.info_outline_rounded, size: 20),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(
              detail,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 12,
                height: 1.4,
                fontWeight: FontWeight.w500,
              ),
            ),
            if (profile != null) ...[
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  _NatMetaChip(
                    label: strings.natPublicEndpoint,
                    value: dash(profile.publicEndpoint),
                  ),
                  _NatMetaChip(
                    label: strings.natMappingBehavior,
                    value: strings.natBehaviorLabel(profile.mappingBehavior),
                  ),
                  _NatMetaChip(
                    label: strings.natFilteringBehavior,
                    value: strings.natBehaviorLabel(profile.filteringBehavior),
                  ),
                  if (profile.confidence != null)
                    _NatMetaChip(
                      label: strings.natConfidence,
                      value: '${profile.confidence}%',
                    ),
                  if (probabilities.isNotEmpty)
                    _NatMetaChip(
                      label: strings.natProbabilityTotal,
                      value: _formatProbabilityTotal(profile.probabilityTotal),
                    ),
                  if (maxProbability != null)
                    _NatMetaChip(
                      label: strings.natMaxProbability,
                      value: _maxProbabilityChipValue(
                        strings,
                        maxProbabilities,
                        maxProbability,
                      ),
                    ),
                ],
              ),
              if (probabilities.isNotEmpty) ...[
                const SizedBox(height: 12),
                _NatProbabilityList(probabilities: probabilities),
              ],
              const SizedBox(height: 12),
              Text(
                strings.natTraversalTypeAdvice(adviceType),
                style: TextStyle(
                  color: colors.text,
                  fontSize: 12,
                  height: 1.35,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  void _showNatGuide(BuildContext context) {
    final strings = AppStringsScope.of(context);
    showDialog<void>(
      context: context,
      builder: (context) => _NatGuideDialog(strings: strings),
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

String _formatProbability(double value) {
  final bounded = value.clamp(0, 100).toDouble();
  final rounded = bounded.round();
  if ((bounded - rounded).abs() < 0.05) return '$rounded%';
  return '${bounded.toStringAsFixed(1)}%';
}

String _formatProbabilityTotal(double value) {
  if ((value - 100).abs() < 0.5) return '100%';
  return _formatProbability(value);
}

String _maxProbabilityChipValue(
  AppStrings strings,
  List<NatTypeProbability> probabilities,
  String probability,
) {
  if (probabilities.length == 1) {
    return '${strings.natTraversalShortLabel(probabilities.first.type)} $probability';
  }
  return strings.isZh
      ? '${probabilities.length} 类并列 $probability'
      : '${probabilities.length} tied $probability';
}

class _NatProbabilityList extends StatelessWidget {
  const _NatProbabilityList({required this.probabilities});

  final List<NatTypeProbability> probabilities;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          strings.natTypeProbabilities,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 12,
            fontWeight: FontWeight.w800,
          ),
        ),
        const SizedBox(height: 8),
        for (final item in probabilities) ...[
          _NatProbabilityRow(probability: item),
          if (item != probabilities.last) const SizedBox(height: 8),
        ],
      ],
    );
  }
}

class _NatProbabilityRow extends StatelessWidget {
  const _NatProbabilityRow({required this.probability});

  final NatTypeProbability probability;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = _tonePanelColors(context, _natTone(probability.type, true));
    final value = (probability.probability / 100).clamp(0, 1).toDouble();
    final percent = _formatProbability(probability.probability);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                strings.natTraversalShortLabel(probability.type),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Text(
              percent,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 12,
                fontWeight: FontWeight.w800,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ],
        ),
        const SizedBox(height: 5),
        ClipRRect(
          borderRadius: BorderRadius.circular(999),
          child: LinearProgressIndicator(
            minHeight: 6,
            value: value,
            backgroundColor: theme.colorScheme.surfaceContainerHighest,
            valueColor: AlwaysStoppedAnimation<Color>(colors.text),
          ),
        ),
      ],
    );
  }
}

class _NatMetaChip extends StatelessWidget {
  const _NatMetaChip({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
        child: RichText(
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          text: TextSpan(
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 12,
              height: 1.2,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
            children: [
              TextSpan(
                text: '$label ',
                style: TextStyle(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w600,
                ),
              ),
              TextSpan(
                text: value,
                style: const TextStyle(fontWeight: FontWeight.w800),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _NatGuideDialog extends StatelessWidget {
  const _NatGuideDialog({required this.strings});

  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(strings.natGuideTitle),
      content: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(strings.natGuideIntro),
              const SizedBox(height: 14),
              for (final type in const [
                NatTraversalType.fullCone,
                NatTraversalType.restrictedCone,
                NatTraversalType.portRestrictedCone,
                NatTraversalType.symmetric,
              ]) ...[
                _NatGuideRow(type: type, strings: strings),
                if (type != NatTraversalType.symmetric)
                  const SizedBox(height: 12),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(strings.close),
        ),
      ],
    );
  }
}

class _NatGuideRow extends StatelessWidget {
  const _NatGuideRow({required this.type, required this.strings});

  final NatTraversalType type;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          strings.natTraversalTypeLabel(type),
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 13,
            fontWeight: FontWeight.w800,
          ),
        ),
        const SizedBox(height: 3),
        Text(
          strings.natTraversalTypeDescription(type),
          style: TextStyle(
            color: theme.colorScheme.onSurfaceVariant,
            fontSize: 12,
            height: 1.35,
          ),
        ),
      ],
    );
  }
}
