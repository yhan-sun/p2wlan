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
    final tone = _natTone(type, profile != null);
    final colors = _tonePanelColors(context, tone);
    final title = profile == null
        ? strings.natDetectionUnavailable
        : strings.natTraversalTypeLabel(type);
    final detail = profile == null
        ? strings.natDetectionUnavailableDetail
        : strings.natTraversalTypeDescription(type);

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
                ],
              ),
              const SizedBox(height: 12),
              Text(
                strings.natTraversalTypeAdvice(type),
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

  void _showNatGuide(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (context) => const _NatGuideDialog(),
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
  const _NatGuideDialog();

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
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
                _NatGuideRow(type: type),
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
  const _NatGuideRow({required this.type});

  final NatTraversalType type;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
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
