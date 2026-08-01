part of '../nodes_page.dart';

class _DetailLine extends StatelessWidget {
  const _DetailLine({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final labelText = Text(
            label,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          );
          final valueText = SelectableText(
            value,
            style: TextStyle(
              fontSize: 12,
              color: theme.colorScheme.onSurface,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          );
          if (constraints.maxWidth < 340) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [labelText, const SizedBox(height: 3), valueText],
            );
          }
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: 96, child: labelText),
              Expanded(child: valueText),
            ],
          );
        },
      ),
    );
  }
}

class _PathBadge extends StatelessWidget {
  const _PathBadge({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final tone = _peerNeedsAttention(peer)
        ? StatusTone.bad
        : switch (peer.path) {
            'direct' => StatusTone.good,
            'relay' => StatusTone.warn,
            'direct_trial' || 'probing' => StatusTone.warn,
            _ => StatusTone.neutral,
          };
    return StatusBadge(
      label: _connectionLabel(AppStringsScope.of(context), peer),
      tone: tone,
    );
  }
}
