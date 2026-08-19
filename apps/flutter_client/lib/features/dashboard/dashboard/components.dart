part of '../dashboard_page.dart';

/// Plain-language network component status. Only rows that can be judged
/// reliably from real snapshot data are shown — no fabricated states.
class _NetworkComponentsSection extends StatelessWidget {
  const _NetworkComponentsSection({
    required this.snapshot,
    required this.counts,
  });

  final DiagnosticsSnapshot snapshot;
  final _PeerCounts counts;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);

    final rows = <Widget>[
      _ComponentRow(
        label: strings.componentControlServer,
        value: snapshot.health.controlConnected
            ? strings.componentStatusNormal
            : strings.componentStatusDisconnected,
        tone: snapshot.health.controlConnected
            ? StatusTone.good
            : StatusTone.warn,
      ),
      // Overlay route: only when the daemon reports an authoritative phase.
      if (_overlayTone(snapshot) case final tone?)
        _ComponentRow(
          label: strings.componentOverlayRoute,
          value: _overlayLabel(strings, tone),
          tone: tone,
        ),
      _ComponentRow(
        label: strings.componentPeerConnectivity,
        value: '${counts.online} / ${counts.total}',
        tone: counts.total == 0
            ? StatusTone.neutral
            : counts.online == counts.total
            ? StatusTone.good
            : StatusTone.warn,
      ),
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          strings.networkComponents,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 15,
            fontWeight: FontWeight.w700,
            letterSpacing: 0,
          ),
        ),
        const SizedBox(height: AppTokens.space12),
        for (var index = 0; index < rows.length; index++) ...[
          if (index > 0) const Divider(height: 17),
          rows[index],
        ],
      ],
    );
  }
}

/// null = not judgeable from the current data (row is omitted).
StatusTone? _overlayTone(DiagnosticsSnapshot snapshot) {
  final phase = snapshot.readyPhase.toLowerCase();
  if (phase.isEmpty || phase == 'unknown') return null;
  if (phase.startsWith('connected')) return StatusTone.good;
  if (phase.contains('discover') ||
      phase.contains('connect') ||
      phase.contains('negotiat') ||
      phase.contains('pending')) {
    return StatusTone.warn;
  }
  if (phase.contains('error') || phase.contains('fail')) return StatusTone.bad;
  return null;
}

String _overlayLabel(AppStrings strings, StatusTone tone) => switch (tone) {
  StatusTone.good => strings.componentStatusNormal,
  StatusTone.warn => strings.componentStatusConnecting,
  StatusTone.bad => strings.componentStatusError,
  StatusTone.neutral => strings.componentStatusUnknown,
};

class _ComponentRow extends StatelessWidget {
  const _ComponentRow({
    required this.label,
    required this.value,
    required this.tone,
  });

  final String label;
  final String value;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final text = _tonePanelColors(context, tone).text;
    return Row(
      children: [
        Expanded(
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurfaceVariant,
              fontSize: 13,
              fontWeight: FontWeight.w600,
              height: 1.3,
            ),
          ),
        ),
        const SizedBox(width: AppTokens.space12),
        Container(
          width: 7,
          height: 7,
          decoration: BoxDecoration(color: text, shape: BoxShape.circle),
        ),
        const SizedBox(width: 7),
        Flexible(
          child: Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: text,
              fontSize: 13,
              fontWeight: FontWeight.w600,
              height: 1.3,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
      ],
    );
  }
}
