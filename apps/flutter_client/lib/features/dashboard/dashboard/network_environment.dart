part of '../dashboard_page.dart';

class _NetworkEnvironment extends StatelessWidget {
  const _NetworkEnvironment({
    required this.snapshot,
    required this.lastFetchedAt,
    required this.requestDuration,
    required this.snapshotStale,
  });

  final DiagnosticsSnapshot? snapshot;
  final DateTime? lastFetchedAt;
  final Duration? requestDuration;
  final bool snapshotStale;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final c = P2WlanColors.of(context);
    final rows = <Widget>[
      _natRow(context, strings),
      _relayRow(context, strings),
    ];

    final udpBlocked = snapshot?.natProfile?.udpBlocked == true;
    final udpCount = snapshot?.udpSocketCount ?? 0;
    if (udpBlocked) {
      rows.add(
        _EnvRow(
          label: strings.udp,
          value: strings.udpUnavailable,
          dotColor: c.dangerText,
        ),
      );
    } else if (udpCount > 0) {
      rows.add(
        _EnvRow(
          label: strings.udp,
          value: strings.udpAvailable,
          dotColor: c.successText,
        ),
      );
    } else {
      rows.add(_EnvRow(label: strings.udp, value: '—'));
    }

    final refreshValue = snapshotStale
        ? strings.snapshotExpired
        : '${formatDateTime(lastFetchedAt)} · ${formatDuration(requestDuration)}';
    rows.add(_EnvRow(label: strings.lastRefresh, value: refreshValue));

    return AppPanel(
      title: strings.networkEnvironment,
      child: Column(
        children: [
          for (var index = 0; index < rows.length; index++) ...[
            rows[index],
            if (index != rows.length - 1) const Divider(height: 17),
          ],
        ],
      ),
    );
  }

  Widget _natRow(BuildContext context, AppStrings strings) {
    final profile = snapshot?.natProfile;
    final type = profile?.traversalType ?? NatTraversalType.unknown;
    final tone = _natTone(type, profile != null);
    final value = profile == null
        ? strings.natDetectionUnavailable
        : strings.natTraversalTypeLabel(type);
    return _EnvRow(
      label: strings.natNetworkType,
      value: value,
      dotColor: _tonePanelColors(context, tone).text,
    );
  }

  Widget _relayRow(BuildContext context, AppStrings strings) {
    final relay = snapshot?.relaySelection;
    final relayValue = _relayValue(strings, relay);
    final color = snapshot?.relayConnected == true
        ? P2WlanColors.of(context).relay
        : null;
    return _EnvRow(label: strings.relay, value: relayValue, dotColor: color);
  }

  String _relayValue(AppStrings strings, RelaySelectionSnapshot? relay) {
    if (snapshot?.relayConnected != true) return strings.notConnected;
    final region = relay?.selectedRegion?.trim();
    if (region != null && region.isNotEmpty) {
      final latency = relay?.latencyMs;
      return latency == null ? region : '$region · ${formatLatency(latency)}';
    }
    final endpoint = relay?.selectedEndpoint?.trim();
    if (endpoint != null && endpoint.isNotEmpty) return endpoint;
    return strings.connected;
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

class _EnvRow extends StatelessWidget {
  const _EnvRow({required this.label, required this.value, this.dotColor});

  final String label;
  final String value;
  final Color? dotColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
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
        if (dotColor != null) ...[
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: dotColor, shape: BoxShape.circle),
          ),
          const SizedBox(width: 7),
        ],
        Text(
          value,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          textAlign: TextAlign.right,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 13,
            fontWeight: FontWeight.w600,
            height: 1.3,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}
