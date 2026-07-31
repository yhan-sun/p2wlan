import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

class DashboardPage extends StatelessWidget {
  const DashboardPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: Listenable.merge([settingsStore, statusStore]),
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        return PageScaffold(
          title: strings.dashboard,
          subtitle: strings.dashboardSubtitle,
          showHeader: showHeader,
          children: [
            _ConnectionBanner(
              snapshot: snapshot,
              daemonReachable: statusStore.daemonReachable,
              healthReachable: statusStore.healthReachable,
              statusReachable: statusStore.statusReachable,
              refreshing: statusStore.refreshing,
              daemonBusy: statusStore.daemonBusy,
              autoRefreshEnabled: statusStore.autoRefreshEnabled,
              error: statusStore.lastError,
              healthError: statusStore.lastHealthError,
              statusError: statusStore.lastStatusError,
              daemonManualCommand: statusStore.lastDaemonManualCommand,
              lastFetchedAt: statusStore.lastFetchedAt,
              requestDuration: statusStore.lastRequestDuration,
              onStartDaemon: statusStore.startDaemon,
              onStopDaemon: statusStore.stopDaemon,
              onRefresh: statusStore.refresh,
              onAutoRefreshChanged: (value) => statusStore.setAutoRefresh(
                enabled: value,
                refreshImmediately: value,
              ),
            ),
          ],
        );
      },
    );
  }
}

class _ConnectionBanner extends StatelessWidget {
  const _ConnectionBanner({
    required this.snapshot,
    required this.daemonReachable,
    required this.healthReachable,
    required this.statusReachable,
    required this.refreshing,
    required this.daemonBusy,
    required this.autoRefreshEnabled,
    required this.error,
    required this.healthError,
    required this.statusError,
    required this.daemonManualCommand,
    required this.lastFetchedAt,
    required this.requestDuration,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
    required this.onAutoRefreshChanged,
  });

  final DiagnosticsSnapshot? snapshot;
  final bool daemonReachable;
  final bool healthReachable;
  final bool statusReachable;
  final bool refreshing;
  final bool daemonBusy;
  final bool autoRefreshEnabled;
  final String? error;
  final String? healthError;
  final String? statusError;
  final String? daemonManualCommand;
  final DateTime? lastFetchedAt;
  final Duration? requestDuration;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final Future<void> Function() onRefresh;
  final ValueChanged<bool> onAutoRefreshChanged;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final daemonAvailable = _daemonAvailable;
    final tone = _overallTone();
    final issueMessage =
        _statusMessage(strings, daemonAvailable) ?? _attentionMessage(strings);
    final showIssueNote = issueMessage != null && daemonAvailable;
    return _DashboardSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _DashboardSurfaceHeader(),
          const SizedBox(height: 16),
          _ConnectionOverview(
            snapshot: snapshot,
            daemonAvailable: daemonAvailable,
            tone: tone,
            healthReachable: healthReachable,
            statusReachable: statusReachable,
          ),
          const SizedBox(height: 16),
          _DashboardActions(
            daemonAvailable: daemonAvailable,
            daemonBusy: daemonBusy,
            refreshing: refreshing,
            autoRefreshEnabled: autoRefreshEnabled,
            onStartDaemon: () => _handleStart(context),
            onStopDaemon: onStopDaemon,
            onRefresh: onRefresh,
            onAutoRefreshChanged: onAutoRefreshChanged,
          ),
          if (daemonAvailable) ...[
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 14),
            _DashboardMetrics(
              snapshot: snapshot,
              lastFetchedAt: lastFetchedAt,
              requestDuration: requestDuration,
            ),
          ],
          if (showIssueNote) ...[
            const SizedBox(height: 12),
            _StatusNote(
              label: strings.reviewRecommended,
              message: issueMessage,
              tone: StatusTone.warn,
            ),
          ],
          if (daemonManualCommand != null) ...[
            const SizedBox(height: 14),
            _ManualDaemonCommand(command: daemonManualCommand!),
          ],
        ],
      ),
    );
  }

  bool get _daemonAvailable => daemonReachable || statusReachable;

  String? _statusMessage(AppStrings strings, bool daemonAvailable) {
    if (!daemonAvailable) return strings.offlineSnapshotMessage;
    if (!statusReachable && statusError != null) {
      return strings.statusMessage(statusError) ?? statusError;
    }
    if (!healthReachable && healthError != null) {
      return strings.statusMessage(healthError) ?? healthError;
    }
    if (_overallTone() != StatusTone.good && error != null) {
      return strings.statusMessage(error) ?? error;
    }
    return null;
  }

  String? _attentionMessage(AppStrings strings) {
    final health = snapshot?.health;
    if (health?.reauthRequired == true) return strings.issueReauthRequired;
    if (health != null && !health.controlConnected) {
      return strings.issueControlDisconnected;
    }
    final reason = health?.reason?.trim();
    if (reason != null && reason.isNotEmpty) return reason;
    if (snapshot != null && !snapshot!.relayConnected) {
      return strings.issueRelayDisconnected;
    }
    final warningCount =
        snapshot?.peers.where((peer) => peer.lastError != null).length ?? 0;
    if (warningCount > 0) return strings.peerWarnings(warningCount);
    return null;
  }

  Future<void> _handleStart(BuildContext context) async {
    if (defaultTargetPlatform == TargetPlatform.macOS) {
      final strings = AppStringsScope.of(context);
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (dialogContext) {
          return AlertDialog(
            title: Text(strings.macosAuthorizationTitle),
            content: Text(strings.macosAuthorizationBody),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(false),
                child: Text(strings.cancel),
              ),
              FilledButton(
                onPressed: () => Navigator.of(dialogContext).pop(true),
                child: Text(strings.continueAction),
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;
    }
    await onStartDaemon();
  }

  StatusTone _overallTone() {
    if (!_daemonAvailable) return StatusTone.neutral;
    if (!healthReachable) return StatusTone.bad;
    if (!statusReachable) return StatusTone.warn;
    return switch (snapshot?.health.status.toLowerCase()) {
      'healthy' => StatusTone.good,
      'degraded' => StatusTone.warn,
      _ => StatusTone.bad,
    };
  }
}

class _DashboardSurface extends StatelessWidget {
  const _DashboardSurface({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: theme.colorScheme.outline, width: 1),
        boxShadow: isDark ? const [] : AppTokens.shadowBorder,
      ),
      child: Padding(padding: const EdgeInsets.all(16), child: child),
    );
  }
}

class _DashboardSurfaceHeader extends StatelessWidget {
  const _DashboardSurfaceHeader();

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Row(
      children: [
        Expanded(
          child: Text(
            strings.virtualNetwork,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 15,
              fontWeight: FontWeight.w800,
              letterSpacing: 0,
            ),
          ),
        ),
      ],
    );
  }
}

class _ManualDaemonCommand extends StatelessWidget {
  const _ManualDaemonCommand({required this.command});

  final String command;

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
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    strings.manualLaunchCommand,
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      color: AppTokens.colorConsoleText,
                    ),
                  ),
                ),
                TextButton.icon(
                  onPressed: () => _copy(context, strings),
                  icon: const Icon(Icons.copy_rounded, size: 16),
                  label: Text(strings.copyLaunchCommand),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              strings.manualLaunchCommandBody,
              style: const TextStyle(
                fontSize: 12,
                color: AppTokens.colorConsoleText,
                height: 1.35,
              ),
            ),
            const SizedBox(height: 10),
            SelectableText(
              command,
              style: const TextStyle(
                fontSize: 12,
                height: 1.35,
                color: AppTokens.colorConsoleText,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _copy(BuildContext context, AppStrings strings) async {
    await Clipboard.setData(ClipboardData(text: command));
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(strings.copiedLaunchCommand)));
  }
}

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

class _DashboardMetrics extends StatelessWidget {
  const _DashboardMetrics({
    required this.snapshot,
    required this.lastFetchedAt,
    required this.requestDuration,
  });

  final DiagnosticsSnapshot? snapshot;
  final DateTime? lastFetchedAt;
  final Duration? requestDuration;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final stats = snapshot?.stats;
    final relay = snapshot?.relaySelection;
    final totalPeers = snapshot?.peers.length ?? stats?.totalPeers;
    final onlinePeers = snapshot?.peers.where((peer) => peer.online).length;
    final offlinePeers = snapshot?.peers.where((peer) => !peer.online).length;
    final probingPeers = snapshot?.peers
        .where((peer) => peer.path == 'probing' || peer.path == 'direct_trial')
        .length;
    final items = [
      _MetricItem(
        label: strings.onlineDevices,
        value: onlinePeers == null
            ? '—'
            : '${formatInt(onlinePeers)}/${formatInt(totalPeers ?? 0)}',
        detail: offlinePeers == null
            ? null
            : '${strings.offlineDevices}: ${formatInt(offlinePeers)}',
      ),
      _MetricItem(
        label: strings.pathOverview,
        value: stats == null
            ? '—'
            : '${formatInt(stats.directConnections)} / ${formatInt(stats.relayConnections)}',
        detail: stats == null
            ? null
            : '${strings.directPaths} · ${strings.relayPaths}${probingPeers == null || probingPeers == 0 ? '' : ' · ${strings.probing}: ${formatInt(probingPeers)}'}',
      ),
      _MetricItem(
        label: strings.relay,
        value: snapshot == null
            ? '—'
            : snapshot!.relayConnected
            ? strings.connected
            : strings.notConnected,
        detail: dash(relay?.selectedRegion ?? relay?.selectedEndpoint),
      ),
      _MetricItem(
        label: strings.lastRefresh,
        value: formatDateTime(lastFetchedAt),
        detail: formatDuration(requestDuration),
      ),
    ];

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            children: [
              for (var index = 0; index < items.length; index++) ...[
                _CompactMetricRow(item: items[index]),
                if (index != items.length - 1) const _MetricDivider(),
              ],
            ],
          );
        }

        final columns = constraints.maxWidth < 760 ? 2 : 4;
        final spacing = columns == 2 ? 18.0 : 24.0;
        final width =
            (constraints.maxWidth - (spacing * (columns - 1))) / columns;
        return Wrap(
          spacing: spacing,
          runSpacing: 16,
          children: [
            for (final item in items) _MetricBlock(width: width, item: item),
          ],
        );
      },
    );
  }
}

class _MetricItem {
  const _MetricItem({required this.label, required this.value, this.detail});

  final String label;
  final String value;
  final String? detail;
}

class _MetricBlock extends StatelessWidget {
  const _MetricBlock({required this.width, required this.item});

  final double width;
  final _MetricItem item;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SizedBox(
      width: width,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _MetricLabel(item.label),
          const SizedBox(height: 6),
          Text(
            item.value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: theme.colorScheme.onSurface,
              fontSize: 16,
              fontWeight: FontWeight.w700,
              height: 1.15,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
          if (item.detail != null) ...[
            const SizedBox(height: 4),
            _MetricDetail(item.detail!),
          ],
        ],
      ),
    );
  }
}

class _CompactMetricRow extends StatelessWidget {
  const _CompactMetricRow({required this.item});

  final _MetricItem item;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 9),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: _MetricLabel(item.label)),
          const SizedBox(width: 16),
          Flexible(
            flex: 2,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  item.value,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.right,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                    height: 1.2,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
                if (item.detail != null) ...[
                  const SizedBox(height: 3),
                  _MetricDetail(item.detail!, textAlign: TextAlign.right),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _MetricLabel extends StatelessWidget {
  const _MetricLabel(this.value);

  final String value;

  @override
  Widget build(BuildContext context) {
    return Text(
      value,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        color: Theme.of(context).colorScheme.onSurfaceVariant,
        fontSize: 12,
        fontWeight: FontWeight.w600,
        height: 1.2,
      ),
    );
  }
}

class _MetricDetail extends StatelessWidget {
  const _MetricDetail(this.value, {this.textAlign = TextAlign.left});

  final String value;
  final TextAlign textAlign;

  @override
  Widget build(BuildContext context) {
    return Text(
      value,
      maxLines: 2,
      overflow: TextOverflow.ellipsis,
      textAlign: textAlign,
      style: TextStyle(
        color: Theme.of(context).colorScheme.onSurfaceVariant,
        fontSize: 12,
        fontWeight: FontWeight.w400,
        height: 1.25,
        fontFeatures: AppTokens.tabularFontFeatures,
      ),
    );
  }
}

class _MetricDivider extends StatelessWidget {
  const _MetricDivider();

  @override
  Widget build(BuildContext context) {
    return Divider(color: Theme.of(context).colorScheme.outlineVariant);
  }
}

class _StatusNote extends StatelessWidget {
  const _StatusNote({
    required this.label,
    required this.message,
    required this.tone,
  });

  final String label;
  final String message;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
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
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.only(top: 7),
              child: Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(
                  color: colors.text,
                  shape: BoxShape.circle,
                ),
              ),
            ),
            const SizedBox(width: 9),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: TextStyle(
                      color: colors.text,
                      fontSize: 12,
                      height: 1.25,
                      fontWeight: FontWeight.w800,
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
          ],
        ),
      ),
    );
  }
}

({Color bg, Color border, Color text}) _tonePanelColors(
  BuildContext context,
  StatusTone tone,
) {
  final theme = Theme.of(context);
  final isDark = theme.brightness == Brightness.dark;
  if (isDark) {
    return switch (tone) {
      StatusTone.good => (
        bg: AppTokens.colorDarkGoodBg,
        border: AppTokens.colorDarkGoodBorder,
        text: AppTokens.colorDarkGoodText,
      ),
      StatusTone.warn => (
        bg: AppTokens.colorDarkWarnBg,
        border: AppTokens.colorDarkWarnBorder,
        text: AppTokens.colorDarkWarnText,
      ),
      StatusTone.bad => (
        bg: AppTokens.colorDarkBadBg,
        border: AppTokens.colorDarkBadBorder,
        text: AppTokens.colorDarkBadText,
      ),
      StatusTone.neutral => (
        bg: AppTokens.colorDarkNeutralBg,
        border: AppTokens.colorDarkNeutralBorder,
        text: AppTokens.colorDarkNeutralText,
      ),
    };
  }

  return switch (tone) {
    StatusTone.good => (
      bg: AppTokens.colorGoodBg,
      border: AppTokens.colorGoodBorder,
      text: AppTokens.colorGoodText,
    ),
    StatusTone.warn => (
      bg: AppTokens.colorWarnBg,
      border: AppTokens.colorWarnBorder,
      text: AppTokens.colorWarnText,
    ),
    StatusTone.bad => (
      bg: AppTokens.colorBadBg,
      border: AppTokens.colorBadBorder,
      text: AppTokens.colorBadText,
    ),
    StatusTone.neutral => (
      bg: theme.colorScheme.surfaceContainerHighest,
      border: theme.colorScheme.outline,
      text: theme.colorScheme.onSurfaceVariant,
    ),
  };
}

class _DashboardActions extends StatelessWidget {
  const _DashboardActions({
    required this.daemonAvailable,
    required this.daemonBusy,
    required this.refreshing,
    required this.autoRefreshEnabled,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
    required this.onAutoRefreshChanged,
  });

  final bool daemonAvailable;
  final bool daemonBusy;
  final bool refreshing;
  final bool autoRefreshEnabled;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final Future<void> Function() onRefresh;
  final ValueChanged<bool> onAutoRefreshChanged;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final busy = daemonBusy || refreshing;
    final primaryAction = _PrimaryDaemonButton(
      daemonAvailable: daemonAvailable,
      daemonBusy: daemonBusy,
      onStartDaemon: onStartDaemon,
      onStopDaemon: onStopDaemon,
    );
    final refreshAction = OutlinedButton.icon(
      key: const Key('dashboard-refresh-button'),
      onPressed: busy ? null : onRefresh,
      icon: refreshing
          ? const SizedBox.square(
              dimension: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.refresh_rounded, size: 17),
      label: Text(refreshing ? strings.refreshing : strings.refreshNow),
    );
    final autoRefreshAction = _AutoRefreshButton(
      autoRefreshEnabled: autoRefreshEnabled,
      daemonBusy: daemonBusy,
      onAutoRefreshChanged: onAutoRefreshChanged,
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              primaryAction,
              const SizedBox(height: 8),
              refreshAction,
              const SizedBox(height: 8),
              autoRefreshAction,
            ],
          );
        }

        return Wrap(
          spacing: 10,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [primaryAction, refreshAction, autoRefreshAction],
        );
      },
    );
  }
}

class _PrimaryDaemonButton extends StatelessWidget {
  const _PrimaryDaemonButton({
    required this.daemonAvailable,
    required this.daemonBusy,
    required this.onStartDaemon,
    required this.onStopDaemon,
  });

  final bool daemonAvailable;
  final bool daemonBusy;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    if (daemonAvailable) {
      return FilledButton.icon(
        key: const Key('dashboard-stop-button'),
        onPressed: daemonBusy ? null : onStopDaemon,
        icon: daemonBusy
            ? const _ButtonSpinner()
            : const Icon(Icons.stop_rounded, size: 17),
        label: Text(daemonBusy ? strings.daemonWorking : strings.stopP2wlan),
      );
    }

    return FilledButton.icon(
      key: const Key('dashboard-start-button'),
      onPressed: daemonBusy ? null : onStartDaemon,
      icon: daemonBusy
          ? const _ButtonSpinner()
          : const Icon(Icons.play_arrow_rounded, size: 18),
      label: Text(daemonBusy ? strings.daemonWorking : strings.startP2wlan),
    );
  }
}

class _AutoRefreshButton extends StatelessWidget {
  const _AutoRefreshButton({
    required this.autoRefreshEnabled,
    required this.daemonBusy,
    required this.onAutoRefreshChanged,
  });

  final bool autoRefreshEnabled;
  final bool daemonBusy;
  final ValueChanged<bool> onAutoRefreshChanged;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final label = strings.autoRefresh(
      StatusStore.defaultAutoRefreshInterval.inSeconds,
    );

    return Tooltip(
      message: strings.autoRefreshTooltip,
      child: OutlinedButton.icon(
        key: const Key('auto-refresh-toggle'),
        onPressed: daemonBusy
            ? null
            : () => onAutoRefreshChanged(!autoRefreshEnabled),
        icon: AnimatedSwitcher(
          duration: AppTokens.durationMedium,
          switchInCurve: AppTokens.curveEase,
          switchOutCurve: Curves.easeIn,
          transitionBuilder: (child, animation) {
            return FadeTransition(
              opacity: animation,
              child: ScaleTransition(scale: animation, child: child),
            );
          },
          child: Icon(
            autoRefreshEnabled ? Icons.timer_rounded : Icons.timer_off_outlined,
            key: ValueKey(autoRefreshEnabled),
            size: 17,
          ),
        ),
        label: Text(label),
        style: OutlinedButton.styleFrom(
          foregroundColor: autoRefreshEnabled
              ? colorScheme.primary
              : colorScheme.onSurfaceVariant,
          backgroundColor: autoRefreshEnabled
              ? colorScheme.surfaceContainerHighest
              : Colors.transparent,
          side: BorderSide(
            color: autoRefreshEnabled
                ? colorScheme.primary.withValues(alpha: 0.34)
                : colorScheme.outline,
          ),
        ),
      ),
    );
  }
}

class _ButtonSpinner extends StatelessWidget {
  const _ButtonSpinner();

  @override
  Widget build(BuildContext context) {
    return SizedBox.square(
      dimension: 14,
      child: CircularProgressIndicator(
        strokeWidth: 2,
        valueColor: AlwaysStoppedAnimation<Color>(
          Theme.of(context).colorScheme.onPrimary,
        ),
      ),
    );
  }
}
