import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

part 'dashboard/banner.dart';
part 'dashboard/surface.dart';
part 'dashboard/overview.dart';
part 'dashboard/metrics.dart';
part 'dashboard/nat_profile.dart';
part 'dashboard/actions.dart';

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
              canControlLocalDaemon:
                  PlatformCapabilities.current().canControlLocalDaemon,
              daemonReachable: statusStore.daemonReachable,
              healthReachable: statusStore.healthReachable,
              statusReachable: statusStore.statusReachable,
              refreshing: statusStore.refreshing,
              daemonBusy: statusStore.daemonBusy,
              error: statusStore.lastError,
              healthError: statusStore.lastHealthError,
              statusError: statusStore.lastStatusError,
              daemonManualCommand:
                  settingsStore.settings.authToken.trim().isEmpty
                  ? statusStore.lastDaemonManualCommand
                  : null,
              snapshotStale: statusStore.snapshotStale,
              lastFetchedAt: statusStore.lastSuccessfulStatusAt,
              requestDuration: statusStore.lastRequestDuration,
              onStartDaemon: statusStore.startDaemon,
              onStopDaemon: statusStore.stopDaemon,
              onRefresh: statusStore.refresh,
            ),
          ],
        );
      },
    );
  }
}
