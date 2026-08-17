import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/security/redactor.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/log_tail.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

part 'diagnostics/actions.dart';
part 'diagnostics/platform_panel.dart';
part 'diagnostics/status_panels.dart';
part 'diagnostics/health_panels.dart';
part 'diagnostics/raw_json.dart';
part 'diagnostics/recent_logs.dart';
part 'diagnostics/helpers.dart';

class DiagnosticsPage extends StatelessWidget {
  const DiagnosticsPage({
    super.key,
    required this.statusStore,
    this.showHeader = true,
  });

  final StatusStore statusStore;
  final bool showHeader;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        return PageScaffold(
          title: strings.diagnostics,
          subtitle: strings.diagnosticsSubtitle,
          showHeader: showHeader,
          children: [
            _DiagnosticsActions(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 14),
            _Summary(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 14),
            _IssuesPanel(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 14),
            _PlatformPanel(),
            const SizedBox(height: 14),
            _BoundaryPanel(snapshot: snapshot),
            const SizedBox(height: 14),
            _TaskPanel(snapshot: snapshot),
            const SizedBox(height: 14),
            _RecentLogsPanel(),
            const SizedBox(height: 14),
            _RawJson(statusStore: statusStore, snapshot: snapshot),
          ],
        );
      },
    );
  }
}
