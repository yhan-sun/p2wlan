import 'package:flutter/material.dart';

import '../app/app_constants.dart';
import '../app/app_strings.dart';
import '../app/app_tokens.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../features/dashboard/dashboard_page.dart';
import '../features/diagnostics/diagnostics_page.dart';
import '../features/nodes/nodes_page.dart';
import '../features/settings/settings_page.dart';
import '../shared/widgets/status_badge.dart';

enum P2WlanSection {
  dashboard(Icons.dashboard_outlined),
  nodes(Icons.hub_outlined),
  diagnostics(Icons.monitor_heart_outlined),
  settings(Icons.settings_outlined);

  const P2WlanSection(this.icon);

  final IconData icon;
}

class P2WlanShell extends StatefulWidget {
  const P2WlanShell({
    super.key,
    required this.settingsStore,
    required this.statusStore,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  @override
  State<P2WlanShell> createState() => _P2WlanShellState();
}

class _P2WlanShellState extends State<P2WlanShell> {
  var _section = P2WlanSection.dashboard;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);

    return LayoutBuilder(
      builder: (context, constraints) {
        final wide = constraints.maxWidth >= 900;
        final body = _buildBody();

        return Scaffold(
          appBar: AppBar(
            title: const Text(p2wlanAppName),
            centerTitle: false,
            actions: [
              _ShellStatusActions(statusStore: widget.statusStore),
              const SizedBox(width: 8),
            ],
          ),
          body: wide
              ? _WideShell(
                  body: body,
                  selected: _section,
                  strings: strings,
                  onSelect: _select,
                )
              : body,
          bottomNavigationBar: wide
              ? null
              : NavigationBar(
                  selectedIndex: _section.index,
                  onDestinationSelected: (index) =>
                      _select(P2WlanSection.values[index]),
                  destinations: [
                    for (final item in P2WlanSection.values)
                      NavigationDestination(
                        icon: Icon(item.icon),
                        label: strings.sectionLabel(item.name),
                      ),
                  ],
                ),
        );
      },
    );
  }

  Widget _buildBody() {
    return switch (_section) {
      P2WlanSection.dashboard => DashboardPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
      ),
      P2WlanSection.nodes => NodesPage(statusStore: widget.statusStore),
      P2WlanSection.diagnostics => DiagnosticsPage(
        statusStore: widget.statusStore,
      ),
      P2WlanSection.settings => SettingsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
      ),
    };
  }

  void _select(P2WlanSection section) {
    if (_section != section) {
      setState(() => _section = section);
    }
  }
}

class _WideShell extends StatelessWidget {
  const _WideShell({
    required this.body,
    required this.selected,
    required this.strings,
    required this.onSelect,
  });

  final Widget body;
  final P2WlanSection selected;
  final AppStrings strings;
  final ValueChanged<P2WlanSection> onSelect;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        NavigationRail(
          selectedIndex: selected.index,
          onDestinationSelected: (index) =>
              onSelect(P2WlanSection.values[index]),
          labelType: NavigationRailLabelType.all,
          minWidth: 88,
          destinations: [
            for (final item in P2WlanSection.values)
              NavigationRailDestination(
                icon: Icon(item.icon),
                label: Text(strings.sectionLabel(item.name)),
              ),
          ],
        ),
        const VerticalDivider(width: 1),
        Expanded(child: body),
      ],
    );
  }
}

class _ShellStatusActions extends StatelessWidget {
  const _ShellStatusActions({required this.statusStore});

  final StatusStore statusStore;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Center(
                child: StatusBadge(
                  label: statusStore.online ? strings.online : strings.offline,
                  tone: statusStore.online ? StatusTone.good : StatusTone.bad,
                ),
              ),
            ),
            IconButton(
              tooltip: strings.refresh,
              onPressed: statusStore.refreshing ? null : statusStore.refresh,
              icon: statusStore.refreshing
                  ? const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          AppTokens.colorTextMuted,
                        ),
                      ),
                    )
                  : const Icon(Icons.refresh),
            ),
          ],
        );
      },
    );
  }
}
