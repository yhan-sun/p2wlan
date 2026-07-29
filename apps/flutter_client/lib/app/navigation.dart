import 'package:flutter/material.dart';

import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../features/dashboard/dashboard_page.dart';
import '../features/diagnostics/diagnostics_page.dart';
import '../features/nodes/nodes_page.dart';
import '../features/settings/settings_page.dart';
import '../shared/widgets/status_badge.dart';
import 'app_constants.dart';

enum P2WlanSection {
  dashboard('Dashboard', Icons.dashboard_outlined),
  nodes('Nodes', Icons.hub_outlined),
  diagnostics('Diagnostics', Icons.monitor_heart_outlined),
  settings('Settings', Icons.settings_outlined);

  const P2WlanSection(this.label, this.icon);

  final String label;
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
    final pages = {
      P2WlanSection.dashboard: DashboardPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
      ),
      P2WlanSection.nodes: NodesPage(statusStore: widget.statusStore),
      P2WlanSection.diagnostics: DiagnosticsPage(
        statusStore: widget.statusStore,
      ),
      P2WlanSection.settings: SettingsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
      ),
    };

    return AnimatedBuilder(
      animation: widget.statusStore,
      builder: (context, _) {
        return LayoutBuilder(
          builder: (context, constraints) {
            final wide = constraints.maxWidth >= 900;
            final body = pages[_section]!;
            return Scaffold(
              appBar: AppBar(
                title: const Text(p2wlanAppName),
                centerTitle: false,
                actions: [
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    child: Center(
                      child: StatusBadge(
                        label: widget.statusStore.online ? 'Online' : 'Offline',
                        tone: widget.statusStore.online
                            ? StatusTone.good
                            : StatusTone.bad,
                      ),
                    ),
                  ),
                  IconButton(
                    tooltip: 'Refresh',
                    onPressed: widget.statusStore.refreshing
                        ? null
                        : () => widget.statusStore.refresh(),
                    icon: widget.statusStore.refreshing
                        ? const SizedBox.square(
                            dimension: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.refresh),
                  ),
                  const SizedBox(width: 8),
                ],
              ),
              body: wide
                  ? _WideShell(
                      body: body,
                      selected: _section,
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
                            label: item.label,
                          ),
                      ],
                    ),
            );
          },
        );
      },
    );
  }

  void _select(P2WlanSection section) {
    setState(() => _section = section);
  }
}

class _WideShell extends StatelessWidget {
  const _WideShell({
    required this.body,
    required this.selected,
    required this.onSelect,
  });

  final Widget body;
  final P2WlanSection selected;
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
          minWidth: 96,
          destinations: [
            for (final item in P2WlanSection.values)
              NavigationRailDestination(
                icon: Icon(item.icon),
                label: Text(item.label),
              ),
          ],
        ),
        const VerticalDivider(width: 1),
        Expanded(child: body),
      ],
    );
  }
}
