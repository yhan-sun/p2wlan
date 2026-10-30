import 'package:flutter/material.dart';

import '../../core/models/diagnostics_models.dart';
import '../../core/traffic/traffic_history_store.dart';

/// App-owned history is available to pages and navigator overlays alike.
class TrafficHistoryScope extends InheritedNotifier<TrafficHistoryStore> {
  const TrafficHistoryScope({
    super.key,
    required TrafficHistoryStore store,
    required this.settings,
    required this.onRefresh,
    required super.child,
  }) : super(notifier: store);

  final AppSettings settings;
  final VoidCallback onRefresh;
  TrafficHistoryStore get store => notifier!;

  static TrafficHistoryScope? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<TrafficHistoryScope>();

  @override
  bool updateShouldNotify(TrafficHistoryScope oldWidget) =>
      settings != oldWidget.settings || super.updateShouldNotify(oldWidget);
}
