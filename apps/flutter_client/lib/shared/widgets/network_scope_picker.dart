import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../core/presentation/network_overview.dart';
import '../network_overview_presentation.dart';

/// Local display scope only; selecting a scope never changes a runtime.
class NetworkScopePicker extends StatelessWidget {
  const NetworkScopePicker({
    super.key,
    required this.overview,
    required this.selectedId,
    required this.onChanged,
  });

  final NetworkOverview overview;
  final String? selectedId;
  final ValueChanged<String?> onChanged;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final selected = overview.selected(selectedId);
    final allLabel = strings.isZh ? '全部房间与网络' : 'All rooms and networks';
    return Align(
      alignment: Alignment.centerLeft,
      child: PopupMenuButton<String>(
        key: const Key('network-scope-picker'),
        tooltip: strings.isZh ? '查看范围' : 'View scope',
        onSelected: (value) => onChanged(value.isEmpty ? null : value),
        itemBuilder: (_) => [
          CheckedPopupMenuItem(
            value: '',
            checked: selectedId == null,
            child: Text(allLabel),
          ),
          for (final scope in overview.scopes)
            CheckedPopupMenuItem(
              value: scope.id,
              checked: selectedId == scope.id,
              child: Text(networkScopeLabel(strings, scope)),
            ),
        ],
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 10),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.layers_outlined, size: 18),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  selectedId == null || selected.isEmpty
                      ? allLabel
                      : networkScopeLabel(strings, selected.first),
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              const Icon(Icons.expand_more_rounded, size: 18),
            ],
          ),
        ),
      ),
    );
  }
}
