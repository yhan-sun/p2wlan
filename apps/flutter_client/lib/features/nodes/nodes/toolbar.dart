part of '../nodes_page.dart';

/// Devices toolbar: one search field (bounded on desktop), a single summary
/// line, and two quiet menus for filter and sort. No chip row, no repeated
/// counts — every control earns its place.
class _NodeToolbar extends StatelessWidget {
  const _NodeToolbar({
    required this.searchController,
    required this.searchFocusNode,
    required this.filter,
    required this.sort,
    required this.allPeers,
    required this.onFilterChanged,
    required this.onSortChanged,
    required this.onQueryChanged,
    required this.onClearSearch,
  });

  final TextEditingController searchController;
  final FocusNode searchFocusNode;
  final _NodeFilter filter;
  final _NodeSort sort;
  final List<PeerSnapshot> allPeers;
  final ValueChanged<_NodeFilter> onFilterChanged;
  final ValueChanged<_NodeSort> onSortChanged;
  final VoidCallback onQueryChanged;
  final VoidCallback onClearSearch;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    // Single source of truth for the "online" semantic: the same predicate
    // the Online filter uses, so summary and filter can never disagree.
    final onlineCount = _filterCount(allPeers, _NodeFilter.online);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: TextField(
            key: const Key('nodes-search-field'),
            controller: searchController,
            focusNode: searchFocusNode,
            onChanged: (_) => onQueryChanged(),
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(
              hintText: strings.searchDevicesPlaceholder,
              prefixIcon: const Icon(Icons.search_rounded, size: 20),
              suffixIcon: searchController.text.isEmpty
                  ? null
                  : IconButton(
                      key: const Key('nodes-search-clear'),
                      tooltip: strings.clearSearch,
                      onPressed: onClearSearch,
                      icon: const Icon(Icons.close_rounded, size: 18),
                    ),
              isDense: true,
              border: const UnderlineInputBorder(),
            ),
          ),
        ),
        const SizedBox(height: AppTokens.space8),
        Row(
          children: [
            Expanded(
              child: Text(
                strings.deviceCountSummary(allPeers.length, onlineCount),
                key: const Key('nodes-summary'),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            _MenuButton<_NodeFilter>(
              buttonKey: const Key('nodes-filter-button'),
              tooltip: strings.filter,
              initialValue: filter,
              label: filter == _NodeFilter.all
                  ? strings.filter
                  : _filterLabel(strings, filter),
              onSelected: onFilterChanged,
              itemBuilder: (context) => [
                for (final item in _NodeFilter.values)
                  CheckedPopupMenuItem(
                    key: Key('nodes-filter-${item.name}'),
                    value: item,
                    checked: filter == item,
                    child: Text(_filterLabel(strings, item)),
                  ),
              ],
            ),
            const SizedBox(width: AppTokens.space4),
            _MenuButton<_NodeSort>(
              buttonKey: const Key('nodes-sort-button'),
              tooltip: _sortLabel(strings, sort),
              initialValue: sort,
              label: _sortLabel(strings, sort),
              onSelected: onSortChanged,
              itemBuilder: (context) => [
                for (final item in _NodeSort.values)
                  CheckedPopupMenuItem(
                    key: Key('nodes-sort-${item.name}'),
                    value: item,
                    checked: sort == item,
                    child: Text(_sortLabel(strings, item)),
                  ),
              ],
            ),
          ],
        ),
      ],
    );
  }
}

/// Quiet label button that opens a checked popup menu.
class _MenuButton<T> extends StatelessWidget {
  const _MenuButton({
    required this.buttonKey,
    required this.tooltip,
    required this.initialValue,
    required this.label,
    required this.onSelected,
    required this.itemBuilder,
  });

  final Key buttonKey;
  final String tooltip;
  final T initialValue;
  final String label;
  final ValueChanged<T> onSelected;
  final PopupMenuItemBuilder<T> itemBuilder;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return PopupMenuButton<T>(
      key: buttonKey,
      tooltip: tooltip,
      initialValue: initialValue,
      onSelected: onSelected,
      itemBuilder: itemBuilder,
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Icons.tune_rounded,
                size: 18,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: AppTokens.space6),
              Text(
                label,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

String _filterLabel(AppStrings strings, _NodeFilter filter) {
  return switch (filter) {
    _NodeFilter.all => strings.filterAll,
    _NodeFilter.online => strings.online,
    _NodeFilter.direct => strings.direct,
    _NodeFilter.relay => strings.relay,
    _NodeFilter.attention => strings.needsAttention,
    _NodeFilter.offline => strings.offline,
  };
}

String _sortLabel(AppStrings strings, _NodeSort sort) {
  return switch (sort) {
    _NodeSort.recommended => strings.sortRecommended,
    _NodeSort.name => strings.sortByName,
    _NodeSort.latency => strings.sortByLatency,
  };
}
