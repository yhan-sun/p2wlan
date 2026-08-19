part of '../nodes_page.dart';

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
    // Single source of truth for the "online" semantic: the same predicate the
    // Online filter chip uses, so summary and chip can never disagree.
    final onlineCount = _filterCount(allPeers, _NodeFilter.online);
    final chips = _NodeFilter.values.map((item) {
      return Padding(
        padding: const EdgeInsets.only(right: 8),
        child: ChoiceChip(
          key: Key('nodes-filter-${item.name}'),
          label: Text(
            '${_filterLabel(strings, item)} ${_filterCount(allPeers, item)}',
          ),
          selected: filter == item,
          visualDensity: VisualDensity.compact,
          onSelected: (_) => onFilterChanged(item),
        ),
      );
    }).toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
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
                  border: const OutlineInputBorder(),
                ),
              ),
            ),
            const SizedBox(width: AppTokens.space10),
            PopupMenuButton<_NodeSort>(
              key: const Key('nodes-sort-button'),
              tooltip: _sortLabel(strings, sort),
              initialValue: sort,
              onSelected: onSortChanged,
              itemBuilder: (context) => [
                PopupMenuItem(
                  value: _NodeSort.recommended,
                  child: Text(strings.sortRecommended),
                ),
                PopupMenuItem(
                  value: _NodeSort.name,
                  child: Text(strings.sortByName),
                ),
                PopupMenuItem(
                  value: _NodeSort.latency,
                  child: Text(strings.sortByLatency),
                ),
              ],
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 10,
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.sort_rounded,
                      size: 18,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: AppTokens.space6),
                    Text(
                      _sortLabel(strings, sort),
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
          ],
        ),
        const SizedBox(height: AppTokens.space10),
        LayoutBuilder(
          builder: (context, constraints) {
            final chipsRow = SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(children: chips),
            );
            final summary = Text(
              strings.deviceCountSummary(allPeers.length, onlineCount),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            );
            if (constraints.maxWidth < 560) {
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  chipsRow,
                  const SizedBox(height: AppTokens.space8),
                  summary,
                ],
              );
            }
            return Row(
              children: [
                Expanded(child: chipsRow),
                const SizedBox(width: AppTokens.space12),
                summary,
              ],
            );
          },
        ),
      ],
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
