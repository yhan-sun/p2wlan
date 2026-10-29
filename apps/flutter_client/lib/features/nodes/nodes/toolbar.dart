part of '../nodes_page.dart';

/// Search and distinct filter/sort controls share the available panel width.
/// A single summary describes the peer catalog; local identity stays separate.
class _NodeToolbar extends StatelessWidget {
  const _NodeToolbar({
    required this.searchController,
    required this.searchFocusNode,
    required this.filter,
    required this.sort,
    required this.allPeers,
    this.onlineCount,
    this.scopeConnections = false,
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
  final int? onlineCount;
  final bool scopeConnections;
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
    final onlineCount =
        this.onlineCount ?? _filterCount(allPeers, _NodeFilter.online);
    final colors = P2WlanColors.of(context);
    final search = TextField(
      key: const Key('nodes-search-field'),
      controller: searchController,
      focusNode: searchFocusNode,
      onChanged: (_) => onQueryChanged(),
      textInputAction: TextInputAction.search,
      style: const TextStyle(fontSize: 13),
      decoration: InputDecoration(
        hintText: strings.searchDevicesPlaceholder,
        prefixIcon: const Icon(Icons.search_rounded, size: 18),
        prefixIconConstraints: const BoxConstraints(minWidth: 38),
        suffixIcon: searchController.text.isEmpty
            ? null
            : IconButton(
                key: const Key('nodes-search-clear'),
                tooltip: strings.clearSearch,
                onPressed: onClearSearch,
                icon: const Icon(Icons.close_rounded, size: 17),
              ),
        isDense: true,
        fillColor: colors.surfaceMuted,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 12,
          vertical: 12,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          borderSide: BorderSide(color: colors.border),
        ),
      ),
    );
    final summary = Text(
      scopeConnections
          ? (strings.isZh
                ? '${allPeers.length} 个设备连接 · $onlineCount 在线'
                : '${allPeers.length} device connections · $onlineCount online')
          : strings.deviceCountSummary(allPeers.length, onlineCount),
      key: const Key('nodes-summary'),
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(fontSize: 12, color: theme.colorScheme.onSurfaceVariant),
    );
    final menus = Wrap(
      spacing: AppTokens.space4,
      runSpacing: 4,
      children: [
        _MenuButton<_NodeFilter>(
          buttonKey: const Key('nodes-filter-button'),
          icon: Icons.filter_alt_outlined,
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
        _MenuButton<_NodeSort>(
          buttonKey: const Key('nodes-sort-button'),
          icon: Icons.sort_rounded,
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
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        final largeText = MediaQuery.textScalerOf(context).scale(13) > 17;
        if (constraints.maxWidth >= 500 && !largeText) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(child: search),
                  const SizedBox(width: AppTokens.space8),
                  menus,
                ],
              ),
              const SizedBox(height: AppTokens.space8),
              summary,
            ],
          );
        }
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            search,
            const SizedBox(height: AppTokens.space8),
            if (constraints.maxWidth >= 360 && !largeText)
              Row(
                children: [
                  Expanded(child: summary),
                  menus,
                ],
              )
            else ...[
              summary,
              const SizedBox(height: AppTokens.space4),
              Align(alignment: Alignment.centerLeft, child: menus),
            ],
          ],
        );
      },
    );
  }
}

/// Quiet label button that opens a checked popup menu.
class _MenuButton<T> extends StatelessWidget {
  const _MenuButton({
    required this.buttonKey,
    required this.tooltip,
    required this.icon,
    required this.initialValue,
    required this.label,
    required this.onSelected,
    required this.itemBuilder,
  });

  final Key buttonKey;
  final String tooltip;
  final IconData icon;
  final T initialValue;
  final String label;
  final ValueChanged<T> onSelected;
  final PopupMenuItemBuilder<T> itemBuilder;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return PopupMenuButton<T>(
      key: buttonKey,
      tooltip: tooltip,
      initialValue: initialValue,
      onSelected: onSelected,
      itemBuilder: itemBuilder,
      color: colors.surfaceElevated,
      surfaceTintColor: Colors.transparent,
      shadowColor: const Color(0x240F172A),
      elevation: 10,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        side: BorderSide(color: colors.border),
      ),
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, size: 16, color: theme.colorScheme.onSurfaceVariant),
              const SizedBox(width: AppTokens.space6),
              Flexible(
                child: Text(
                  label,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: theme.colorScheme.onSurface,
                  ),
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
    _NodeSort.recommended => strings.sortByOnlineFirst,
    _NodeSort.name => strings.sortByName,
    _NodeSort.latency => strings.sortByLatency,
  };
}
