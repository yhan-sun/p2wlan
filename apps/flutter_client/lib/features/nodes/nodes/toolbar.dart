part of '../nodes_page.dart';

/// The desktop status segment fits next to search and sort. Mobile keeps its
/// space-saving menu, including the path and attention filters.
class _NodeToolbar extends StatelessWidget {
  const _NodeToolbar({
    required this.searchController,
    required this.searchFocusNode,
    required this.filter,
    required this.sort,
    required this.totalCount,
    required this.onlineCount,
    this.desktop = false,
    this.scopeConnections = false,
    required this.onFilterChanged,
    required this.onSortChanged,
    required this.onQueryChanged,
    required this.onClearSearch,
    this.onOpenWakeCatalog,
  });

  final TextEditingController searchController;
  final FocusNode searchFocusNode;
  final _NodeFilter filter;
  final _NodeSort sort;
  final int totalCount;
  final int onlineCount;
  final bool desktop;
  final bool scopeConnections;
  final ValueChanged<_NodeFilter> onFilterChanged;
  final ValueChanged<_NodeSort> onSortChanged;
  final VoidCallback onQueryChanged;
  final VoidCallback onClearSearch;
  final VoidCallback? onOpenWakeCatalog;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final controlHeight = desktop
        ? AppTokens.space40
        : AppTokens.minTouchTarget;
    final search = ConstrainedBox(
      constraints: BoxConstraints(minHeight: controlHeight),
      child: TextField(
        key: const Key('nodes-search-field'),
        controller: searchController,
        focusNode: searchFocusNode,
        onChanged: (_) => onQueryChanged(),
        textInputAction: TextInputAction.search,
        style: const TextStyle(fontSize: 13),
        decoration: InputDecoration(
          hintText: desktop
              ? (strings.isZh
                    ? '搜索设备名称或虚拟 IP'
                    : 'Search device name or virtual IP')
              : strings.searchDevicesPlaceholder,
          prefixIcon: desktop
              ? const Center(
                  widthFactor: 1,
                  child: DesktopIcon('search', size: 16),
                )
              : const Icon(Icons.search_rounded, size: 18),
          prefixIconConstraints: BoxConstraints(
            minWidth: controlHeight,
            minHeight: controlHeight,
          ),
          suffixIcon: searchController.text.isEmpty
              ? null
              : IconButton(
                  key: const Key('nodes-search-clear'),
                  tooltip: strings.clearSearch,
                  onPressed: onClearSearch,
                  visualDensity: desktop
                      ? VisualDensity.compact
                      : VisualDensity.standard,
                  icon: const Icon(Icons.close_rounded, size: 17),
                ),
          isDense: true,
          filled: desktop ? true : null,
          fillColor: desktop ? colors.surfaceElevated : colors.surfaceMuted,
          contentPadding: EdgeInsets.symmetric(
            horizontal: AppTokens.space12,
            vertical: desktop ? AppTokens.space8 : AppTokens.space12,
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
            borderSide: BorderSide(
              color: desktop ? DesktopCard.borderOf(context) : colors.border,
            ),
          ),
        ),
      ),
    );
    final sortButton = _MenuButton<_NodeSort>(
      buttonKey: const Key('nodes-sort-button'),
      icon: Icons.sort_rounded,
      tooltip: _sortLabel(strings, sort),
      desktop: desktop,
      initialValue: sort,
      label: desktop && sort == _NodeSort.recommended
          ? (strings.isZh ? '默认排序' : 'Default sort')
          : _sortLabel(strings, sort),
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
    );
    final wakeButton = onOpenWakeCatalog == null
        ? null
        : SizedBox.square(
            dimension: controlHeight,
            child: IconButton(
              key: const ValueKey('devices-remote-wake'),
              tooltip: WakeStrings(strings.isZh).title,
              onPressed: onOpenWakeCatalog,
              icon: const Icon(Icons.power_settings_new_rounded, size: 18),
            ),
          );
    if (desktop) {
      return LayoutBuilder(
        builder: (context, constraints) {
          final segment = _DeviceStatusSegment(
            filter: filter,
            onChanged: onFilterChanged,
          );
          final scaledLabel = MediaQuery.textScalerOf(context).scale(13);
          if (constraints.maxWidth >= 516 * (scaledLabel / 13).clamp(1, 1.3) &&
              scaledLabel <= 17) {
            return Row(
              children: [
                Expanded(child: search),
                const SizedBox(width: AppTokens.space12),
                segment,
                const SizedBox(width: AppTokens.space12),
                sortButton,
                ?wakeButton,
              ],
            );
          }
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              search,
              const SizedBox(height: AppTokens.space8),
              Wrap(
                spacing: AppTokens.space12,
                runSpacing: AppTokens.space8,
                children: [segment, sortButton, ?wakeButton],
              ),
            ],
          );
        },
      );
    }
    final mobileSearch = wakeButton == null
        ? search
        : Row(
            children: [
              Expanded(child: search),
              const SizedBox(width: AppTokens.space8),
              wakeButton,
            ],
          );
    final summary = Text(
      scopeConnections
          ? (strings.isZh
                ? '$totalCount 个设备连接 · $onlineCount 在线'
                : '$totalCount device connections · $onlineCount online')
          : strings.deviceCountSummary(totalCount, onlineCount),
      key: const Key('nodes-summary'),
      style: theme.textTheme.bodySmall!.copyWith(color: colors.textSecondary),
    );
    final menus = Wrap(
      spacing: AppTokens.space4,
      runSpacing: 4,
      children: [
        _MenuButton<_NodeFilter>(
          buttonKey: const Key('nodes-filter-button'),
          icon: Icons.filter_alt_outlined,
          tooltip: strings.filter,
          desktop: desktop,
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
        sortButton,
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
                  Expanded(child: mobileSearch),
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
            mobileSearch,
            const SizedBox(height: AppTokens.space8),
            if (constraints.maxWidth >= 320 && !largeText)
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

class _DeviceStatusSegment extends StatelessWidget {
  const _DeviceStatusSegment({required this.filter, required this.onChanged});

  final _NodeFilter filter;
  final ValueChanged<_NodeFilter> onChanged;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final colors = P2WlanColors.of(context);
    final border = DesktopCard.borderOf(context);
    final primary = Theme.of(context).colorScheme.primary;
    final scaledLabel = MediaQuery.textScalerOf(context).scale(13);
    final fixedSize = scaledLabel <= 17
        ? Size(62 * (scaledLabel / 13).clamp(1, 1.3), 32)
        : null;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.surfaceMuted,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: border),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space4),
        child: Wrap(
          spacing: AppTokens.space2,
          runSpacing: AppTokens.space2,
          children: [
            for (final item in _desktopNodeFilters)
              Semantics(
                selected: filter == item,
                child: TextButton(
                  key: Key('nodes-filter-${item.name}'),
                  onPressed: () => onChanged(item),
                  style: TextButton.styleFrom(
                    minimumSize: const Size(62, 32),
                    fixedSize: fixedSize,
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppTokens.space8,
                    ),
                    foregroundColor: filter == item
                        ? primary
                        : colors.textSecondary,
                    backgroundColor: filter == item
                        ? colors.surfaceElevated
                        : null,
                    textStyle: TextStyle(
                      fontSize: 13,
                      fontFamily: AppTokens.primaryFontFamily,
                      fontFamilyFallback: AppTokens.fontFamilyFallback,
                      fontWeight: filter == item
                          ? FontWeight.w600
                          : FontWeight.w500,
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(6),
                      side: filter == item
                          ? BorderSide(color: border)
                          : BorderSide.none,
                    ),
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    visualDensity: VisualDensity.standard,
                  ),
                  child: Text(
                    _filterLabel(strings, item),
                    maxLines: fixedSize == null ? null : 1,
                    overflow: fixedSize == null ? null : TextOverflow.ellipsis,
                  ),
                ),
              ),
          ],
        ),
      ),
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
    required this.desktop,
  });

  final Key buttonKey;
  final String tooltip;
  final IconData icon;
  final T initialValue;
  final String label;
  final ValueChanged<T> onSelected;
  final PopupMenuItemBuilder<T> itemBuilder;
  final bool desktop;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final fixedWidth =
        desktop && MediaQuery.textScalerOf(context).scale(13) <= 17;
    return PopupMenuButton<T>(
      key: buttonKey,
      tooltip: tooltip,
      initialValue: initialValue,
      onSelected: onSelected,
      itemBuilder: itemBuilder,
      color: colors.surfaceElevated,
      surfaceTintColor: Colors.transparent,
      elevation: desktop ? 2 : 8,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        side: BorderSide(color: colors.border),
      ),
      child: ConstrainedBox(
        constraints: BoxConstraints(
          minHeight: desktop ? AppTokens.space40 : AppTokens.minTouchTarget,
          minWidth: desktop ? 120 : AppTokens.minTouchTarget,
          maxWidth: fixedWidth ? 120 : double.infinity,
        ),
        child: MouseRegion(
          cursor: SystemMouseCursors.click,
          child: Container(
            decoration: desktop
                ? BoxDecoration(
                    color: colors.surfaceElevated,
                    borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                    border: Border.all(color: DesktopCard.borderOf(context)),
                  )
                : null,
            padding: EdgeInsets.symmetric(
              horizontal: desktop ? AppTokens.space12 : AppTokens.space8,
              vertical: desktop ? AppTokens.space8 : AppTokens.space12,
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: desktop
                  ? MainAxisAlignment.center
                  : MainAxisAlignment.start,
              children: [
                if (desktop)
                  DesktopIcon(
                    'chevron-down',
                    size: 14,
                    color: colors.textPrimary,
                  )
                else
                  Icon(
                    icon,
                    size: 16,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                const SizedBox(width: AppTokens.space6),
                Flexible(
                  child: Text(
                    label,
                    maxLines: fixedWidth ? 1 : null,
                    overflow: fixedWidth ? TextOverflow.ellipsis : null,
                    style: theme.textTheme.bodySmall!.copyWith(
                      fontWeight: FontWeight.w500,
                      color: colors.textPrimary,
                    ),
                  ),
                ),
              ],
            ),
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
