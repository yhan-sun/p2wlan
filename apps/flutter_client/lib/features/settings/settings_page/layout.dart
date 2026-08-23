part of '../settings_page.dart';

/// The settings "home": a grouped list of categories with a short summary per
/// row. Used for medium and compact layouts (and the standalone page below the
/// desktop breakpoint). Tapping a category opens its detail in-place.
class _SettingsRoot extends StatelessWidget {
  const _SettingsRoot({
    required this.categories,
    required this.summaries,
    required this.onSelect,
  });

  final List<SettingsCategory> categories;
  final Map<SettingsCategory, String> summaries;
  final ValueChanged<SettingsCategory> onSelect;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return ListView(
      padding: const EdgeInsets.symmetric(vertical: AppTokens.space6),
      children: [
        _SettingsSurface(
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space6,
            vertical: AppTokens.space4,
          ),
          child: Column(
            children: [
              for (var index = 0; index < categories.length; index++)
                _PreferenceRow(
                  label: categories[index].label(strings),
                  value: summaries[categories[index]],
                  leading: _SettingsCategoryIcon(categories[index]),
                  showDivider: index != categories.length - 1,
                  onTap: () => onSelect(categories[index]),
                ),
            ],
          ),
        ),
      ],
    );
  }
}

class _SettingsCategoryIcon extends StatelessWidget {
  const _SettingsCategoryIcon(this.category);

  final SettingsCategory category;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Container(
      width: 34,
      height: 34,
      decoration: BoxDecoration(
        color: colors.selectedSurface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
      ),
      child: Icon(category.icon, size: 18, color: theme.colorScheme.primary),
    );
  }
}

/// Desktop sidebar navigation for the Settings section. Deliberately weaker
/// than the global product sidebar: no logo, no footer, no big icons, a narrow
/// width, and a subtle selected surface.
class _SettingsCategoryRail extends StatelessWidget {
  const _SettingsCategoryRail({
    required this.categories,
    required this.selected,
    required this.onSelect,
  });

  final List<SettingsCategory> categories;
  final SettingsCategory selected;
  final ValueChanged<SettingsCategory> onSelect;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return SizedBox(
      width: 176,
      child: ListView(
        padding: const EdgeInsets.symmetric(vertical: AppTokens.space6),
        children: [
          for (final category in categories)
            _CategoryRailItem(
              label: category.label(strings),
              selected: category == selected,
              onTap: () => onSelect(category),
            ),
        ],
      ),
    );
  }
}

class _CategoryRailItem extends StatelessWidget {
  const _CategoryRailItem({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(
        vertical: 1,
        horizontal: AppTokens.space6,
      ),
      child: Semantics(
        selected: selected,
        button: true,
        child: MouseRegion(
          cursor: SystemMouseCursors.click,
          child: InkWell(
            onTap: onTap,
            borderRadius: BorderRadius.circular(AppTokens.radiusMd),
            child: AnimatedContainer(
              duration: AppTokens.durationFast,
              curve: AppTokens.curveEase,
              padding: const EdgeInsets.symmetric(
                horizontal: AppTokens.space12,
                vertical: AppTokens.space10,
              ),
              decoration: BoxDecoration(
                color: selected ? colors.selectedSurface : Colors.transparent,
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: selected
                            ? FontWeight.w600
                            : FontWeight.w500,
                        color: selected
                            ? theme.colorScheme.primary
                            : theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                  if (selected)
                    Container(
                      width: 3,
                      height: 14,
                      decoration: BoxDecoration(
                        color: theme.colorScheme.primary,
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A single category's detail: title, optional restart notice / error, the
/// category content, then the dirty save bar. Scrollable.
class _CategoryDetailView extends StatelessWidget {
  const _CategoryDetailView({
    required this.category,
    required this.state,
    required this.strings,
    required this.credentialState,
    this.onBack,
  });

  final SettingsCategory category;
  final _SettingsPageState state;
  final AppStrings strings;
  final String credentialState;
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    final dirty = state._categoryDirty(category);
    final content = _categoryContent(category, state, strings, credentialState);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Expanded(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(2, 2, 2, 16),
            children: [
              _DetailHeader(
                title: category.label(strings),
                onBack: onBack,
                subtitle: _categorySubtitle(category, strings),
              ),
              if (state._formErrorCategory == category &&
                  state._formError != null) ...[
                _SettingsErrorNotice(message: state._formError!),
                const SizedBox(height: AppTokens.space12),
              ],
              if (state._restartRequired) ...[
                _PendingRestartNotice(
                  busy: state._saving || state.widget.statusStore.daemonBusy,
                  canRestart: state._capabilities.canControlLocalDaemon,
                  onRestart: state._restartDaemonToApply,
                ),
                const SizedBox(height: AppTokens.space12),
              ],
              _SettingsSurface(
                padding: const EdgeInsets.all(AppTokens.space10),
                child: content,
              ),
            ],
          ),
        ),
        if (dirty)
          Padding(
            padding: const EdgeInsets.fromLTRB(2, AppTokens.space10, 2, 2),
            child: _SaveBar(
              busy: state._saving,
              restartRequired: state._restartRequired,
              onSave: () => state._saveCategory(category),
            ),
          ),
      ],
    );
  }

  String? _categorySubtitle(SettingsCategory category, AppStrings strings) {
    return switch (category) {
      SettingsCategory.accountNetwork => strings.settingsSubtitleAccountNetwork,
      SettingsCategory.advancedNetwork => strings.advancedNetworkSubtitle,
      SettingsCategory.developer => strings.developerSectionSubtitle,
      _ => null,
    };
  }
}

Widget _categoryContent(
  SettingsCategory category,
  _SettingsPageState state,
  AppStrings strings,
  String credentialState,
) {
  return switch (category) {
    SettingsCategory.general => _GeneralSection(state: state, strings: strings),
    SettingsCategory.accountNetwork => _AccountSection(
      state: state,
      strings: strings,
      credentialState: credentialState,
    ),
    SettingsCategory.application => _ApplicationSection(
      state: state,
      strings: strings,
    ),
    SettingsCategory.advancedNetwork => _AdvancedNetworkSection(
      state: state,
      strings: strings,
    ),
    SettingsCategory.developer => _DeveloperSection(
      state: state,
      strings: strings,
    ),
  };
}

/// The responsive shell: desktop uses category rail + inline detail; medium and
/// compact use a root list that opens a full category detail in-place (back
/// returns to the root). No Navigator push, no second app shell — drafts live
/// in the page state and survive category switches and detail back-navigation.
class _SettingsShell extends StatelessWidget {
  const _SettingsShell({
    required this.layout,
    required this.categories,
    required this.selected,
    required this.onSelect,
    required this.onBack,
    required this.strings,
    required this.credentialState,
    required this.state,
  });

  final _SettingsLayout layout;
  final List<SettingsCategory> categories;
  final SettingsCategory? selected;
  final ValueChanged<SettingsCategory> onSelect;
  final VoidCallback onBack;
  final AppStrings strings;
  final String credentialState;
  final _SettingsPageState state;

  @override
  Widget build(BuildContext context) {
    if (layout == _SettingsLayout.expanded) {
      final current = selected ?? categories.first;
      return Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SettingsCategoryRail(
            categories: categories,
            selected: current,
            onSelect: onSelect,
          ),
          VerticalDivider(
            width: 1,
            color: Theme.of(context).colorScheme.outlineVariant,
          ),
          const SizedBox(width: AppTokens.space16),
          Expanded(
            child: _CategoryDetailView(
              category: current,
              state: state,
              strings: strings,
              credentialState: credentialState,
            ),
          ),
        ],
      );
    }
    final current = selected;
    if (current == null) {
      return _SettingsRoot(
        categories: categories,
        summaries: {
          for (final category in categories)
            category: state._categorySummary(category, strings),
        },
        onSelect: onSelect,
      );
    }
    return _CategoryDetailView(
      category: current,
      state: state,
      strings: strings,
      credentialState: credentialState,
      onBack: onBack,
    );
  }
}
