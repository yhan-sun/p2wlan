part of '../settings_page.dart';

/// Compact two-line entry rows keep every category visible on a phone.
class _SettingsRoot extends StatelessWidget {
  const _SettingsRoot({
    required this.categories,
    required this.summaryFor,
    required this.onSelect,
  });

  final List<SettingsCategory> categories;
  final String Function(SettingsCategory category) summaryFor;
  final ValueChanged<SettingsCategory> onSelect;

  @override
  Widget build(BuildContext context) {
    final desktop = _usesDesktopSettings(context);
    final rows = Column(
      children: [
        if (desktop) const Divider(height: 1),
        for (var index = 0; index < categories.length; index++) ...[
          if (index > 0)
            Divider(
              height: 1,
              indent: 52,
              endIndent: 16,
              color: P2WlanColors.of(context).divider,
            ),
          _SettingsCategoryCard(
            category: categories[index],
            summary: summaryFor(categories[index]),
            onTap: () => onSelect(categories[index]),
          ),
        ],
        if (desktop) const Divider(height: 1),
      ],
    );
    return ListView(
      padding: const EdgeInsets.symmetric(vertical: AppTokens.space4),
      children: [
        if (desktop)
          rows
        else
          _SettingsSurface(padding: EdgeInsets.zero, child: rows),
      ],
    );
  }
}

class _SettingsCategoryCard extends StatelessWidget {
  const _SettingsCategoryCard({
    required this.category,
    required this.summary,
    required this.onTap,
  });
  final SettingsCategory category;
  final String summary;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final largeText = MediaQuery.textScalerOf(context).scale(14) > 18;
    final desktop = _usesDesktopSettings(context);
    return Semantics(
      container: true,
      button: true,
      onTap: onTap,
      child: _SettingsTapSurface(
        interactionKey: ValueKey('settings-category-card-${category.name}'),
        onTap: onTap,
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: desktop ? 60 : 76),
          child: Padding(
            padding: EdgeInsets.symmetric(
              horizontal: AppTokens.space12,
              vertical: desktop ? AppTokens.space8 : AppTokens.space14,
            ),
            child: Row(
              children: [
                _SettingsCategoryIcon(category),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        category.label(strings),
                        style: theme.textTheme.titleMedium,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        summary,
                        maxLines: largeText ? 2 : 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Icon(
                  Icons.chevron_right_rounded,
                  size: 20,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SettingsCategoryIcon extends StatelessWidget {
  const _SettingsCategoryIcon(this.category);
  final SettingsCategory category;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Icon(
      category.icon,
      size: 21,
      color: theme.colorScheme.onSurfaceVariant,
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
      key: const Key('settings-category-rail'),
      width: 180,
      child: ListView(
        padding: const EdgeInsetsDirectional.only(end: AppTokens.space12),
        children: [
          for (final category in categories)
            _CategoryRailItem(
              label: category.label(strings),
              icon: category.icon,
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
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final foreground = selected
        ? theme.colorScheme.primary
        : colors.textSecondary;
    return Padding(
      padding: const EdgeInsets.only(bottom: AppTokens.space4),
      child: Semantics(
        container: true,
        selected: selected,
        button: true,
        onTap: onTap,
        child: _SettingsTapSurface(
          onTap: onTap,
          selected: selected,
          radius: AppTokens.radiusSm,
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: AppTokens.space8,
              vertical: AppTokens.space8,
            ),
            child: Row(
              children: [
                Icon(icon, size: AppTokens.iconSm, color: foreground),
                const SizedBox(width: AppTokens.space8),
                Expanded(
                  child: Text(
                    label,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                      color: foreground,
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

/// A single category's detail: title, optional restart notice / error, the
/// category content, then the dirty save bar. Scrollable.
class _CategoryDetailView extends StatelessWidget {
  const _CategoryDetailView({
    required this.category,
    required this.state,
    required this.strings,
    required this.credentialState,
    this.onBack,
    this.showHeader = true,
  });

  final SettingsCategory category;
  final _SettingsPageState state;
  final AppStrings strings;
  final String credentialState;
  final VoidCallback? onBack;
  final bool showHeader;

  @override
  Widget build(BuildContext context) {
    final statusSensitive =
        category == SettingsCategory.advancedNetwork ||
        category == SettingsCategory.developer ||
        state.widget.statusStore.primaryConfigurationPending;
    if (!statusSensitive) return _buildDetail(context);
    return AnimatedBuilder(
      animation: state._statusViewNotifier,
      builder: (context, _) => _buildDetail(context),
    );
  }

  Widget _buildDetail(BuildContext context) {
    final desktop = _usesDesktopSettings(context);
    // Flutter adds a desktop scrollbar inside the viewport's trailing edge.
    final endInset = desktop ? AppTokens.space16 : AppTokens.space2;
    final dirty =
        state._categoryDirty(category) || state._savingCategory == category;
    final content = _categoryContent(category, state, strings, credentialState);
    final subtitle = _categorySubtitle(category, strings);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (showHeader)
          Padding(
            padding: EdgeInsetsDirectional.fromSTEB(
              AppTokens.space2,
              AppTokens.space2,
              endInset,
              AppTokens.space8,
            ),
            child: _DetailHeader(
              title: category.label(strings),
              onBack: onBack,
            ),
          ),
        Expanded(
          child: ListView(
            key: PageStorageKey('settings-${category.name}'),
            keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
            padding: EdgeInsetsDirectional.fromSTEB(
              AppTokens.space2,
              AppTokens.space2,
              endInset,
              desktop ? AppTokens.space4 : AppTokens.space16,
            ),
            children: [
              // Keep Back reachable while long descriptions and forms scroll,
              // including short windows with accessibility text scaling.
              if (showHeader && subtitle != null && subtitle.isNotEmpty)
                Padding(
                  padding: EdgeInsetsDirectional.only(
                    start: onBack == null
                        ? 0
                        : _DetailHeader.leadingExtent(desktop: desktop),
                    bottom: AppTokens.space12,
                  ),
                  child: Text(
                    subtitle,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              if (state._formErrorCategory == category &&
                  state._formError != null) ...[
                _SettingsErrorNotice(message: state._formError!),
                const SizedBox(height: AppTokens.space12),
              ],
              if (state._currentRestartPhase !=
                      LocalConnectionRestartPhase.idle &&
                  !(state._currentRestartPhase ==
                          LocalConnectionRestartPhase.complete &&
                      state
                          .widget
                          .statusStore
                          .primaryConfigurationPending)) ...[
                LocalConnectionRestartFeedback(
                  phase: state._currentRestartPhase,
                  serviceReachable: state.widget.statusStore.healthReachable,
                  configurationPending:
                      state.widget.statusStore.primaryConfigurationPending,
                  busy: state._saving || state.widget.statusStore.daemonBusy,
                  onRetry: state._restartDaemonToApply,
                  onDismiss: () => state._updateState(
                    () =>
                        state._restartPhase = LocalConnectionRestartPhase.idle,
                  ),
                ),
                const SizedBox(height: AppTokens.space12),
              ],
              if (state.widget.statusStore.primaryConfigurationPending &&
                  (state._currentRestartPhase ==
                          LocalConnectionRestartPhase.idle ||
                      state._currentRestartPhase ==
                          LocalConnectionRestartPhase.complete)) ...[
                _PendingRestartNotice(
                  busy: state._saving || state.widget.statusStore.daemonBusy,
                  canRestart: state._capabilities.canControlLocalDaemon,
                  onRestart: state._restartDaemonToApply,
                ),
                const SizedBox(height: AppTokens.space12),
              ],
              ExcludeFocus(
                excluding: state._saving,
                child: AbsorbPointer(absorbing: state._saving, child: content),
              ),
            ],
          ),
        ),
        _SettingsSaveSlot(
          key: const Key('settings-save-slot'),
          child: dirty
              ? Padding(
                  padding: EdgeInsetsDirectional.fromSTEB(
                    AppTokens.space2,
                    AppTokens.space10,
                    endInset,
                    AppTokens.space2,
                  ),
                  child: AnimatedBuilder(
                    animation: state._statusViewNotifier,
                    builder: (context, _) => _SaveBar(
                      busy: state._saving,
                      restartRequired: state._draftNeedsRestart(category),
                      onUndo: () => state._resetCategory(category),
                      onSave: () => state._saveCategory(category),
                    ),
                  ),
                )
              : const SizedBox(width: double.infinity),
        ),
      ],
    );
  }

  String? _categorySubtitle(SettingsCategory category, AppStrings strings) {
    return switch (category) {
      SettingsCategory.accountNetwork => strings.settingsSubtitleAccountNetwork,
      SettingsCategory.advancedNetwork => strings.advancedNetworkSubtitle,
      SettingsCategory.developer => strings.settingsDeveloperHint,
      _ => null,
    };
  }
}

/// A real secondary route for compact mobile settings. It covers the shell's
/// root app bar and bottom navigation, gives Android predictive/system back a
/// native route to pop, and still edits the parent Settings page's controllers
/// so drafts survive returning to the category root.
class _MobileSettingsCategoryPage extends StatelessWidget {
  const _MobileSettingsCategoryPage({
    required this.category,
    required this.state,
  });

  final SettingsCategory category;
  final _SettingsPageState state;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([
        state._detailViewNotifier,
        state.widget.settingsStore,
      ]),
      builder: (context, _) {
        final strings = AppStrings.fromCode(
          state.widget.settingsStore.settings.languageCode,
        );
        final colors = P2WlanColors.of(context);
        return AppStringsScope(
          strings: strings,
          child: Scaffold(
            key: const Key('settings-mobile-category-page'),
            backgroundColor: colors.surfaceMuted,
            appBar: AppBar(
              key: const Key('settings-mobile-category-app-bar'),
              leading: const AppBackButton(
                key: Key('settings-mobile-category-back'),
              ),
              title: Text(category.label(strings)),
              centerTitle: false,
              elevation: 0,
              scrolledUnderElevation: 0,
              surfaceTintColor: Colors.transparent,
              backgroundColor: colors.surface,
              bottom: PreferredSize(
                preferredSize: const Size.fromHeight(1),
                child: Divider(height: 1, color: colors.divider),
              ),
            ),
            body: SafeArea(
              top: false,
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(
                    maxWidth: settingsPageMaxWidth,
                  ),
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(16, 20, 16, 20),
                    child: _CategoryDetailView(
                      category: category,
                      state: state,
                      strings: strings,
                      credentialState: state._describeCredential(strings),
                      showHeader: false,
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
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
/// compact use a root list. Mobile opens a real full-screen route; medium
/// desktop opens the detail in-place. Drafts stay in the page state and survive
/// either presentation.
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
          const SizedBox(width: AppTokens.space24),
          Expanded(
            child: AppEntrance(
              identity: current,
              child: _CategoryDetailView(
                category: current,
                state: state,
                strings: strings,
                credentialState: credentialState,
              ),
            ),
          ),
        ],
      );
    }
    final current = selected;
    if (current == null) {
      return AppEntrance(
        identity: 'root',
        child: _SettingsRoot(
          categories: categories,
          summaryFor: (category) => state._categorySummary(category, strings),
          onSelect: onSelect,
        ),
      );
    }
    return AppEntrance(
      identity: current,
      child: _CategoryDetailView(
        category: current,
        state: state,
        strings: strings,
        credentialState: credentialState,
        onBack: onBack,
      ),
    );
  }
}
