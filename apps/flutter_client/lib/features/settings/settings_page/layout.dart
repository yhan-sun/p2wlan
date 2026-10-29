part of '../settings_page.dart';

/// Category entry points use the available width without exposing form fields.
class _SettingsRoot extends StatelessWidget {
  const _SettingsRoot({
    required this.categories,
    required this.summaryFor,
    required this.statusListenable,
    required this.onSelect,
  });

  final List<SettingsCategory> categories;
  final String Function(SettingsCategory category) summaryFor;
  final Listenable statusListenable;
  final ValueChanged<SettingsCategory> onSelect;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final twoColumns =
          constraints.maxWidth >= 520 &&
          MediaQuery.textScalerOf(context).scale(14) <= 19;
      final width = twoColumns
          ? (constraints.maxWidth - 16) / 2
          : constraints.maxWidth;
      Widget cardFor(SettingsCategory category) => SizedBox(
        width: width,
        child: _SettingsCategoryCard(
          category: category,
          summary: summaryFor(category),
          spacious: twoColumns,
          onTap: () => onSelect(category),
        ),
      );
      return ListView(
        padding: const EdgeInsets.symmetric(vertical: 2),
        children: [
          Wrap(
            spacing: 16,
            runSpacing: twoColumns ? 16 : 12,
            children: [
              for (final category in categories)
                if (category == SettingsCategory.developer)
                  AnimatedBuilder(
                    animation: statusListenable,
                    builder: (context, _) => cardFor(category),
                  )
                else
                  cardFor(category),
            ],
          ),
        ],
      );
    },
  );
}

class _SettingsCategoryCard extends StatelessWidget {
  const _SettingsCategoryCard({
    required this.category,
    required this.summary,
    required this.spacious,
    required this.onTap,
  });
  final SettingsCategory category;
  final String summary;
  final bool spacious;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final subtitle = switch (category) {
      SettingsCategory.general =>
        strings.isZh
            ? '设备名称、外观与启动偏好'
            : 'Device identity, appearance and startup',
      SettingsCategory.accountNetwork =>
        strings.isZh ? '账号登录、服务器与网络' : 'Account, server and network identity',
      SettingsCategory.advancedNetwork =>
        strings.isZh
            ? '虚拟网卡、UDP 与中继'
            : 'Virtual interface, UDP and relay options',
      SettingsCategory.developer =>
        strings.isZh ? '诊断服务、日志与版本' : 'Diagnostics, logs and client updates',
    };
    return Semantics(
      container: true,
      button: true,
      onTap: onTap,
      child: _SettingsSurface(
        padding: EdgeInsets.zero,
        child: InkWell(
          key: ValueKey('settings-category-card-${category.name}'),
          excludeFromSemantics: true,
          borderRadius: BorderRadius.circular(12),
          onTap: onTap,
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: spacious ? 150 : 118),
            child: Padding(
              padding: EdgeInsets.all(spacious ? 20 : 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      _SettingsCategoryIcon(category),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          category.label(strings),
                          style: TextStyle(
                            fontSize: 15,
                            height: 1.3,
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.onSurface,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Icon(
                        Icons.chevron_right_rounded,
                        size: 20,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    subtitle,
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.45,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    summary,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 13,
                      height: 1.3,
                      fontWeight: FontWeight.w600,
                      color: theme.colorScheme.onSurfaceVariant,
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

class _SettingsCategoryIcon extends StatelessWidget {
  const _SettingsCategoryIcon(this.category);
  final SettingsCategory category;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: 36,
      height: 36,
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withValues(alpha: .07),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Icon(category.icon, size: 19, color: theme.colorScheme.primary),
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
      width: 184,
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
                      maxLines: 2,
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
        state._restartRequired;
    if (!statusSensitive) return _buildDetail(context);
    return AnimatedBuilder(
      animation: state._statusViewNotifier,
      builder: (context, _) => _buildDetail(context),
    );
  }

  Widget _buildDetail(BuildContext context) {
    final dirty =
        state._categoryDirty(category) || state._savingCategory == category;
    final content = _categoryContent(category, state, strings, credentialState);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Expanded(
          child: ListView(
            key: PageStorageKey('settings-${category.name}'),
            keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
            padding: const EdgeInsets.fromLTRB(2, 2, 2, 16),
            children: [
              if (showHeader)
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
              ExcludeFocus(
                excluding: state._saving,
                child: AbsorbPointer(absorbing: state._saving, child: content),
              ),
            ],
          ),
        ),
        if (dirty)
          Padding(
            padding: const EdgeInsets.fromLTRB(2, AppTokens.space10, 2, 2),
            child: AnimatedBuilder(
              animation: state._statusViewNotifier,
              builder: (context, _) => _SaveBar(
                busy: state._saving,
                restartRequired:
                    state._restartRequired ||
                    state._draftNeedsRestart(category),
                onUndo: () => state._resetCategory(category),
                onSave: () => state._saveCategory(category),
              ),
            ),
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
                    padding: const EdgeInsets.fromLTRB(20, 20, 20, 20),
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
        summaryFor: (category) => state._categorySummary(category, strings),
        statusListenable: state._statusViewNotifier,
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
