part of '../settings_page.dart';

class _GeneralSection extends StatelessWidget {
  const _GeneralSection({required this.state, required this.strings});
  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final settings = state.widget.settingsStore.settings;
    final saving = state._saving;
    final desktop = _usesDesktopSettings(context);
    final savedMessage = switch (state._immediateSaved) {
      'language' => strings.languageSaved,
      'theme' => strings.themeSaved,
      _ => null,
    };
    final themeControl = LayoutBuilder(
      builder: (context, constraints) {
        final options = [
          (AppThemeMode.system.code, strings.themeSystem),
          (AppThemeMode.light.code, strings.themeLight),
          (AppThemeMode.dark.code, strings.themeDark),
        ];
        final vertical =
            constraints.maxWidth < (desktop ? 220 : 300) ||
            MediaQuery.textScalerOf(context).scale(14) > 18;
        // Recreate the render object when changing between bounded and
        // shrink-wrapped layouts. SegmentedButton keeps its initial expansion.
        return KeyedSubtree(
          key: ValueKey(vertical),
          child: SegmentedButton<String>(
            key: const ValueKey('settings-theme-select'),
            direction: vertical ? Axis.vertical : Axis.horizontal,
            expandedInsets: vertical ? null : EdgeInsets.zero,
            showSelectedIcon: false,
            segments: [
              for (final option in options)
                ButtonSegment(value: option.$1, label: Text(option.$2)),
            ],
            selected: {AppThemeMode.fromCode(settings.themeMode).code},
            onSelectionChanged: saving
                ? null
                : (values) => state._saveThemeMode(values.single),
          ),
        );
      },
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _SettingsGroup(
          title: strings.settingsPreferencesGroup,
          headingStatus: desktop ? savedMessage : null,
          children: [
            _PreferenceRow(
              label: strings.language,
              subtitle: desktop ? null : strings.languageHelper,
              showDivider: desktop,
              trailing: AppSelect<String>(
                width: _settingsControlWidth,
                key: const ValueKey('settings-language-select'),
                menuTitle: strings.language,
                value: AppLanguage.fromCode(settings.languageCode).code,
                options: [
                  for (final language in AppLanguage.values)
                    AppSelectOption(
                      value: language.code,
                      label: strings.languageLabel(language.code),
                    ),
                ],
                onChanged: saving ? null : state._saveLanguage,
              ),
            ),
            if (!desktop && state._immediateSaved == 'language')
              _PreferenceSaved(message: strings.languageSaved),
            if (desktop)
              _PreferenceRow(
                label: strings.themeMode,
                trailing: SizedBox(
                  width: _settingsControlWidth,
                  child: themeControl,
                ),
                showDivider: false,
              )
            else ...[
              const SizedBox(height: AppTokens.space16),
              Text(
                strings.themeMode,
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: AppTokens.space4),
              Text(
                strings.themeModeHelper,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: AppTokens.space12),
              themeControl,
            ],
            if (!desktop && state._immediateSaved == 'theme')
              _PreferenceSaved(message: strings.themeSaved),
            if (state._immediateError != null) ...[
              const SizedBox(height: 12),
              _SettingsErrorNotice(message: state._immediateError!),
            ],
          ],
        ),
        _SettingsGroup(
          title: strings.settingsDeviceGroup,
          children: [
            _SettingsField(
              controller: state._deviceNameController,
              focusNode: state._focusFor(state._deviceNameController),
              errorText: state._fieldErrors[state._deviceNameController],
              onChanged: (_) =>
                  state._clearFieldError(state._deviceNameController),
              label: strings.deviceName,
              helper: strings.deviceNameHelper,
              asPreference: true,
              textInputAction: TextInputAction.done,
              onSubmitted: saving
                  ? null
                  : (_) => state._saveCategory(SettingsCategory.general),
            ),
            if (!desktop && state._capabilities.canUseSystemTray) ...[
              const SizedBox(height: 16),
              _ApplicationSection(state: state, strings: strings),
            ],
          ],
        ),
        if (desktop && state._capabilities.canUseSystemTray)
          _SettingsGroup(
            title: strings.isZh ? '启动与窗口' : 'Startup & window',
            children: [_ApplicationSection(state: state, strings: strings)],
          ),
      ],
    );
  }
}

class _PreferenceSaved extends StatelessWidget {
  const _PreferenceSaved({required this.message});
  final String message;
  @override
  Widget build(BuildContext context) => Semantics(
    liveRegion: true,
    child: Padding(
      padding: const EdgeInsets.only(top: 8),
      child: Row(
        children: [
          Icon(
            Icons.check_circle_outline,
            size: 16,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(message, style: Theme.of(context).textTheme.bodySmall),
          ),
        ],
      ),
    ),
  );
}
