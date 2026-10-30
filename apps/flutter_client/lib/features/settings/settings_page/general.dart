part of '../settings_page.dart';

class _GeneralSection extends StatelessWidget {
  const _GeneralSection({required this.state, required this.strings});
  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final settings = state.widget.settingsStore.settings;
    final saving = state._saving;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
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
              textInputAction: TextInputAction.done,
              onSubmitted: saving
                  ? null
                  : (_) => state._saveCategory(SettingsCategory.general),
            ),
            if (state._capabilities.canUseSystemTray) ...[
              const SizedBox(height: 16),
              _ApplicationSection(state: state, strings: strings),
            ],
          ],
        ),
        _SettingsGroup(
          title: strings.settingsPreferencesGroup,
          children: [
            _PreferenceRow(
              label: strings.language,
              subtitle: strings.languageHelper,
              trailing: AppSelect<String>(
                width: 248,
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
            if (state._immediateSaved == 'language')
              _PreferenceSaved(message: strings.languageSaved),
            const SizedBox(height: 16),
            Text(
              strings.themeMode,
              style: Theme.of(context).textTheme.titleSmall,
            ),
            const SizedBox(height: 4),
            Text(
              strings.themeModeHelper,
              style: TextStyle(
                fontSize: 12,
                height: 1.45,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 12),
            LayoutBuilder(
              builder: (context, constraints) {
                final options = [
                  (
                    AppThemeMode.system.code,
                    strings.themeSystem,
                    Icons.brightness_auto_outlined,
                  ),
                  (
                    AppThemeMode.light.code,
                    strings.themeLight,
                    Icons.light_mode_outlined,
                  ),
                  (
                    AppThemeMode.dark.code,
                    strings.themeDark,
                    Icons.dark_mode_outlined,
                  ),
                ];
                final vertical =
                    constraints.maxWidth < 300 ||
                    MediaQuery.textScalerOf(context).scale(14) > 18;
                return SegmentedButton<String>(
                  key: const ValueKey('settings-theme-select'),
                  direction: vertical ? Axis.vertical : Axis.horizontal,
                  expandedInsets: vertical ? null : EdgeInsets.zero,
                  style: ButtonStyle(
                    shape: WidgetStatePropertyAll(
                      RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                  showSelectedIcon: false,
                  segments: [
                    for (final option in options)
                      ButtonSegment(
                        value: option.$1,
                        label: Text(option.$2),
                        icon: Icon(option.$3, size: 18),
                      ),
                  ],
                  selected: {AppThemeMode.fromCode(settings.themeMode).code},
                  onSelectionChanged: saving
                      ? null
                      : (values) => state._saveThemeMode(values.single),
                );
              },
            ),
            if (state._immediateSaved == 'theme')
              _PreferenceSaved(message: strings.themeSaved),
            if (state._immediateError != null) ...[
              const SizedBox(height: 12),
              _SettingsErrorNotice(message: state._immediateError!),
            ],
          ],
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
