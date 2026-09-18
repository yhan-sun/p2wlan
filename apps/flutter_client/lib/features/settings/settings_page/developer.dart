part of '../settings_page.dart';

class _DeveloperSection extends StatelessWidget {
  const _DeveloperSection({required this.state, required this.strings});
  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final status = state.widget.statusStore;
    final daemon = status.daemonController;
    final clientBuild = daemon.clientBuildInfo;
    final daemonBuild = daemon.lastDaemonBuildInfo;
    final canControl = state._capabilities.canControlLocalDaemon;
    final updateResult = state._updateCheckResult;
    final details = <(String, String)>[
      (strings.clientBuildIdentity, clientBuild.appVersion),
      (strings.buildCommitLabel, clientBuild.gitCommit),
      (strings.buildIdLabel, clientBuild.buildId),
      (strings.buildDirtyLabel, clientBuild.dirtyLabel),
      (strings.buildDiffHashLabel, clientBuild.diffHash),
      (strings.buildProfileLabel, clientBuild.profile),
      if (canControl && daemonBuild != null) ...[
        (strings.daemonBuildIdentity, daemonBuild.appVersion),
        (strings.buildCommitLabel, daemonBuild.gitCommit),
        (strings.buildIdLabel, daemonBuild.buildId),
        (strings.buildDirtyLabel, daemonBuild.dirtyLabel),
        (strings.buildDiffHashLabel, daemonBuild.diffHash),
        (strings.buildProfileLabel, daemonBuild.profile),
      ],
    ];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _SettingsGroup(
          title: strings.settingsAboutGroup,
          children: [
            _PreferenceRow(
              label: strings.settingsAppVersion,
              value: clientBuild.appVersion,
            ),
            _PreferenceRow(
              label: strings.checkForUpdates,
              subtitle: _updateStatus(state, strings),
              trailing: OutlinedButton.icon(
                key: const Key('settings-check-for-updates'),
                onPressed: state._checkingForUpdates
                    ? null
                    : state._checkForUpdates,
                icon: state._checkingForUpdates
                    ? const SizedBox.square(
                        dimension: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.refresh_rounded, size: 16),
                label: Text(
                  state._checkingForUpdates
                      ? strings.checkingForUpdates
                      : strings.checkForUpdates,
                ),
              ),
            ),
            if (updateResult?.currentVersion != null)
              _SettingsValue(
                label: strings.currentVersionLabel,
                value: updateResult!.currentAppVersion,
              ),
            if (updateResult?.update != null)
              _SettingsValue(
                label: strings.latestVersionLabel,
                value: updateResult!.update!.version.tag,
              ),
            if (updateResult?.hasUpdate == true)
              Align(
                alignment: Alignment.centerLeft,
                child: FilledButton.icon(
                  key: const Key('settings-view-update'),
                  onPressed: () => state._openUpdateRelease(updateResult!),
                  icon: const Icon(Icons.open_in_new_rounded, size: 16),
                  label: Text(strings.viewNewVersion),
                ),
              ),
            if (updateResult?.status == UpdateCheckStatus.networkError ||
                updateResult?.status == UpdateCheckStatus.invalidRelease)
              _SettingsErrorNotice(
                message: _updateErrorText(updateResult!, strings),
              ),
            if (canControl)
              _PreferenceRow(
                label: strings.localService,
                value: status.daemonReachable
                    ? strings.daemonRunning
                    : strings.daemonStopped,
                showDivider: false,
              ),
          ],
        ),
        if (canControl)
          _SettingsGroup(
            title: strings.diagnosticsEndpoint,
            children: [
              if (status.daemonReachable) ...[
                Text(
                  strings.settingsDiagnosticsStoppedHint,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
              ],
              _SettingsField(
                controller: state._diagnosticsUrlController,
                label: strings.diagnosticsUrl,
                hintText: defaultDiagnosticsUrl,
                helper: strings.diagnosticsUrlHelper,
                errorText: state._diagnosticsError,
                keyboardType: TextInputType.url,
                textInputAction: TextInputAction.done,
                onSubmitted: state._saving
                    ? null
                    : (_) => state._saveCategory(SettingsCategory.developer),
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 12,
                runSpacing: 8,
                children: [
                  OutlinedButton.icon(
                    onPressed: status.refreshActivityVisible
                        ? null
                        : status.refresh,
                    icon: const Icon(Icons.refresh, size: 16),
                    label: Text(strings.refreshNow),
                  ),
                  TextButton.icon(
                    onPressed: state._saving
                        ? null
                        : state._resetDiagnosticsUrl,
                    icon: const Icon(Icons.restore, size: 16),
                    label: Text(strings.restoreDefaultUrl),
                  ),
                ],
              ),
            ],
          ),
        if (canControl)
          _SettingsGroup(
            title: strings.settingsLogsGroup,
            children: [
              Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton.icon(
                  key: const Key('settings-upload-current-session-logs'),
                  onPressed: state._saving || state._uploadingLogs
                      ? null
                      : state._uploadCurrentSessionLogs,
                  icon: state._uploadingLogs
                      ? const SizedBox.square(
                          dimension: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.upload_file_outlined, size: 16),
                  label: Text(
                    state._uploadingLogs
                        ? strings.uploadingLogs
                        : strings.uploadCurrentSessionLogs,
                  ),
                ),
              ),
              if (state._logUploadError != null)
                _SettingsErrorNotice(message: state._logUploadError!),
              _SettingsValue(
                label: strings.clientLogFileLabel,
                value: daemon.clientLogPath,
              ),
              _SettingsValue(
                label: strings.daemonLogFileLabel,
                value: daemon.daemonLogPath,
              ),
              _SettingsValue(
                label: strings.localSettingsFileLabel,
                value: state.widget.settingsStore.configPath ?? '—',
              ),
            ],
          ),
        _SettingsSurface(
          padding: EdgeInsets.zero,
          child: ExpansionTile(
            key: const PageStorageKey('settings-build-details'),
            title: Text(strings.settingsBuildDetails),
            subtitle: Text(strings.settingsBuildDetailsHint),
            tilePadding: const EdgeInsets.symmetric(
              horizontal: 16,
              vertical: 8,
            ),
            childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            shape: const Border(),
            collapsedShape: const Border(),
            children: [
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(
                  key: const Key('settings-copy-build-details'),
                  onPressed: () async {
                    await Clipboard.setData(
                      ClipboardData(
                        text: details
                            .map((row) => '${row.$1}: ${row.$2}')
                            .join('\n'),
                      ),
                    );
                    if (context.mounted) {
                      showAppNotice(context, content: Text(strings.copied));
                    }
                  },
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  label: Text(strings.settingsCopyDetails),
                ),
              ),
              for (final row in details)
                _SettingsValue(label: row.$1, value: row.$2),
            ],
          ),
        ),
        if (state.widget.settingsStore.lastError != null) ...[
          const SizedBox(height: 16),
          _SettingsErrorNotice(message: state.widget.settingsStore.lastError!),
        ],
      ],
    );
  }

  String _updateStatus(_SettingsPageState state, AppStrings strings) {
    if (state._checkingForUpdates) return strings.checkingForUpdates;
    final result = state._updateCheckResult;
    if (result == null) return strings.updateNotChecked;
    return switch (result.status) {
      UpdateCheckStatus.upToDate => strings.updateUpToDate,
      UpdateCheckStatus.updateAvailable => strings.updateAvailableStatus(
        result.update!.version.tag,
      ),
      UpdateCheckStatus.developmentBuild => strings.updateDevelopmentBuild,
      UpdateCheckStatus.invalidRelease => strings.updateInvalidRelease,
      UpdateCheckStatus.networkError => strings.updateCheckFailed,
    };
  }

  String _updateErrorText(UpdateCheckResult result, AppStrings strings) {
    return switch (result.status) {
      UpdateCheckStatus.invalidRelease => strings.updateInvalidRelease,
      UpdateCheckStatus.networkError => strings.updateCheckFailed,
      _ => strings.updateCheckFailed,
    };
  }
}
