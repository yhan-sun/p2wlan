part of '../settings_page.dart';

/// Developer & Diagnostics: Diagnostics URL (with the running-daemon guard and
/// a secondary restore-default action), local service state and config path as
/// compact rows. A deliberately quiet technical page — not a dashboard.
class _DeveloperSection extends StatelessWidget {
  const _DeveloperSection({required this.state, required this.strings});

  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final saving = state._saving;
    final statusStore = state.widget.statusStore;
    final daemonController = statusStore.daemonController;
    final clientBuild = daemonController.clientBuildInfo;
    final daemonBuild = daemonController.lastDaemonBuildInfo;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _SettingsField(
          controller: state._diagnosticsUrlController,
          label: strings.diagnosticsUrl,
          hintText: defaultDiagnosticsUrl,
          helper: strings.diagnosticsUrlHelper,
          errorText: state._diagnosticsError,
          keyboardType: TextInputType.url,
          textInputAction: TextInputAction.done,
          onSubmitted: saving
              ? null
              : (_) => state._saveCategory(SettingsCategory.developer),
        ),
        const SizedBox(height: AppTokens.space10),
        Wrap(
          spacing: 12,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            OutlinedButton.icon(
              onPressed: statusStore.refreshActivityVisible
                  ? null
                  : statusStore.refresh,
              icon: const Icon(Icons.refresh, size: 16),
              label: Text(strings.refreshNow),
            ),
            // Restore is a secondary action, never primary next to Save.
            TextButton.icon(
              onPressed: saving ? null : state._resetDiagnosticsUrl,
              icon: const Icon(Icons.restore, size: 16),
              label: Text(strings.restoreDefaultUrl),
            ),
            OutlinedButton.icon(
              key: const Key('settings-upload-current-session-logs'),
              onPressed: saving || state._uploadingLogs
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
          ],
        ),
        if (state._logUploadError != null) ...[
          const SizedBox(height: AppTokens.space6),
          Text(
            state._logUploadError!,
            style: TextStyle(fontSize: 12, color: theme.colorScheme.error),
          ),
        ],
        const SizedBox(height: AppTokens.space10),
        const Divider(height: 1),
        const SizedBox(height: AppTokens.space6),
        _PreferenceRow(
          label: strings.localService,
          value: statusStore.daemonReachable
              ? strings.daemonRunning
              : strings.daemonStopped,
        ),
        _PreferenceRow(
          label: strings.localSettingsFileLabel,
          value: state.widget.settingsStore.configPath ?? '—',
        ),
        _PreferenceRow(
          label: strings.clientBuildIdentity,
          value: clientBuild.appVersion,
        ),
        _PreferenceRow(
          label: strings.buildCommitLabel,
          value: clientBuild.gitCommit,
        ),
        _PreferenceRow(label: strings.buildIdLabel, value: clientBuild.buildId),
        _PreferenceRow(
          label: strings.buildDirtyLabel,
          value: clientBuild.dirtyLabel,
        ),
        _PreferenceRow(
          label: strings.buildDiffHashLabel,
          value: clientBuild.diffHash,
        ),
        _PreferenceRow(
          label: strings.buildProfileLabel,
          value: clientBuild.profile,
        ),
        if (daemonBuild != null) ...[
          _PreferenceRow(
            label: strings.daemonBuildIdentity,
            value: daemonBuild.appVersion,
          ),
          _PreferenceRow(
            label: strings.buildCommitLabel,
            value: daemonBuild.gitCommit,
          ),
          _PreferenceRow(
            label: strings.buildIdLabel,
            value: daemonBuild.buildId,
          ),
          _PreferenceRow(
            label: strings.buildDirtyLabel,
            value: daemonBuild.dirtyLabel,
          ),
          _PreferenceRow(
            label: strings.buildDiffHashLabel,
            value: daemonBuild.diffHash,
          ),
          _PreferenceRow(
            label: strings.buildProfileLabel,
            value: daemonBuild.profile,
          ),
        ],
        _PreferenceRow(
          label: strings.clientLogFileLabel,
          value: daemonController.clientLogPath,
        ),
        _PreferenceRow(
          label: strings.daemonLogFileLabel,
          value: daemonController.daemonLogPath,
        ),
        if (state.widget.settingsStore.lastError != null) ...[
          const SizedBox(height: AppTokens.space8),
          Text(
            state.widget.settingsStore.lastError!,
            style: TextStyle(
              fontSize: 12,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
  }
}
