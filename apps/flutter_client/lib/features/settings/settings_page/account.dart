part of '../settings_page.dart';

/// Account & Network: credential state (never the token itself), control
/// server, network id, virtual IP, and Sign out as a bottom danger action.
class _AccountSection extends StatelessWidget {
  const _AccountSection({
    required this.state,
    required this.strings,
    required this.credentialState,
  });

  final _SettingsPageState state;
  final AppStrings strings;
  final String credentialState;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final saving = state._saving;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _PreferenceRow(
          label: strings.credentialSectionTitle,
          subtitle: credentialState,
          value: state._showTokenField
              ? strings.hideCredential
              : strings.changeCredential,
          onTap: saving
              ? null
              : () => state._updateState(
                  () => state._showTokenField = !state._showTokenField,
                ),
        ),
        if (state._showTokenField) ...[
          const SizedBox(height: AppTokens.space4),
          _SettingsField(
            controller: state._authTokenController,
            label: strings.authToken,
            helper: strings.credentialChangeHelper,
            obscureText: true,
            textInputAction: TextInputAction.next,
          ),
          const SizedBox(height: AppTokens.space6),
        ],
        _SettingsField(
          controller: state._controlServerController,
          label: strings.controlServer,
          helper: strings.controlServerHelper,
          keyboardType: TextInputType.url,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._networkIdController,
          label: strings.networkId,
          helper: strings.networkIdHelper,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._virtualIpController,
          label: strings.requestedVirtualIp,
          helper: strings.requestedVirtualIpHelperSettings,
          textInputAction: TextInputAction.done,
          onSubmitted: saving
              ? null
              : (_) => state._saveCategory(SettingsCategory.accountNetwork),
        ),
        if (state.widget.onLogout != null) ...[
          const SizedBox(height: AppTokens.space16),
          const Divider(height: 1),
          const SizedBox(height: AppTokens.space12),
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              onPressed: saving ? null : state.widget.onLogout,
              icon: const Icon(Icons.logout_outlined, size: 16),
              label: Text(strings.signOut),
              style: TextButton.styleFrom(
                foregroundColor: theme.colorScheme.error,
              ),
            ),
          ),
        ],
      ],
    );
  }
}
