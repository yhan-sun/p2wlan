part of '../settings_page.dart';

/// Advanced Network: real technical fields, lightly grouped (virtual network /
/// UDP / relay). Only reachable when the device can act as a local VPN node.
class _AdvancedNetworkSection extends StatelessWidget {
  const _AdvancedNetworkSection({required this.state, required this.strings});

  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final saving = state._saving;
    final daemonBusy = state.widget.statusStore.daemonBusy;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _PreferenceRow(
          label: strings.manualMode,
          subtitle: strings.manualModeHelper,
          trailing: Switch.adaptive(
            value: state._manualMode,
            onChanged: saving
                ? null
                : (value) =>
                      state._updateState(() => state._manualMode = value),
          ),
        ),
        _SubsectionLabel(strings.virtualNetwork),
        _SettingsField(
          controller: state._tunInterfaceController,
          label: strings.interfaceName,
          helper: strings.interfaceNameHelper,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._mtuController,
          label: strings.mtu,
          helper: strings.mtuHelper,
          keyboardType: TextInputType.number,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._overlayCidrController,
          label: strings.overlayCidr,
          helper: strings.overlayCidrHelper,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _SubsectionLabel(strings.udpSubsection),
        _SettingsField(
          controller: state._udpBindController,
          label: strings.udpBind,
          helper: strings.udpBindHelper,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._udpAdvertiseController,
          label: strings.udpAdvertise,
          helper: strings.udpAdvertiseHelper,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: AppTokens.space6),
        _PreferenceRow(
          label: strings.socketPool,
          subtitle: strings.socketPoolHelper,
          trailing: AppSelect<String>(
            expanded: MediaQuery.sizeOf(context).width < 340,
            key: const ValueKey('settings-socket-pool-select'),
            menuTitle: strings.socketPool,
            value: state._socketPool,
            options: [
              AppSelectOption(value: 'off', label: strings.socketPoolOff),
              AppSelectOption(value: '2', label: strings.socketPool2),
              AppSelectOption(value: '3', label: strings.socketPool3),
              AppSelectOption(value: '4', label: strings.socketPool4),
            ],
            onChanged: saving || daemonBusy
                ? null
                : (value) =>
                      state._updateState(() => state._socketPool = value),
          ),
        ),
        const SizedBox(height: AppTokens.space6),
        _SubsectionLabel(strings.relaySubsection),
        _SettingsField(
          controller: state._relayServersController,
          label: strings.relayCandidates,
          helper: strings.relayCandidatesHelper,
          textInputAction: TextInputAction.done,
          onSubmitted: saving
              ? null
              : (_) => state._saveCategory(SettingsCategory.advancedNetwork),
        ),
      ],
    );
  }
}
