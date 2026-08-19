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
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._mtuController,
          label: strings.mtu,
          helper: strings.mtuHelper,
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._overlayCidrController,
          label: strings.overlayCidr,
          helper: strings.overlayCidrHelper,
        ),
        const SizedBox(height: AppTokens.space6),
        _SubsectionLabel(strings.udpSubsection),
        _SettingsField(
          controller: state._udpBindController,
          label: strings.udpBind,
          helper: strings.udpBindHelper,
        ),
        const SizedBox(height: AppTokens.space6),
        _SettingsField(
          controller: state._udpAdvertiseController,
          label: strings.udpAdvertise,
          helper: strings.udpAdvertiseHelper,
        ),
        const SizedBox(height: AppTokens.space6),
        _PreferenceRow(
          label: strings.socketPool,
          subtitle: strings.socketPoolHelper,
          trailing: DropdownButton<String>(
            key: ValueKey('socket-pool-${state._socketPool}'),
            value: state._socketPool,
            underline: const SizedBox.shrink(),
            items: const [
              DropdownMenuItem(value: 'off', child: Text('off')),
              DropdownMenuItem(value: '2', child: Text('2 sockets')),
              DropdownMenuItem(value: '3', child: Text('3 sockets')),
              DropdownMenuItem(value: '4', child: Text('4 sockets')),
            ],
            onChanged: saving || daemonBusy
                ? null
                : (value) {
                    if (value != null) {
                      state._updateState(() => state._socketPool = value);
                    }
                  },
          ),
        ),
        const SizedBox(height: AppTokens.space6),
        _SubsectionLabel(strings.relaySubsection),
        _SettingsField(
          controller: state._relayServersController,
          label: strings.relayCandidates,
          helper: strings.relayCandidatesHelper,
        ),
      ],
    );
  }
}
