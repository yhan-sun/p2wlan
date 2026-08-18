import 'package:flutter/material.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/api/diagnostics_api.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/widgets/page_scaffold.dart';

part 'settings_page/widgets.dart';
part 'settings_page/actions.dart';

/// Describes credential state for display without ever revealing the token.
String _describeCredential(AppSettings settings, AppStrings strings) {
  if (settings.manualMode) {
    return strings.credentialManualMode;
  }
  return settings.authToken.trim().isEmpty
      ? strings.credentialNotSaved
      : strings.credentialSaved;
}

class SettingsPage extends StatefulWidget {
  const SettingsPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.capabilities,
    this.onLogout,
    this.showHeader = true,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  /// Platform capability override (used by tests to simulate mobile). Defaults
  /// to the current runtime platform.
  final PlatformCapabilities? capabilities;

  final VoidCallback? onLogout;
  final bool showHeader;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final PlatformCapabilities _capabilities;
  late final TextEditingController _diagnosticsUrlController;
  late final TextEditingController _controlServerController;
  late final TextEditingController _authTokenController;
  late final TextEditingController _networkIdController;
  late final TextEditingController _virtualIpController;
  late final TextEditingController _deviceNameController;
  late final TextEditingController _overlayCidrController;
  late final TextEditingController _tunInterfaceController;
  late final TextEditingController _mtuController;
  late final TextEditingController _udpBindController;
  late final TextEditingController _udpAdvertiseController;
  late final TextEditingController _relayServersController;

  String? _diagnosticsError;
  String? _formError;
  var _saving = false;
  var _manualMode = false;
  var _socketPool = defaultSocketPool;
  var _restartRequired = false;
  var _closeBehavior = defaultCloseBehavior;
  // Progressive-disclosure state. Advanced / Developer groups start collapsed;
  // the change-credential field starts hidden so the token input is not a
  // permanent fixture of the account section.
  var _showAdvancedNetwork = false;
  var _showDeveloper = false;
  var _showTokenField = false;

  void _updateState(VoidCallback fn) => setState(fn);

  @override
  void initState() {
    super.initState();
    _capabilities = widget.capabilities ?? PlatformCapabilities.current();
    final settings = widget.settingsStore.settings;
    _diagnosticsUrlController = TextEditingController(
      text: settings.diagnosticsUrl,
    );
    _controlServerController = TextEditingController(
      text: settings.controlServer,
    );
    // The token field is intentionally NOT prefilled with the stored token: the
    // settings UI must not display the credential. It starts empty; leaving it
    // empty on save (managed mode) preserves the current token, while
    // re-entering a value updates it. Clearing is a separate logout action.
    _authTokenController = TextEditingController();
    _networkIdController = TextEditingController(text: settings.networkId);
    _virtualIpController = TextEditingController(text: settings.virtualIp);
    _deviceNameController = TextEditingController(text: settings.deviceName);
    _overlayCidrController = TextEditingController(text: settings.overlayCidr);
    _tunInterfaceController = TextEditingController(
      text: settings.effectiveTunInterface,
    );
    _mtuController = TextEditingController(text: settings.mtu.toString());
    _udpBindController = TextEditingController(text: settings.udpBind);
    _udpAdvertiseController = TextEditingController(
      text: settings.udpAdvertise,
    );
    _relayServersController = TextEditingController(
      text: settings.relayServers,
    );
    _manualMode = settings.manualMode;
    _socketPool = normalizeSocketPool(settings.socketPool);
    _closeBehavior = normalizeCloseBehavior(settings.closeBehavior);
  }

  @override
  void dispose() {
    _diagnosticsUrlController.dispose();
    _controlServerController.dispose();
    _authTokenController.dispose();
    _networkIdController.dispose();
    _virtualIpController.dispose();
    _deviceNameController.dispose();
    _overlayCidrController.dispose();
    _tunInterfaceController.dispose();
    _mtuController.dispose();
    _udpBindController.dispose();
    _udpAdvertiseController.dispose();
    _relayServersController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.settingsStore,
      builder: (context, _) {
        final strings = AppStrings.fromCode(
          widget.settingsStore.settings.languageCode,
        );
        final languageCode = widget.settingsStore.settings.languageCode;
        final themeCode = widget.settingsStore.settings.themeMode;
        final theme = Theme.of(context);
        // Derived from the live store + current strings so a language switch
        // (or any other store update) re-renders the status correctly. The raw
        // token is never read back into a text field.
        final credentialState = _describeCredential(
          widget.settingsStore.settings,
          strings,
        );
        return PageScaffold(
          title: strings.settings,
          subtitle: strings.settingsSubtitle,
          showHeader: widget.showHeader,
          maxWidth: settingsPageMaxWidth,
          children: [
            if (_formError != null) ...[
              _ErrorBanner(message: _formError!),
              const SizedBox(height: 14),
            ],
            if (_restartRequired) ...[
              _PendingRestartNotice(
                busy: _saving || widget.statusStore.daemonBusy,
                canRestart: _capabilities.canControlLocalDaemon,
                onRestart: _restartDaemonToApply,
              ),
              const SizedBox(height: 14),
            ],
            _SettingsSection(
              title: strings.settingsSectionGeneral,
              children: [
                _SettingsTextField(
                  controller: _deviceNameController,
                  label: strings.deviceName,
                  helper: strings.deviceNameHelper,
                ),
                _gap,
                _SettingsRow(
                  label: strings.language,
                  subtitle: strings.languageHelper,
                  control: DropdownButtonFormField<String>(
                    key: ValueKey('language-$languageCode'),
                    initialValue: AppLanguage.fromCode(languageCode).code,
                    isExpanded: true,
                    decoration: InputDecoration(labelText: strings.language),
                    items: [
                      for (final language in AppLanguage.values)
                        DropdownMenuItem(
                          value: language.code,
                          child: Text(strings.languageLabel(language.code)),
                        ),
                    ],
                    onChanged: _saving
                        ? null
                        : (value) {
                            if (value != null) _saveLanguage(value);
                          },
                  ),
                ),
                _SettingsRow(
                  label: strings.themeMode,
                  subtitle: strings.themeModeHelper,
                  control: DropdownButtonFormField<String>(
                    key: ValueKey('theme-$themeCode'),
                    initialValue: AppThemeMode.fromCode(themeCode).code,
                    isExpanded: true,
                    decoration: InputDecoration(labelText: strings.themeMode),
                    items: [
                      DropdownMenuItem(
                        value: AppThemeMode.system.code,
                        child: Text(strings.themeSystem),
                      ),
                      DropdownMenuItem(
                        value: AppThemeMode.light.code,
                        child: Text(strings.themeLight),
                      ),
                      DropdownMenuItem(
                        value: AppThemeMode.dark.code,
                        child: Text(strings.themeDark),
                      ),
                    ],
                    onChanged: _saving
                        ? null
                        : (value) {
                            if (value != null) _saveThemeMode(value);
                          },
                  ),
                ),
                if (_capabilities.canUseSystemTray)
                  _SettingsRow(
                    label: strings.closeBehavior,
                    subtitle: strings.closeBehaviorHelper,
                    control: DropdownButtonFormField<String>(
                      key: ValueKey('close-behavior-$_closeBehavior'),
                      initialValue: _closeBehavior,
                      isExpanded: true,
                      decoration: InputDecoration(
                        labelText: strings.closeBehavior,
                      ),
                      items: [
                        DropdownMenuItem(
                          value: 'keep-running',
                          child: Text(strings.closeBehaviorKeepRunning),
                        ),
                        DropdownMenuItem(
                          value: 'stop-and-quit',
                          child: Text(strings.closeBehaviorStopAndQuit),
                        ),
                      ],
                      onChanged: _saving
                          ? null
                          : (value) {
                              if (value != null) {
                                setState(() => _closeBehavior = value);
                              }
                            },
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 18),
            _SettingsSection(
              title: strings.settingsSectionAccountNetwork,
              helper: strings.settingsSubtitleAccountNetwork,
              children: [
                _SettingsRow(
                  label: strings.credentialSectionTitle,
                  subtitle: credentialState,
                  control: TextButton.icon(
                    onPressed: _saving
                        ? null
                        : () => setState(
                            () => _showTokenField = !_showTokenField,
                          ),
                    icon: Icon(
                      _showTokenField ? Icons.expand_less : Icons.edit_outlined,
                      size: 16,
                    ),
                    label: Text(
                      _showTokenField
                          ? strings.hideCredential
                          : strings.changeCredential,
                    ),
                  ),
                ),
                if (_showTokenField) ...[
                  _SettingsTextField(
                    controller: _authTokenController,
                    label: strings.authToken,
                    helper: strings.credentialChangeHelper,
                    obscureText: true,
                  ),
                  _gap,
                ],
                _SettingsTextField(
                  controller: _controlServerController,
                  label: strings.controlServer,
                  helper: strings.isZh
                      ? '用户注册、设备认证和节点目录同步地址。'
                      : 'Used for account auth, device registration, and peer catalog sync.',
                  keyboardType: TextInputType.url,
                ),
                _gap,
                _SettingsTextField(
                  controller: _networkIdController,
                  label: strings.networkId,
                  helper: strings.isZh
                      ? '加入的专用虚拟内网标识。'
                      : 'Virtual network identifier to join.',
                ),
                _gap,
                _SettingsTextField(
                  controller: _virtualIpController,
                  label: strings.isZh ? '期望虚拟 IP' : 'Requested virtual IP',
                  helper: strings.isZh
                      ? '可选；留空由控制面自动分配，例如 10.20.0.42。保存后重启 P2WLAN 生效。'
                      : 'Optional; leave blank for control-plane assignment, e.g. 10.20.0.42. Restart P2WLAN after saving.',
                ),
                if (widget.onLogout != null) ...[
                  _gap,
                  Align(
                    alignment: Alignment.centerLeft,
                    child: OutlinedButton.icon(
                      onPressed: _saving ? null : widget.onLogout,
                      icon: const Icon(Icons.logout_outlined, size: 16),
                      label: Text(strings.signOut),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: theme.colorScheme.error,
                      ),
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 18),
            if (_capabilities.canActAsLocalVpnNode)
              _SettingsDisclosure(
                title: strings.settingsSectionAdvancedNetwork,
                subtitle: strings.advancedNetworkSubtitle,
                open: _showAdvancedNetwork,
                onToggle: () => setState(
                  () => _showAdvancedNetwork = !_showAdvancedNetwork,
                ),
                children: [
                  _SettingsRow(
                    label: strings.manualMode,
                    subtitle: strings.manualModeHelper,
                    control: Switch.adaptive(
                      value: _manualMode,
                      onChanged: _saving
                          ? null
                          : (value) => setState(() => _manualMode = value),
                    ),
                  ),
                  _ResponsiveFieldRow(
                    first: _SettingsTextField(
                      controller: _tunInterfaceController,
                      label: strings.interfaceName,
                      helper: defaultTunInterface,
                    ),
                    second: _SettingsTextField(
                      controller: _mtuController,
                      label: strings.mtu,
                      helper: strings.mtuHelper,
                      keyboardType: TextInputType.number,
                    ),
                  ),
                  _gap,
                  _SettingsTextField(
                    controller: _overlayCidrController,
                    label: strings.overlayCidr,
                    helper: defaultOverlayCidr,
                  ),
                  _gap,
                  _ResponsiveFieldRow(
                    first: _SettingsTextField(
                      controller: _udpBindController,
                      label: strings.udpBind,
                      helper: '0.0.0.0:0',
                    ),
                    second: _SettingsTextField(
                      controller: _udpAdvertiseController,
                      label: strings.udpAdvertise,
                      helper: strings.udpAdvertiseHelper,
                    ),
                  ),
                  _gap,
                  _SettingsRow(
                    label: strings.socketPool,
                    subtitle: strings.socketPoolHelper,
                    control: DropdownButtonFormField<String>(
                      key: ValueKey('socket-pool-$_socketPool'),
                      initialValue: _socketPool,
                      isExpanded: true,
                      decoration: InputDecoration(
                        labelText: strings.socketPool,
                      ),
                      items: const [
                        DropdownMenuItem(value: 'off', child: Text('off')),
                        DropdownMenuItem(value: '2', child: Text('2 sockets')),
                        DropdownMenuItem(value: '3', child: Text('3 sockets')),
                        DropdownMenuItem(value: '4', child: Text('4 sockets')),
                      ],
                      onChanged: _saving || widget.statusStore.daemonBusy
                          ? null
                          : (value) {
                              if (value != null) {
                                setState(() => _socketPool = value);
                              }
                            },
                    ),
                  ),
                  _SettingsTextField(
                    controller: _relayServersController,
                    label: strings.relayCandidates,
                    helper: strings.relayCandidatesHelper,
                  ),
                ],
              ),
            const SizedBox(height: 18),
            if (_capabilities.canControlLocalDaemon)
              _SettingsDisclosure(
                title: strings.settingsSectionDeveloperDiagnostics,
                subtitle: strings.developerSectionSubtitle,
                open: _showDeveloper,
                onToggle: () =>
                    setState(() => _showDeveloper = !_showDeveloper),
                children: [
                  _SettingsTextField(
                    controller: _diagnosticsUrlController,
                    label: strings.diagnosticsUrl,
                    hintText: defaultDiagnosticsUrl,
                    helper: strings.diagnosticsUrlHelper,
                    errorText: _diagnosticsError,
                    keyboardType: TextInputType.url,
                    onSubmitted: (_) => _saveAll(),
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 12,
                    runSpacing: 8,
                    children: [
                      OutlinedButton.icon(
                        onPressed: widget.statusStore.refreshing
                            ? null
                            : () => widget.statusStore.refresh(),
                        icon: const Icon(Icons.refresh, size: 16),
                        label: Text(strings.refreshNow),
                      ),
                      OutlinedButton.icon(
                        onPressed: _saving ? null : _resetDiagnosticsUrl,
                        icon: const Icon(Icons.restore, size: 16),
                        label: Text(strings.restoreDefaultUrl),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  const Divider(height: 24),
                  _SettingsRow(
                    label: strings.localService,
                    subtitle: strings.isZh
                        ? '诊断端点对应的本地 daemon。'
                        : 'Local daemon behind the diagnostics endpoint.',
                    control: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 8,
                          height: 8,
                          decoration: BoxDecoration(
                            color: widget.statusStore.daemonReachable
                                ? theme.colorScheme.primary
                                : theme.colorScheme.outline,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 6),
                        Text(
                          widget.statusStore.daemonReachable
                              ? strings.daemonRunning
                              : strings.daemonStopped,
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w500,
                            color: theme.colorScheme.onSurface,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: Text(
                      strings.localSettingsFile(
                        widget.settingsStore.configPath ?? '—',
                      ),
                      style: TextStyle(
                        fontSize: 12,
                        color: theme.colorScheme.onSurfaceVariant,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ),
                  if (widget.settingsStore.lastError != null) ...[
                    Text(
                      widget.settingsStore.lastError!,
                      style: const TextStyle(
                        fontSize: 12,
                        color: AppTokens.colorBadText,
                      ),
                    ),
                    const SizedBox(height: 8),
                  ],
                ],
              ),
            const SizedBox(height: 16),
            LayoutBuilder(
              builder: (context, constraints) {
                final narrow = constraints.maxWidth < 520;
                return Align(
                  alignment: narrow ? Alignment.center : Alignment.centerRight,
                  child: SizedBox(
                    width: narrow ? double.infinity : null,
                    child: FilledButton.icon(
                      key: const Key('settings-save-button'),
                      onPressed: _saving ? null : _saveAll,
                      icon: _saving
                          ? const SizedBox.square(
                              dimension: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.save_outlined, size: 16),
                      label: Text(
                        _restartRequired
                            ? strings.saveChangesRestartRequired
                            : strings.saveChanges,
                      ),
                    ),
                  ),
                );
              },
            ),
          ],
        );
      },
    );
  }

  static const _gap = SizedBox(height: 12);
}
