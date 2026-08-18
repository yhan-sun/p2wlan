import 'package:flutter/material.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/api/diagnostics_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';

part 'settings_page/widgets.dart';
part 'settings_page/actions.dart';

/// Describes credential state for display without ever revealing the token.
String _describeCredential(AppSettings settings) {
  if (settings.manualMode) {
    return 'Manual / offline mode (no control token needed)';
  }
  return settings.authToken.trim().isEmpty
      ? 'No control token stored — sign in to authenticate'
      : 'Control token stored';
}

class SettingsPage extends StatefulWidget {
  const SettingsPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.onLogout,
    this.showHeader = true,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final VoidCallback? onLogout;
  final bool showHeader;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
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
  // Human-readable credential status (e.g. "valid" / "missing"). The raw token
  // is never shown; this only describes whether one is stored.
  late String _credentialState;

  void _updateState(VoidCallback fn) => setState(fn);

  @override
  void initState() {
    super.initState();
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
    _credentialState = _describeCredential(settings);
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
                onRestart: _restartDaemonToApply,
              ),
              const SizedBox(height: 14),
            ],
            AppPanel(
              title: strings.diagnosticsEndpoint,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: _diagnosticsUrlController,
                    decoration: InputDecoration(
                      labelText: strings.diagnosticsUrl,
                      hintText: defaultDiagnosticsUrl,
                      helperText: strings.diagnosticsUrlHelper,
                      errorText: _diagnosticsError,
                    ),
                    keyboardType: TextInputType.url,
                    onSubmitted: (_) => _saveAll(),
                  ),
                  const SizedBox(height: 12),
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
                ],
              ),
            ),
            const SizedBox(height: 14),
            AppPanel(
              title: strings.connectionSettings,
              child: Column(
                children: [
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
                    controller: _authTokenController,
                    label: strings.authToken,
                    helper: '${strings.authTokenHelper} · $_credentialState',
                    obscureText: true,
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
                  _gap,
                  _SettingsTextField(
                    controller: _deviceNameController,
                    label: strings.deviceName,
                    helper: strings.isZh
                        ? '留空保存时会使用当前主机名。'
                        : 'If left empty, the current hostname is used.',
                  ),
                  Material(
                    type: MaterialType.transparency,
                    child: SwitchListTile.adaptive(
                      contentPadding: EdgeInsets.zero,
                      value: _manualMode,
                      onChanged: _saving
                          ? null
                          : (value) => setState(() => _manualMode = value),
                      title: Text(strings.manualMode),
                      subtitle: Text(strings.manualModeHelper),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
            AppPanel(
              title: strings.isZh ? '网络与隧道' : 'Network and Tunnel',
              child: Column(
                children: [
                  _ResponsiveFieldRow(
                    first: _SettingsTextField(
                      controller: _tunInterfaceController,
                      label: strings.isZh ? '网卡设备名称' : 'Interface name',
                      helper: defaultTunInterface,
                    ),
                    second: _SettingsTextField(
                      controller: _mtuController,
                      label: 'MTU',
                      helper: strings.isZh
                          ? '建议 1420；Relay 路径异常时可尝试 1280。'
                          : '1420 is recommended; try 1280 for relay path issues.',
                      keyboardType: TextInputType.number,
                    ),
                  ),
                  _gap,
                  _SettingsTextField(
                    controller: _overlayCidrController,
                    label: 'Overlay CIDR',
                    helper: defaultOverlayCidr,
                  ),
                  _gap,
                  _ResponsiveFieldRow(
                    first: _SettingsTextField(
                      controller: _udpBindController,
                      label: strings.isZh ? 'UDP 监听地址' : 'UDP bind',
                      helper: '0.0.0.0:0',
                    ),
                    second: _SettingsTextField(
                      controller: _udpAdvertiseController,
                      label: strings.isZh ? '公网 UDP 地址' : 'UDP advertise',
                      helper: strings.isZh
                          ? '云主机固定入口，例如 203.0.113.10:60207。'
                          : 'Fixed cloud endpoint such as 203.0.113.10:60207.',
                    ),
                  ),
                  _gap,
                  DropdownButtonFormField<String>(
                    initialValue: _socketPool,
                    decoration: InputDecoration(
                      labelText: strings.isZh
                          ? '增强打洞 socket pool'
                          : 'Socket pool',
                      helperText: strings.isZh
                          ? '困难 NAT 下增加受控 UDP 映射，推荐 3。'
                          : 'Adds bounded UDP mappings for hard NATs; 3 is recommended.',
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
                  _gap,
                  _SettingsTextField(
                    controller: _relayServersController,
                    label: strings.isZh ? 'Relay 候选' : 'Relay candidates',
                    helper: strings.isZh
                        ? '可选，逗号分隔，格式 region@ip:port 或 ip:port。'
                        : 'Optional comma-separated region@ip:port or ip:port entries.',
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
            AppPanel(
              title: strings.isZh ? '系统与行为' : 'System Behavior',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  DropdownButtonFormField<String>(
                    initialValue: AppLanguage.fromCode(
                      widget.settingsStore.settings.languageCode,
                    ).code,
                    decoration: InputDecoration(
                      labelText: strings.language,
                      helperText: strings.languageHelper,
                    ),
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
                  _gap,
                  DropdownButtonFormField<String>(
                    initialValue: AppThemeMode.fromCode(
                      widget.settingsStore.settings.themeMode,
                    ).code,
                    decoration: InputDecoration(
                      labelText: strings.themeMode,
                      helperText: strings.themeModeHelper,
                    ),
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
                ],
              ),
            ),
            const SizedBox(height: 14),
            AppPanel(
              title: strings.daemonControl,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    strings.daemonControlText,
                    style: const TextStyle(
                      fontSize: 13,
                      color: AppTokens.colorTextSecondary,
                      height: 1.4,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    strings.localSettingsFile(
                      widget.settingsStore.configPath ?? '—',
                    ),
                    style: const TextStyle(
                      fontSize: 12,
                      color: AppTokens.colorTextMuted,
                      fontFeatures: AppTokens.tabularFontFeatures,
                    ),
                  ),
                  if (widget.settingsStore.lastError != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      widget.settingsStore.lastError!,
                      style: const TextStyle(
                        fontSize: 12,
                        color: AppTokens.colorBadText,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                if (widget.onLogout != null)
                  OutlinedButton.icon(
                    onPressed: _saving ? null : widget.onLogout,
                    icon: const Icon(Icons.logout_outlined, size: 16),
                    label: Text(strings.isZh ? '退出登录' : 'Sign out'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppTokens.colorBadText,
                    ),
                  )
                else
                  const SizedBox.shrink(),
                FilledButton.icon(
                  key: const Key('settings-save-button'),
                  onPressed: _saving ? null : _saveAll,
                  icon: _saving
                      ? const SizedBox.square(
                          dimension: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.save_outlined, size: 16),
                  label: Text(strings.save),
                ),
              ],
            ),
          ],
        );
      },
    );
  }

  static const _gap = SizedBox(height: 12);
}
