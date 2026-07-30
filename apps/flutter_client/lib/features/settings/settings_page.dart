import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final TextEditingController _diagnosticsUrlController;
  late final TextEditingController _controlServerController;
  late final TextEditingController _authTokenController;
  late final TextEditingController _networkIdController;
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
  var _closeBehavior = defaultCloseBehavior;

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
    _authTokenController = TextEditingController(text: settings.authToken);
    _networkIdController = TextEditingController(text: settings.networkId);
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
          children: [
            if (_formError != null) ...[
              _ErrorBanner(message: _formError!),
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
                    helper: strings.authTokenHelper,
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
                  Row(
                    children: [
                      Expanded(
                        child: _SettingsTextField(
                          controller: _tunInterfaceController,
                          label: strings.isZh ? '网卡设备名称' : 'Interface name',
                          helper: defaultTunInterface,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: _SettingsTextField(
                          controller: _mtuController,
                          label: 'MTU',
                          helper: strings.isZh
                              ? '建议 1420；Relay 路径异常时可尝试 1280。'
                              : '1420 is recommended; try 1280 for relay path issues.',
                          keyboardType: TextInputType.number,
                        ),
                      ),
                    ],
                  ),
                  _gap,
                  _SettingsTextField(
                    controller: _overlayCidrController,
                    label: 'Overlay CIDR',
                    helper: defaultOverlayCidr,
                  ),
                  _gap,
                  Row(
                    children: [
                      Expanded(
                        child: _SettingsTextField(
                          controller: _udpBindController,
                          label: strings.isZh ? 'UDP 监听地址' : 'UDP bind',
                          helper: '0.0.0.0:0',
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: _SettingsTextField(
                          controller: _udpAdvertiseController,
                          label: strings.isZh ? '公网 UDP 地址' : 'UDP advertise',
                          helper: strings.isZh
                              ? '云主机固定入口，例如 203.0.113.10:60207。'
                              : 'Fixed cloud endpoint such as 203.0.113.10:60207.',
                        ),
                      ),
                    ],
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
                  RadioGroup<String>(
                    groupValue: _closeBehavior,
                    onChanged: (value) {
                      if (!_saving && value != null) {
                        setState(() => _closeBehavior = value);
                      }
                    },
                    child: Column(
                      children: [
                        Material(
                          type: MaterialType.transparency,
                          child: RadioListTile<String>(
                            contentPadding: EdgeInsets.zero,
                            value: 'keep-running',
                            enabled: !_saving,
                            title: Text(
                              strings.isZh ? '后台静默运行' : 'Keep running',
                            ),
                            subtitle: Text(
                              strings.isZh
                                  ? '关闭主窗口时隐藏到系统托盘，不中断虚拟内网。'
                                  : 'Close hides the window to tray without stopping the tunnel.',
                            ),
                          ),
                        ),
                        Material(
                          type: MaterialType.transparency,
                          child: RadioListTile<String>(
                            contentPadding: EdgeInsets.zero,
                            value: 'stop-and-quit',
                            enabled: !_saving,
                            title: Text(
                              strings.isZh ? '完全停止并退出' : 'Stop and quit',
                            ),
                            subtitle: Text(
                              strings.isZh
                                  ? '退出时先停止 daemon 并清理 TUN/路由。'
                                  : 'Quit stops the daemon and cleans up TUN/routes first.',
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 24),
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
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
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
            ),
          ],
        );
      },
    );
  }

  static const _gap = SizedBox(height: 12);

  Future<void> _saveAll() async {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    setState(() {
      _saving = true;
      _diagnosticsError = null;
      _formError = null;
    });
    try {
      final mtu = int.tryParse(_mtuController.text.trim()) ?? defaultMtu;
      final deviceName = _deviceNameController.text.trim().isEmpty
          ? await resolveDefaultDeviceName()
          : _deviceNameController.text.trim();
      await widget.settingsStore.updateConnectionSettings(
        diagnosticsUrl: _diagnosticsUrlController.text,
        controlServer: _controlServerController.text,
        authToken: _authTokenController.text,
        networkId: _networkIdController.text,
        deviceName: deviceName,
        manualMode: _manualMode,
        overlayCidr: _overlayCidrController.text,
        tunInterface: _tunInterfaceController.text,
        mtu: mtu,
        udpBind: _udpBindController.text,
        udpAdvertise: _udpAdvertiseController.text,
        socketPool: _socketPool,
        relayServers: _relayServersController.text,
        closeBehavior: _closeBehavior,
      );
      await widget.statusStore.refresh();
      _showSnackBar(strings.diagnosticsUrlSaved);
    } on FormatException catch (error) {
      final message = error.message;
      setState(() {
        if (message.startsWith('Diagnostics URL')) {
          _diagnosticsError = strings.diagnosticsUrlError(message);
        } else {
          _formError = message;
        }
      });
      _showSnackBar(
        message.startsWith('Diagnostics URL')
            ? strings.diagnosticsUrlNotSaved
            : strings.failedToSaveLocalSettings,
      );
    } catch (error) {
      setState(() => _formError = error.toString());
      _showSnackBar(strings.failedToSaveLocalSettings);
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
  }

  Future<void> _resetDiagnosticsUrl() async {
    _diagnosticsUrlController.text = defaultDiagnosticsUrl;
    await _saveAll();
  }

  Future<void> _saveLanguage(String languageCode) async {
    setState(() => _saving = true);
    try {
      await widget.settingsStore.updateLanguageCode(languageCode);
      _showSnackBar(AppStrings.fromCode(languageCode).languageSaved);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _saveThemeMode(String themeMode) async {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    setState(() => _saving = true);
    try {
      await widget.settingsStore.updateThemeMode(themeMode);
      _showSnackBar(strings.themeSaved);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }
}

class _SettingsTextField extends StatelessWidget {
  const _SettingsTextField({
    required this.controller,
    required this.label,
    required this.helper,
    this.keyboardType,
    this.obscureText = false,
  });

  final TextEditingController controller;
  final String label;
  final String helper;
  final TextInputType? keyboardType;
  final bool obscureText;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      keyboardType: keyboardType,
      obscureText: obscureText,
      decoration: InputDecoration(labelText: label, helperText: helper),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: AppTokens.colorBadBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: AppTokens.colorBadBorder),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Text(
          message,
          style: const TextStyle(
            color: AppTokens.colorBadText,
            fontSize: 13,
            height: 1.35,
          ),
        ),
      ),
    );
  }
}
