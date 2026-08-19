import 'package:flutter/material.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/api/diagnostics_api.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';

part 'settings_page/categories.dart';
part 'settings_page/common.dart';
part 'settings_page/layout.dart';
part 'settings_page/general.dart';
part 'settings_page/account.dart';
part 'settings_page/application.dart';
part 'settings_page/advanced.dart';
part 'settings_page/developer.dart';
part 'settings_page/actions.dart';

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
  var _showTokenField = false;

  /// Currently open category in the medium/compact root-detail layout.
  /// Null = the settings root. In the desktop rail layout it always maps to a
  /// concrete category (defaulting to the first visible one). Not persisted.
  SettingsCategory? _selectedCategory;

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
    // Live dirty detection: any controller edit triggers a rebuild so the
    // category save bar appears/disappears without needing an explicit submit.
    for (final controller in [
      _diagnosticsUrlController,
      _controlServerController,
      _authTokenController,
      _networkIdController,
      _virtualIpController,
      _deviceNameController,
      _overlayCidrController,
      _tunInterfaceController,
      _mtuController,
      _udpBindController,
      _udpAdvertiseController,
      _relayServersController,
    ]) {
      controller.addListener(_onDraftChanged);
    }
  }

  void _onDraftChanged() {
    if (!mounted) return;
    setState(() {});
  }

  @override
  void dispose() {
    for (final controller in [
      _diagnosticsUrlController,
      _controlServerController,
      _authTokenController,
      _networkIdController,
      _virtualIpController,
      _deviceNameController,
      _overlayCidrController,
      _tunInterfaceController,
      _mtuController,
      _udpBindController,
      _udpAdvertiseController,
      _relayServersController,
    ]) {
      controller.removeListener(_onDraftChanged);
    }
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

  /// Describes credential state for display without ever revealing the token.
  String _describeCredential(AppStrings strings) {
    final settings = widget.settingsStore.settings;
    if (settings.manualMode) {
      return strings.credentialManualMode;
    }
    return settings.authToken.trim().isEmpty
        ? strings.credentialNotSaved
        : strings.credentialSaved;
  }

  /// Short summary shown on a category row so the settings home answers "find
  /// a setting" without opening every detail.
  String _categorySummary(SettingsCategory category, AppStrings strings) {
    return switch (category) {
      SettingsCategory.general =>
        _deviceNameController.text.trim().isEmpty
            ? strings.credentialNotSaved
            : _deviceNameController.text.trim(),
      SettingsCategory.accountNetwork => _describeCredential(strings),
      SettingsCategory.application =>
        _closeBehavior == 'keep-running'
            ? strings.closeBehaviorKeepRunning
            : strings.closeBehaviorStopAndQuit,
      SettingsCategory.advancedNetwork =>
        _manualMode ? strings.manualMode : 'MTU ${_mtuController.text.trim()}',
      SettingsCategory.developer =>
        widget.statusStore.daemonReachable
            ? strings.daemonRunning
            : strings.daemonStopped,
    };
  }

  List<SettingsCategory> get _visibleCategories =>
      visibleSettingsCategories(_capabilities);

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([widget.settingsStore, widget.statusStore]),
      builder: (context, _) {
        final strings = AppStrings.fromCode(
          widget.settingsStore.settings.languageCode,
        );
        // Provide the page's own string scope so shared widgets (rows, save
        // bar, root, rail) resolve to the same locale as the page state, even
        // when the surrounding host scope differs.
        return AppStringsScope(strings: strings, child: _buildBody(strings));
      },
    );
  }

  Widget _buildBody(AppStrings strings) {
    final theme = Theme.of(context);
    final credentialState = _describeCredential(strings);
    final categories = _visibleCategories;
    final selected = _normalizeSelection(categories);
    return LayoutBuilder(
      builder: (context, constraints) {
        final layout = constraints.maxWidth >= _settingsSidebarBreakpoint
            ? _SettingsLayout.expanded
            : _SettingsLayout.rootDetail;
        return Padding(
          padding: const EdgeInsets.fromLTRB(
            AppTokens.space16,
            AppTokens.space12,
            AppTokens.space16,
            AppTokens.space16,
          ),
          child: Center(
            child: ConstrainedBox(
              constraints: BoxConstraints(maxWidth: settingsPageMaxWidth),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (widget.showHeader) ...[
                    Align(
                      alignment: Alignment.center,
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            strings.settings,
                            style: TextStyle(
                              fontSize: 22,
                              fontWeight: FontWeight.w600,
                              color: theme.colorScheme.onSurface,
                            ),
                          ),
                          const SizedBox(height: 3),
                          Text(
                            strings.settingsSubtitle,
                            style: TextStyle(
                              fontSize: 13,
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: AppTokens.space16),
                  ],
                  Expanded(
                    child: _SettingsShell(
                      layout: layout,
                      categories: categories,
                      selected: selected,
                      onSelect: (category) =>
                          _updateState(() => _selectedCategory = category),
                      onBack: () =>
                          _updateState(() => _selectedCategory = null),
                      strings: strings,
                      credentialState: credentialState,
                      state: this,
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  /// Resolves the currently effective category. In the desktop rail layout a
  /// null selection maps to the first visible category (default: General).
  SettingsCategory? _normalizeSelection(List<SettingsCategory> categories) {
    final selected = _selectedCategory;
    if (selected != null && categories.contains(selected)) return selected;
    return null;
  }
}
