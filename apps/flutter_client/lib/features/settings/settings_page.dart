import 'package:flutter/material.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/api/control_api.dart';
import '../../core/api/diagnostics_api.dart';
import '../../core/build_info.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/diagnostics/session_log_bundle.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/widgets/app_select.dart';

part 'settings_page/categories.dart';
part 'settings_page/common.dart';
part 'settings_page/layout.dart';
part 'settings_page/general.dart';
part 'settings_page/account.dart';
part 'settings_page/application.dart';
part 'settings_page/advanced.dart';
part 'settings_page/developer.dart';
part 'settings_page/actions.dart';

/// Lets the app shell unwind Settings' medium-width in-place root/detail
/// navigation before handling a system back gesture as product-level
/// navigation.
///
/// Compact mobile details use a real Navigator route and therefore unwind
/// natively before this controller is consulted. Unsaved drafts remain owned
/// by the still-mounted Settings page state behind that route.
class SettingsPageController {
  bool Function()? _backHandler;

  bool maybeGoBack() => _backHandler?.call() ?? false;

  void _attach(bool Function() handler) => _backHandler = handler;

  void _detach(bool Function() handler) {
    if (_backHandler == handler) _backHandler = null;
  }
}

class SettingsPage extends StatefulWidget {
  const SettingsPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.capabilities,
    this.controlApi,
    this.onLogout,
    this.onDirtyChanged,
    this.controller,
    this.showHeader = true,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  /// Platform capability override (used by tests to simulate mobile). Defaults
  /// to the current runtime platform.
  final PlatformCapabilities? capabilities;

  /// Optional auth client override used by tests and embedded shells. When
  /// omitted, the page owns a short-lived client for support-log uploads.
  final ControlApi? controlApi;

  final VoidCallback? onLogout;

  /// Notifies the host shell when the page transitions between clean and dirty
  /// (any category has unsaved drafts). The shell uses this to guard against
  /// silently losing settings when the user navigates away.
  final ValueChanged<bool>? onDirtyChanged;

  final SettingsPageController? controller;

  final bool showHeader;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final PlatformCapabilities _capabilities;
  late final ControlApi _controlApi;
  late final bool _ownsControlApi;
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
  SettingsCategory? _formErrorCategory;
  var _saving = false;
  var _manualMode = false;
  var _socketPool = defaultSocketPool;
  var _restartRequired = false;
  var _closeBehavior = defaultCloseBehavior;
  var _showTokenField = false;
  var _uploadingLogs = false;
  String? _logUploadError;

  /// Rebuilds a full-screen mobile category route when draft-only state
  /// changes. Settings/status stores and text controllers have their own
  /// listenables; toggles and async busy/error state flow through this one.
  final _detailViewNotifier = ValueNotifier<int>(0);

  /// Currently open category in the medium-width root-detail layout.
  /// Null = the settings root. In the desktop rail layout it always maps to a
  /// concrete category (defaulting to the first visible one). Not persisted.
  SettingsCategory? _selectedCategory;

  /// Width of the last rendered Settings body. It is read only for a system
  /// back request so desktop's persistent category rail is never mistaken for
  /// a pushed detail page.
  var _lastLayoutWidth = double.infinity;

  void _updateState(VoidCallback fn) {
    if (!mounted) return;
    setState(fn);
    _detailViewNotifier.value += 1;
  }

  @override
  void initState() {
    super.initState();
    _capabilities = widget.capabilities ?? PlatformCapabilities.current();
    _ownsControlApi = widget.controlApi == null;
    _controlApi = widget.controlApi ?? ControlApi();
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
    widget.controller?._attach(_handleBackRequest);
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
    // Notify the host shell of the initial dirty state (always false on init).
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _notifyDirty();
    });
  }

  @override
  void didUpdateWidget(covariant SettingsPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller?._detach(_handleBackRequest);
      widget.controller?._attach(_handleBackRequest);
    }
  }

  void _onDraftChanged() {
    if (!mounted) return;
    _notifyDirty();
    _updateState(() {});
  }

  bool _lastNotifiedDirty = false;

  void _notifyDirty() {
    final dirty = _anyCategoryDirty;
    if (dirty != _lastNotifiedDirty) {
      _lastNotifiedDirty = dirty;
      widget.onDirtyChanged?.call(dirty);
    }
  }

  /// True when any visible category has unsaved drafts (excludes immediate-save
  /// language/theme which never count as dirty).
  bool get _anyCategoryDirty {
    for (final category in _visibleCategories) {
      if (_categoryDirty(category)) return true;
    }
    return false;
  }

  @override
  void dispose() {
    widget.controller?._detach(_handleBackRequest);
    if (_ownsControlApi) _controlApi.close();
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
    _detailViewNotifier.dispose();
    super.dispose();
  }

  bool _handleBackRequest() {
    if (!mounted ||
        _lastLayoutWidth >= _settingsSidebarBreakpoint ||
        _selectedCategory == null) {
      return false;
    }
    _updateState(() => _selectedCategory = null);
    return true;
  }

  Future<void> _openMobileCategory(SettingsCategory category) async {
    await Navigator.of(context, rootNavigator: true).push<void>(
      MaterialPageRoute<void>(
        settings: RouteSettings(name: '/settings/${category.name}'),
        builder: (_) =>
            _MobileSettingsCategoryPage(category: category, state: this),
      ),
    );
    // The route edits the same controllers/state as this page. Refresh the
    // root summaries after returning without manufacturing an in-page detail.
    if (mounted) _updateState(() {});
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
        _lastLayoutWidth = constraints.maxWidth;
        final isNarrow = constraints.maxWidth < 520;
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
                      alignment: isNarrow
                          ? Alignment.center
                          : Alignment.centerLeft,
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: isNarrow
                            ? CrossAxisAlignment.center
                            : CrossAxisAlignment.start,
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
                            textAlign: isNarrow
                                ? TextAlign.center
                                : TextAlign.left,
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
                      onSelect: (category) {
                        if (layout == _SettingsLayout.rootDetail &&
                            !_capabilities.canUseSystemTray) {
                          _openMobileCategory(category);
                        } else {
                          _updateState(() => _selectedCategory = category);
                        }
                      },
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
