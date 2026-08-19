part of '../settings_page.dart';

extension _SettingsPageActions on _SettingsPageState {
  /// Whether the given category currently has edits that differ from the
  /// persisted values. Language / theme are immediate-save and never count as
  /// dirty. Values are normalized (trimmed, int MTU, normalized pool/behavior)
  /// so a pure-space or equivalent normalized value never shows Save forever.
  bool _categoryDirty(SettingsCategory category) {
    final settings = widget.settingsStore.settings;
    switch (category) {
      case SettingsCategory.general:
        return _deviceNameController.text.trim() != settings.deviceName.trim();
      case SettingsCategory.accountNetwork:
        // A non-empty token draft counts; an empty token field means "keep the
        // stored credential" and is not a change.
        return _authTokenController.text.trim().isNotEmpty ||
            _controlServerController.text.trim() !=
                settings.controlServer.trim() ||
            _networkIdController.text.trim() != settings.networkId.trim() ||
            _virtualIpController.text.trim() != settings.virtualIp.trim();
      case SettingsCategory.application:
        return normalizeCloseBehavior(_closeBehavior) !=
            normalizeCloseBehavior(settings.closeBehavior);
      case SettingsCategory.advancedNetwork:
        final mtuText = _mtuController.text.trim();
        return _manualMode != settings.manualMode ||
            _overlayCidrController.text.trim() != settings.overlayCidr.trim() ||
            _tunInterfaceController.text.trim() !=
                settings.effectiveTunInterface.trim() ||
            int.tryParse(mtuText) != settings.mtu ||
            _udpBindController.text.trim() != settings.udpBind.trim() ||
            _udpAdvertiseController.text.trim() !=
                settings.udpAdvertise.trim() ||
            normalizeSocketPool(_socketPool) !=
                normalizeSocketPool(settings.socketPool) ||
            _relayServersController.text.trim() != settings.relayServers.trim();
      case SettingsCategory.developer:
        final draft = _normalizedUrl(_diagnosticsUrlController.text);
        final saved = _normalizedUrl(settings.diagnosticsUrl);
        return draft != saved;
    }
  }

  /// Normalized diagnostics URL, or null when the draft is invalid (an invalid
  /// draft is treated as dirty rather than crashing the dirty check).
  String? _normalizedUrl(String raw) {
    try {
      return normalizeDiagnosticsUrl(raw);
    } catch (_) {
      return null;
    }
  }

  /// Saves only the selected category's drafts on top of the currently
  /// persisted values. Other categories' drafts stay untouched in their
  /// controllers, so a General save can never be blocked by a pending
  /// Diagnostics URL edit or clobber another category's in-progress changes.
  Future<void> _saveCategory(SettingsCategory category) async {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    _updateState(() {
      _saving = true;
      _diagnosticsError = null;
      _formError = null;
    });
    try {
      final current = widget.settingsStore.settings;
      final daemonWasRunning = widget.statusStore.daemonReachable;

      var diagnosticsUrl = current.diagnosticsUrl;
      var controlServer = current.controlServer;
      var authToken = current.authToken;
      var networkId = current.networkId;
      var virtualIp = current.virtualIp;
      var deviceName = current.deviceName;
      var manualMode = current.manualMode;
      var overlayCidr = current.overlayCidr;
      var tunInterface = current.tunInterface;
      var mtu = current.mtu;
      var udpBind = current.udpBind;
      var udpAdvertise = current.udpAdvertise;
      var socketPool = current.socketPool;
      var relayServers = current.relayServers;
      var closeBehavior = current.closeBehavior;

      switch (category) {
        case SettingsCategory.general:
          deviceName = _deviceNameController.text;
        case SettingsCategory.accountNetwork:
          controlServer = _controlServerController.text;
          authToken = _authTokenController.text;
          networkId = _networkIdController.text;
          virtualIp = _virtualIpController.text;
        case SettingsCategory.application:
          closeBehavior = _closeBehavior;
        case SettingsCategory.advancedNetwork:
          manualMode = _manualMode;
          overlayCidr = _overlayCidrController.text;
          tunInterface = _tunInterfaceController.text;
          mtu = int.tryParse(_mtuController.text.trim()) ?? defaultMtu;
          udpBind = _udpBindController.text;
          udpAdvertise = _udpAdvertiseController.text;
          socketPool = _socketPool;
          relayServers = _relayServersController.text;
        case SettingsCategory.developer:
          diagnosticsUrl = _diagnosticsUrlController.text;
      }

      // The running-daemon guard stays: changing the Diagnostics URL while the
      // daemon is running must be blocked with a clear, human-readable message.
      if (daemonWasRunning &&
          category == SettingsCategory.developer &&
          normalizeDiagnosticsUrl(diagnosticsUrl) !=
              normalizeDiagnosticsUrl(current.diagnosticsUrl)) {
        throw const FormatException(
          'Stop P2WLAN before changing the Diagnostics URL.',
        );
      }

      await widget.settingsStore.updateConnectionSettings(
        diagnosticsUrl: diagnosticsUrl,
        controlServer: controlServer,
        authToken: authToken,
        networkId: networkId,
        virtualIp: virtualIp,
        deviceName: deviceName,
        manualMode: manualMode,
        overlayCidr: overlayCidr,
        tunInterface: tunInterface,
        mtu: mtu,
        udpBind: udpBind,
        udpAdvertise: udpAdvertise,
        socketPool: socketPool,
        relayServers: relayServers,
        closeBehavior: closeBehavior,
      );
      final restartRequiredNow =
          daemonWasRunning &&
          _daemonLaunchSettingsChanged(current, widget.settingsStore.settings);
      await widget.statusStore.refresh();
      if (mounted) {
        _updateState(() {
          // A pending restart must survive unrelated saves: once a
          // daemon-launch setting changed while the daemon was running, it
          // stays sticky until the daemon is actually restarted.
          _restartRequired = _restartRequired || restartRequiredNow;
        });
      }
      _showSnackBar(
        _restartRequired
            ? strings.settingsSavedRestartRequired
            : strings.diagnosticsUrlSaved,
      );
    } on FormatException catch (error) {
      final message = error.message;
      _updateState(() {
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
      _updateState(() => _formError = strings.settingsSaveFailed);
      _showSnackBar(strings.failedToSaveLocalSettings);
    } finally {
      if (mounted) {
        _updateState(() => _saving = false);
      }
    }
  }

  Future<void> _restartDaemonToApply() async {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    _updateState(() => _saving = true);
    try {
      final stopped = await widget.statusStore.stopDaemon();
      if (!stopped.ok) {
        _showSnackBar(stopped.message);
        return;
      }
      final started = await widget.statusStore.startDaemon();
      if (!started.ok) {
        _showSnackBar(started.message);
        return;
      }
      if (mounted) _updateState(() => _restartRequired = false);
      _showSnackBar(strings.settingsApplied);
    } finally {
      if (mounted) _updateState(() => _saving = false);
    }
  }

  bool _daemonLaunchSettingsChanged(AppSettings before, AppSettings after) {
    return before.controlServer != after.controlServer ||
        before.authToken != after.authToken ||
        before.networkId != after.networkId ||
        before.virtualIp != after.virtualIp ||
        before.deviceName != after.deviceName ||
        before.manualMode != after.manualMode ||
        before.tunInterface != after.tunInterface ||
        before.mtu != after.mtu ||
        before.udpBind != after.udpBind ||
        before.udpAdvertise != after.udpAdvertise ||
        before.socketPool != after.socketPool ||
        before.relayServers != after.relayServers;
  }

  Future<void> _resetDiagnosticsUrl() async {
    _diagnosticsUrlController.text = defaultDiagnosticsUrl;
    await _saveCategory(SettingsCategory.developer);
  }

  Future<void> _saveLanguage(String languageCode) async {
    _updateState(() => _saving = true);
    try {
      await widget.settingsStore.updateLanguageCode(languageCode);
      _showSnackBar(AppStrings.fromCode(languageCode).languageSaved);
    } finally {
      if (mounted) _updateState(() => _saving = false);
    }
  }

  Future<void> _saveThemeMode(String themeMode) async {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    _updateState(() => _saving = true);
    try {
      await widget.settingsStore.updateThemeMode(themeMode);
      _showSnackBar(strings.themeSaved);
    } finally {
      if (mounted) _updateState(() => _saving = false);
    }
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }
}
