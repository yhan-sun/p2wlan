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
        return _deviceNameController.text.trim() !=
                settings.deviceName.trim() ||
            (_capabilities.canUseSystemTray &&
                normalizeCloseBehavior(_closeBehavior) !=
                    normalizeCloseBehavior(settings.closeBehavior));
      case SettingsCategory.accountNetwork:
        // A non-empty token draft counts; an empty token field means "keep the
        // stored credential" and is not a change.
        return _authTokenController.text.trim().isNotEmpty ||
            _controlServerController.text.trim() !=
                settings.controlServer.trim() ||
            _networkIdController.text.trim() != settings.networkId.trim() ||
            _virtualIpController.text.trim() != settings.virtualIp.trim();
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
    if (_saving) return;
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    _updateState(() {
      _saving = true;
      // Only clear errors belonging to the category being saved. Other
      // categories' errors stay visible so the user can navigate back and
      // see what went wrong.
      if (category == SettingsCategory.developer) {
        _diagnosticsError = null;
      }
      if (_formErrorCategory == category) {
        _formError = null;
        _formErrorCategory = null;
      }
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
          if (_capabilities.canUseSystemTray) closeBehavior = _closeBehavior;
        case SettingsCategory.accountNetwork:
          controlServer = _controlServerController.text;
          authToken = _authTokenController.text;
          networkId = _networkIdController.text;
          virtualIp = _virtualIpController.text;
        case SettingsCategory.advancedNetwork:
          // Empty delegates credential preservation/clearing to SettingsStore:
          // managed mode preserves, manual mode clears.
          authToken = '';
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
          // Clear this category's errors on successful save.
          if (category == SettingsCategory.developer) {
            _diagnosticsError = null;
          }
          if (_formErrorCategory == category) {
            _formError = null;
            _formErrorCategory = null;
          }
        });
      }
      if (mounted) _resetCategory(category, afterSave: true);
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
          _formErrorCategory = category;
        }
      });
      _showSnackBar(
        message.startsWith('Diagnostics URL')
            ? strings.diagnosticsUrlNotSaved
            : strings.failedToSaveLocalSettings,
      );
    } catch (error) {
      _updateState(() {
        _formError = strings.settingsSaveFailed;
        _formErrorCategory = category;
      });
      _showSnackBar(strings.failedToSaveLocalSettings);
    } finally {
      if (mounted) {
        _updateState(() => _saving = false);
        _notifyDirty();
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
        _showSnackBar(strings.tunnelRestartFailed);
        return;
      }
      final started = await widget.statusStore.startDaemon();
      if (!started.ok) {
        _showSnackBar(strings.tunnelRestartFailed);
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
        before.overlayCidr != after.overlayCidr ||
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

  Future<void> _checkForUpdates() async {
    if (_checkingForUpdates) return;
    _updateState(() {
      _checkingForUpdates = true;
      _updateCheckResult = null;
    });
    try {
      final result = await _updateService.check();
      if (mounted) _updateState(() => _updateCheckResult = result);
    } catch (_) {
      if (mounted) {
        _updateState(
          () => _updateCheckResult = UpdateCheckResult(
            status: UpdateCheckStatus.networkError,
            currentAppVersion: ClientBuildInfo.current.appVersion,
            error: const UpdateCheckError(
              UpdateCheckErrorCode.transport,
              'The release request failed.',
            ),
          ),
        );
      }
    } finally {
      if (mounted) _updateState(() => _checkingForUpdates = false);
    }
  }

  Future<void> _openUpdateRelease(UpdateCheckResult result) async {
    final update = result.update;
    if (update == null) return;
    final opened = await _updateService.openRelease(update);
    if (!opened && mounted) {
      final strings = AppStrings.fromCode(
        widget.settingsStore.settings.languageCode,
      );
      showAppNotice(context, content: Text(strings.updateOpenFailed));
    }
  }

  Future<void> _uploadCurrentSessionLogs() async {
    if (_uploadingLogs) return;
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    final settings = widget.settingsStore.settings;
    final authToken = settings.authToken.trim();
    if (settings.manualMode ||
        authToken.isEmpty ||
        isAuthTokenExpired(authToken)) {
      _showSnackBar(strings.logsUploadRequiresLogin);
      return;
    }

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(strings.uploadLogsTitle),
        content: Text(strings.uploadLogsBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(strings.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(strings.uploadLogsConfirm),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    _updateState(() {
      _uploadingLogs = true;
      _logUploadError = null;
    });
    try {
      final parallel = widget.statusStore.parallelRooms;
      final activeRoomProfileIds = parallel.supportLogProfileCandidates;
      final dynamicSummaries = parallel.exportStatusSummaries();
      final bundle = await CurrentSessionLogBundle.collectCurrentStartup(
        activeRoomProfileIds: activeRoomProfileIds,
        dynamicSummaries: dynamicSummaries,
      );
      final result = await _controlApi.uploadSupportLogs(
        controlServer: settings.controlServer,
        authToken: authToken,
        deviceName: settings.deviceName,
        clientBuild: ClientBuildInfo.current,
        daemonBuild: widget.statusStore.daemonController.lastDaemonBuildInfo,
        files: bundle.files,
        omittedRoomProfileIds: bundle.omittedRoomProfileIds,
      );
      if (mounted) {
        final message = result.instances > 1
            ? '${strings.logsUploaded(result.uploadId)} (${result.instances} 个实例)'
            : strings.logsUploaded(result.uploadId);
        _showSnackBar(message);
      }
    } catch (error) {
      if (mounted) {
        _updateState(() => _logUploadError = error.toString());
        _showSnackBar(strings.logsUploadFailed);
      }
    } finally {
      if (mounted) _updateState(() => _uploadingLogs = false);
    }
  }

  Future<void> _saveLanguage(String languageCode) async {
    await _saveImmediate(
      'language',
      () => widget.settingsStore.updateLanguageCode(languageCode),
    );
  }

  Future<void> _saveThemeMode(String themeMode) async {
    await _saveImmediate(
      'theme',
      () => widget.settingsStore.updateThemeMode(themeMode),
    );
  }

  Future<void> _saveImmediate(
    String preference,
    Future<void> Function() save,
  ) async {
    if (_saving) return;
    _updateState(() {
      _saving = true;
      _immediateSaved = null;
      _immediateError = null;
    });
    try {
      await save();
      _updateState(() => _immediateSaved = preference);
    } catch (_) {
      _updateState(
        () => _immediateError = AppStrings.fromCode(
          widget.settingsStore.settings.languageCode,
        ).failedToSaveLocalSettings,
      );
    } finally {
      _updateState(() => _saving = false);
    }
  }

  bool _draftNeedsRestart(SettingsCategory category) {
    if (!widget.statusStore.daemonReachable || !_categoryDirty(category)) {
      return false;
    }
    if (category == SettingsCategory.general) {
      return _deviceNameController.text.trim() !=
          widget.settingsStore.settings.deviceName.trim();
    }
    return category == SettingsCategory.accountNetwork ||
        category == SettingsCategory.advancedNetwork;
  }

  /// Discard only this category. Immediate preferences and other drafts survive.
  void _resetCategory(SettingsCategory category, {bool afterSave = false}) {
    if (_saving && !afterSave) return;
    final saved = widget.settingsStore.settings;
    switch (category) {
      case SettingsCategory.general:
        _deviceNameController.text = saved.deviceName;
        _closeBehavior = saved.closeBehavior;
      case SettingsCategory.accountNetwork:
        _authTokenController.clear();
        _controlServerController.text = saved.controlServer;
        _networkIdController.text = saved.networkId;
        _virtualIpController.text = saved.virtualIp;
      case SettingsCategory.advancedNetwork:
        _manualMode = saved.manualMode;
        _socketPool = saved.socketPool;
        _tunInterfaceController.text = saved.effectiveTunInterface;
        _mtuController.text = saved.mtu.toString();
        _overlayCidrController.text = saved.overlayCidr;
        _udpBindController.text = saved.udpBind;
        _udpAdvertiseController.text = saved.udpAdvertise;
        _relayServersController.text = saved.relayServers;
      case SettingsCategory.developer:
        _diagnosticsUrlController.text = saved.diagnosticsUrl;
        _diagnosticsError = null;
    }
    _updateState(() {
      if (_formErrorCategory == category) {
        _formError = null;
        _formErrorCategory = null;
      }
    });
    _notifyDirty();
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    showAppNotice(context, content: Text(message));
  }
}
