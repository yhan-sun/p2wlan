part of '../settings_page.dart';

extension _SettingsPageActions on _SettingsPageState {
  Future<void> _saveAll() async {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    _updateState(() {
      _saving = true;
      _diagnosticsError = null;
      _formError = null;
    });
    try {
      final currentSettings = widget.settingsStore.settings;
      final daemonWasRunning = widget.statusStore.daemonReachable;
      final nextDiagnosticsUrl = normalizeDiagnosticsUrl(
        _diagnosticsUrlController.text,
      );
      if (daemonWasRunning &&
          nextDiagnosticsUrl != currentSettings.diagnosticsUrl) {
        throw const FormatException(
          'Stop P2WLAN before changing the Diagnostics URL.',
        );
      }
      final mtu = int.tryParse(_mtuController.text.trim()) ?? defaultMtu;
      final deviceName = _deviceNameController.text.trim().isEmpty
          ? await resolveDefaultDeviceName()
          : _deviceNameController.text.trim();
      await widget.settingsStore.updateConnectionSettings(
        diagnosticsUrl: _diagnosticsUrlController.text,
        controlServer: _controlServerController.text,
        authToken: _authTokenController.text,
        networkId: _networkIdController.text,
        virtualIp: _virtualIpController.text,
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
      final restartRequiredNow =
          daemonWasRunning &&
          _daemonLaunchSettingsChanged(
            currentSettings,
            widget.settingsStore.settings,
          );
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
    await _saveAll();
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
