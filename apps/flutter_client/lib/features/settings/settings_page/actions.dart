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
      await widget.statusStore.refresh();
      _showSnackBar(strings.diagnosticsUrlSaved);
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
      _updateState(() => _formError = error.toString());
      _showSnackBar(strings.failedToSaveLocalSettings);
    } finally {
      if (mounted) {
        _updateState(() => _saving = false);
      }
    }
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
