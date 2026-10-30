part of '../settings_page.dart';

/// Field feedback belongs to the draft; the store validates persisted values.
extension _SettingsDraftValidation on _SettingsPageState {
  List<TextEditingController> _categoryControllers(SettingsCategory category) =>
      switch (category) {
        SettingsCategory.general => [_deviceNameController],
        SettingsCategory.accountNetwork => [
          _controlServerController,
          _networkIdController,
          _virtualIpController,
        ],
        SettingsCategory.advancedNetwork => [
          _mtuController,
          _overlayCidrController,
          _udpBindController,
          _udpAdvertiseController,
        ],
        SettingsCategory.developer => [_diagnosticsUrlController],
      };

  bool _validateCategory(SettingsCategory category, AppStrings strings) {
    final errors = <TextEditingController, String>{};
    final isZh = strings.isZh;
    switch (category) {
      case SettingsCategory.general:
        if (_deviceNameController.text.trim().isEmpty) {
          errors[_deviceNameController] = isZh
              ? '请输入设备名称。'
              : 'Enter a device name.';
        }
      case SettingsCategory.accountNetwork:
        try {
          final server = normalizeControlServer(_controlServerController.text);
          final current = widget.settingsStore.settings;
          if (server.isEmpty) {
            errors[_controlServerController] = isZh
                ? '请输入完整的 HTTP 或 HTTPS 服务器地址。'
                : 'Server URL must use http or https, for example https://example.com.';
          } else if (_authTokenController.text.trim().isEmpty &&
              current.authToken.trim().isNotEmpty &&
              server != normalizeControlServer(current.controlServer)) {
            errors[_controlServerController] = isZh
                ? '更换服务器需要该服务器的登录凭据。请重新登录，或在“更换凭据”中填写新凭据。'
                : 'Sign in to the new server, or enter its credential under Change credential before saving.';
          }
        } on FormatException {
          errors[_controlServerController] = isZh
              ? '请输入完整的 HTTP 或 HTTPS 服务器地址。'
              : 'Server URL must use http or https, for example https://example.com.';
        }
        if (_networkIdController.text.trim().isEmpty) {
          errors[_networkIdController] = isZh
              ? '请输入网络 ID。'
              : 'Enter a network ID.';
        }
        final ip = _virtualIpController.text.trim();
        if (ip.isNotEmpty && !_draftIpv4Valid(ip)) {
          errors[_virtualIpController] = isZh
              ? '请输入有效的 IPv4 地址，例如 10.20.0.42；留空可自动分配。'
              : 'Enter an IPv4 address such as 10.20.0.42, or leave blank for automatic assignment.';
        }
      case SettingsCategory.advancedNetwork:
        final mtuText = _mtuController.text.trim();
        final mtu = int.tryParse(mtuText);
        if (!RegExp(r'^\d+$').hasMatch(mtuText) ||
            mtu == null ||
            mtu < 576 ||
            mtu > 65535) {
          errors[_mtuController] = isZh
              ? '请输入 576–65535 之间的整数。'
              : 'Enter a whole number from 576 to 65535.';
        }
        final cidr = _overlayCidrController.text.trim().split('/');
        final prefix = cidr.length == 2 ? int.tryParse(cidr[1]) : null;
        if (cidr.length != 2 ||
            !_draftIpv4Valid(cidr[0]) ||
            prefix == null ||
            prefix < 0 ||
            prefix > 32) {
          errors[_overlayCidrController] = isZh
              ? '请输入有效的 IPv4 网段，例如 10.20.0.0/16。'
              : 'Enter an IPv4 CIDR such as 10.20.0.0/16.';
        }
        if (!_draftSocketValid(_udpBindController.text, allowPortZero: true)) {
          errors[_udpBindController] = isZh
              ? '请输入 IP 地址和端口，例如 0.0.0.0:60207。'
              : 'Enter an IP address and port such as 0.0.0.0:60207.';
        }
        final advertise = _udpAdvertiseController.text.trim();
        if (advertise.isNotEmpty &&
            (!_draftSocketValid(advertise, allowPortZero: false) ||
                advertise.startsWith('0.0.0.0:') ||
                advertise.startsWith('[::]:'))) {
          errors[_udpAdvertiseController] = isZh ? '请输入可访问的 IP 地址和端口；留空可自动选择。' : 'Enter a reachable IP address and port, or leave blank for automatic selection.';
        }
      case SettingsCategory.developer:
        // Keep localized Diagnostics URL validation and running-daemon guard.
        break;
    }
    _updateState(() {
      for (final controller in _categoryControllers(category)) {
        _fieldErrors.remove(controller);
      }
      _fieldErrors.addAll(errors);
    });
    if (errors.isNotEmpty) {
      _focusFor(errors.keys.first).requestFocus();
      return false;
    }
    return true;
  }
}

bool _draftIpv4Valid(String value) {
  final parts = value.split('.');
  return parts.length == 4 &&
      parts.every((part) {
        final number = int.tryParse(part);
        return RegExp(r'^\d{1,3}$').hasMatch(part) &&
            number != null &&
            number >= 0 &&
            number <= 255;
      });
}

bool _draftSocketValid(String raw, {required bool allowPortZero}) {
  final value = raw.trim();
  final bracket = value.startsWith('[');
  final hostEnd = bracket ? value.indexOf(']') : value.lastIndexOf(':');
  if (hostEnd < 1) return false;
  final portStart = bracket ? hostEnd + 2 : hostEnd + 1;
  if (bracket && (hostEnd + 1 >= value.length || value[hostEnd + 1] != ':')) {
    return false;
  }
  final host = value.substring(bracket ? 1 : 0, hostEnd);
  final portText = value.substring(portStart);
  final port = int.tryParse(portText);
  // Match the store's supported literal IPv4 / IPv6 socket representation.
  return (_draftIpv4Valid(host) || (bracket && host.contains(':'))) &&
      RegExp(r'^\d+$').hasMatch(portText) &&
      port != null &&
      port >= (allowPortZero ? 0 : 1) &&
      port <= 65535;
}
