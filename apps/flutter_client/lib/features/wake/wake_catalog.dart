import 'dart:async';

import 'package:flutter/material.dart';

import '../../core/api/wake_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/rooms/room_profiles.dart';
import '../../core/state/settings_store.dart';
import 'wake_dialog.dart';
import 'wake_strings.dart';

Future<void> showWakeCatalog(
  BuildContext context, {
  required SettingsStore settingsStore,
  required WakeStrings strings,
  required String networkId,
  bool includeDevices = false,
}) => showDialog<void>(
  context: context,
  builder: (_) => _WakeCatalog(
    settingsStore: settingsStore,
    strings: strings,
    networkId: networkId,
    includeDevices: includeDevices,
  ),
);

class _WakeCatalog extends StatefulWidget {
  const _WakeCatalog({
    required this.settingsStore,
    required this.strings,
    required this.networkId,
    required this.includeDevices,
  });

  final SettingsStore settingsStore;
  final WakeStrings strings;
  final String networkId;
  final bool includeDevices;

  @override
  State<_WakeCatalog> createState() => _WakeCatalogState();
}

class _WakeCatalogState extends State<_WakeCatalog> {
  late final AppSettings _settings;
  late final WakeApi _api;
  bool _valid = true;
  bool _busy = true;
  String? _error;
  List<WakeTarget> _devices = const [];
  List<WakeTarget> _manual = const [];

  WakeStrings get _s => widget.strings;
  bool get _live => mounted && _valid;

  @override
  void initState() {
    super.initState();
    _settings = widget.settingsStore.settings;
    _api = WakeApi(server: _settings.controlServer, token: _settings.authToken);
    widget.settingsStore.addListener(_settingsChanged);
    unawaited(_load());
  }

  void _settingsChanged() {
    if (!_valid ||
        accountSessionKey(widget.settingsStore.settings) ==
            accountSessionKey(_settings)) {
      return;
    }
    _api.close();
    setState(() {
      _valid = false;
      _busy = false;
      _devices = [];
      _manual = [];
      _error = 'auth_expired';
    });
  }

  @override
  void dispose() {
    widget.settingsStore.removeListener(_settingsChanged);
    if (_valid) _api.close();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final lists = await Future.wait([
        if (widget.includeDevices) _api.devices(widget.networkId),
        _api.manualTargets(widget.networkId),
      ]);
      if (!_live) return;
      setState(() {
        _devices = widget.includeDevices ? lists.first : const [];
        _manual = lists.last;
      });
    } on WakeApiException catch (error) {
      if (_live) setState(() => _error = error.code);
    } finally {
      if (_live) setState(() => _busy = false);
    }
  }

  Future<void> _edit([WakeTarget? target]) async {
    final data = await showDialog<({String name, String? mac, bool? enabled})>(
      context: context,
      builder: (_) => _TargetEditor(strings: _s, target: target),
    );
    if (!_live || data == null) return;
    await _change(
      () => _api.saveManualTarget(
        widget.networkId,
        targetId: target?.id,
        name: data.name,
        mac: data.mac,
        enabled: data.enabled,
      ),
    );
  }

  Future<void> _remove(WakeTarget target) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(_s.remove),
        content: Text(_s.removeNamed(target.name)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: Text(_s.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: Text(_s.remove),
          ),
        ],
      ),
    );
    if (_live && confirmed == true) {
      await _change(() => _api.removeManualTarget(target.id));
    }
  }

  Future<void> _change(Future<void> Function() change) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await change();
      if (_live) await _load();
    } on WakeApiException catch (error) {
      if (_live) {
        setState(() {
          _error = error.code;
          _busy = false;
        });
      }
    }
  }

  void _open(WakeTarget target) {
    unawaited(
      showWakeDialog(
        context,
        settingsStore: widget.settingsStore,
        strings: _s,
        target: target,
      ),
    );
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.includeDevices ? _s.title : _s.manualTargets),
    scrollable: true,
    content: SizedBox(
      width: 420,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          if (_error case final error?)
            Semantics(liveRegion: true, child: Text(_s.error(error))),
          if (_busy) const LinearProgressIndicator(),
          if (_valid &&
              (!_busy || _devices.isNotEmpty || _manual.isNotEmpty)) ...[
            if (widget.includeDevices &&
                (_error == null || _devices.isNotEmpty)) ...[
              Text(_s.devices, style: Theme.of(context).textTheme.titleSmall),
              if (_devices.isEmpty) Text(_s.noDevices),
              for (final target in _devices)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.computer_rounded),
                  title: Text(target.name),
                  onTap: _busy ? null : () => _open(target),
                ),
              const Divider(),
            ],
            if (widget.includeDevices && (_error == null || _manual.isNotEmpty))
              Text(
                _s.manualTargets,
                style: Theme.of(context).textTheme.titleSmall,
              ),
            if (_error == null && _manual.isEmpty) Text(_s.noTargets),
            for (final target in _manual)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.power_settings_new_rounded),
                title: Text(target.name),
                onTap: _busy ? null : () => _open(target),
                trailing: PopupMenuButton<String>(
                  enabled: !_busy,
                  itemBuilder: (_) => [
                    PopupMenuItem(value: 'edit', child: Text(_s.edit)),
                    PopupMenuItem(value: 'remove', child: Text(_s.remove)),
                  ],
                  onSelected: (value) {
                    if (value == 'edit') {
                      unawaited(_edit(target));
                    } else {
                      unawaited(_remove(target));
                    }
                  },
                ),
              ),
          ],
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: Text(_s.close),
      ),
      if (_live && !_busy && _error != null)
        TextButton(onPressed: _load, child: Text(_s.refresh)),
      if (_live &&
          !_busy &&
          !const {
            'https_required',
            'unsupported',
            'auth_expired',
          }.contains(_error))
        FilledButton(onPressed: _edit, child: Text(_s.add)),
    ],
  );
}

class _TargetEditor extends StatefulWidget {
  const _TargetEditor({required this.strings, this.target});

  final WakeStrings strings;
  final WakeTarget? target;

  @override
  State<_TargetEditor> createState() => _TargetEditorState();
}

class _TargetEditorState extends State<_TargetEditor> {
  final _form = GlobalKey<FormState>();
  String _name = '';
  String? _mac;
  late bool _enabled = widget.target?.enabled ?? true;

  void _save() {
    final form = _form.currentState;
    if (form == null || !form.validate()) return;
    form.save();
    Navigator.pop(context, (
      name: _name,
      mac: _mac,
      enabled: widget.target == null ? null : _enabled,
    ));
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.strings;
    return AlertDialog(
      title: Text(widget.target == null ? s.add : s.edit),
      scrollable: true,
      content: SizedBox(
        width: 360,
        child: Form(
          key: _form,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextFormField(
                initialValue: widget.target?.name,
                decoration: InputDecoration(labelText: s.name),
                maxLength: 64,
                validator: (value) {
                  final name = value?.trim() ?? '';
                  return name.isEmpty ||
                          name.runes.length > 64 ||
                          RegExp(r'[\x00-\x1f\x7f-\x9f]').hasMatch(name)
                      ? s.invalidName
                      : null;
                },
                onSaved: (value) => _name = value?.trim() ?? '',
              ),
              TextFormField(
                decoration: InputDecoration(
                  labelText: s.mac,
                  helperText: widget.target == null ? null : s.keepMac,
                ),
                autocorrect: false,
                enableSuggestions: false,
                maxLength: 17,
                validator: (value) {
                  final raw = value?.trim() ?? '';
                  if (raw.isEmpty && widget.target != null) return null;
                  return _normalizeMac(raw) == null ? s.invalidMac : null;
                },
                onSaved: (value) => _mac = _normalizeMac(value?.trim() ?? ''),
              ),
              if (widget.target != null)
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(s.enableTarget),
                  value: _enabled,
                  onChanged: (value) => setState(() => _enabled = value),
                ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(s.cancel),
        ),
        FilledButton(onPressed: _save, child: Text(s.save)),
      ],
    );
  }
}

String? _normalizeMac(String input) {
  if (!RegExp(r'^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$').hasMatch(input)) {
    return null;
  }
  final mac = input.replaceAll('-', ':').toLowerCase();
  final firstByte = int.parse(mac.substring(0, 2), radix: 16);
  if (firstByte.isOdd || mac == '00:00:00:00:00:00') return null;
  return mac;
}
