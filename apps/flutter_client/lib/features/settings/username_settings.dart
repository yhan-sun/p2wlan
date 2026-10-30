import 'package:flutter/material.dart';

import '../../core/api/control_api.dart';
import '../../app/app_strings.dart';
import '../../shared/widgets/app_notice.dart';

/// Owns the username draft across category navigation. The server profile is
/// the saved baseline; the text controller remains the only editable value.
class UsernameSettingsController extends ChangeNotifier {
  UsernameSettingsController({String username = ''})
    : _savedUsername = username.trim(),
      text = TextEditingController(text: username.trim()) {
    text.addListener(notifyListeners);
  }

  final TextEditingController text;
  String _savedUsername;
  (String, String)? _account;

  bool get isDirty => text.text.trim() != _savedUsername;

  void _bindAccount(String server, String token, String username) {
    final account = (server.trim(), token);
    if (_account != null && _account != account) {
      _acceptSaved(username, preserveDraft: false);
    }
    _account = account;
  }

  void _acceptSaved(String username, {bool preserveDraft = true}) {
    final hadDraft = isDirty;
    _savedUsername = username.trim();
    if ((!preserveDraft || !hadDraft) && text.text != _savedUsername) {
      text.text = _savedUsername;
    } else {
      notifyListeners();
    }
  }

  @override
  void dispose() {
    text.removeListener(notifyListeners);
    text.dispose();
    super.dispose();
  }
}

/// Usernames are account display names, independent of login email and devices.
class UsernameSettings extends StatefulWidget {
  const UsernameSettings({
    super.key,
    required this.server,
    required this.token,
    this.email = '',
    this.username = '',
    this.onProfileLoaded,
    this.controller,
    this.controlApi,
  });
  final String server;
  final String token;
  final String email;
  final String username;
  final ValueChanged<AccountProfile>? onProfileLoaded;
  final UsernameSettingsController? controller;
  final ControlApi? controlApi;
  @override
  State<UsernameSettings> createState() => _UsernameSettingsState();
}

class _UsernameSettingsState extends State<UsernameSettings> {
  late final ControlApi _api;
  late final bool _ownsApi;
  late UsernameSettingsController _controller;
  late bool _ownsController;
  TextEditingController get _name => _controller.text;
  bool _busy = true;
  bool _loaded = false;
  String? _error;
  String? _saved;
  late String _email;
  var _requestRevision = 0;

  @override
  void initState() {
    super.initState();
    _ownsApi = widget.controlApi == null;
    _api = widget.controlApi ?? ControlApi();
    _attachController();
    _email = widget.email.trim();
    _loaded = _name.text.isNotEmpty;
    _load();
  }

  void _attachController() {
    _ownsController = widget.controller == null;
    _controller =
        widget.controller ??
        UsernameSettingsController(username: widget.username);
    _controller._bindAccount(widget.server, widget.token, widget.username);
  }

  @override
  void didUpdateWidget(covariant UsernameSettings oldWidget) {
    super.didUpdateWidget(oldWidget);
    final accountChanged =
        oldWidget.server != widget.server || oldWidget.token != widget.token;
    if (oldWidget.controller != widget.controller) {
      if (_ownsController) _controller.dispose();
      _attachController();
    } else {
      _controller._bindAccount(widget.server, widget.token, widget.username);
    }
    final nextEmail = widget.email.trim();
    if (accountChanged || nextEmail.isNotEmpty) _email = nextEmail;
    final nextUsername = widget.username.trim();
    if (nextUsername != oldWidget.username.trim()) {
      _controller._acceptSaved(nextUsername);
      _loaded = true;
    }
    if (accountChanged) {
      _saved = null;
      _loaded = _name.text.isNotEmpty;
      _load();
    }
  }

  Future<void> _load() async {
    final revision = ++_requestRevision;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final profile = await _api.accountProfile(
        controlServer: widget.server,
        authToken: widget.token,
      );
      if (!mounted || revision != _requestRevision) return;
      _email = profile.email.isEmpty ? _email : profile.email;
      _controller._acceptSaved(profile.username);
      _loaded = true;
      widget.onProfileLoaded?.call(profile);
    } catch (_) {
      if (mounted && revision == _requestRevision) {
        _error = AppStringsScope.of(context).settingsUsernameLoadError;
        showAppNotice(context, content: Text(_error!));
      }
    } finally {
      if (mounted && revision == _requestRevision) {
        setState(() => _busy = false);
      }
    }
  }

  Future<void> _save() async {
    final revision = ++_requestRevision;
    setState(() {
      _busy = true;
      _error = null;
      _saved = null;
    });
    try {
      final profile = await _api.accountProfile(
        controlServer: widget.server,
        authToken: widget.token,
        username: _name.text,
      );
      if (!mounted || revision != _requestRevision) return;
      _email = profile.email.isEmpty ? _email : profile.email;
      _controller._acceptSaved(profile.username, preserveDraft: false);
      widget.onProfileLoaded?.call(profile);
      _saved = AppStringsScope.of(context).settingsUsernameSaved;
    } on ControlApiException catch (error) {
      if (mounted && revision == _requestRevision) {
        _error = error.message;
        showAppNotice(context, content: Text(error.message));
      }
    } finally {
      if (mounted && revision == _requestRevision) {
        setState(() => _busy = false);
      }
    }
  }

  @override
  void dispose() {
    if (_ownsApi) _api.close();
    if (_ownsController) _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Align(
        alignment: Alignment.centerLeft,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (_email.isNotEmpty) ...[
                InputDecorator(
                  decoration: InputDecoration(
                    labelText: strings.settingsAccountEmail,
                    helperText: strings.settingsAccountEmailHelper,
                    helperMaxLines: 2,
                    prefixIcon: const Icon(Icons.alternate_email_outlined),
                  ),
                  child: Text(
                    _email,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(height: 16),
              ],
              if (_loaded)
                TextField(
                  controller: _name,
                  enabled: !_busy,
                  maxLength: 32,
                  decoration: InputDecoration(
                    labelText: strings.settingsUsername,
                    hintText: strings.settingsUsernameHint,
                    helperText: strings.settingsUsernameHelper,
                    helperMaxLines: 3,
                  ),
                  onSubmitted: _busy ? null : (_) => _save(),
                )
              else
                Text(
                  strings.settingsUsername,
                  style: Theme.of(context).textTheme.titleSmall,
                ),
              if (_busy) const LinearProgressIndicator(),
              if (_error != null && _name.text.trim().isEmpty)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Text(
                    _error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              if (_saved != null)
                Semantics(
                  liveRegion: true,
                  child: Text(
                    _saved!,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ),
              TextButton(
                onPressed: _busy
                    ? null
                    : _loaded
                    ? _save
                    : _load,
                child: Text(
                  _loaded
                      ? strings.settingsSaveUsername
                      : strings.settingsReloadUsername,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
