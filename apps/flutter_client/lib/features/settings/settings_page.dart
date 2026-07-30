import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/api/daemon_api.dart';
import '../../core/models/daemon_models.dart';
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
  String? _error;
  var _saving = false;

  @override
  void initState() {
    super.initState();
    _diagnosticsUrlController = TextEditingController(
      text: widget.settingsStore.settings.diagnosticsUrl,
    );
  }

  @override
  void dispose() {
    _diagnosticsUrlController.dispose();
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
                      errorText: _error,
                    ),
                    keyboardType: TextInputType.url,
                    onSubmitted: (_) => _save(),
                  ),
                  const SizedBox(height: 14),
                  Wrap(
                    spacing: 12,
                    runSpacing: 8,
                    children: [
                      FilledButton.icon(
                        onPressed: _saving ? null : _save,
                        icon: _saving
                            ? const SizedBox.square(
                                dimension: 14,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  valueColor: AlwaysStoppedAnimation<Color>(
                                    Colors.white,
                                  ),
                                ),
                              )
                            : const Icon(Icons.save_outlined, size: 16),
                        label: Text(strings.save),
                      ),
                      OutlinedButton.icon(
                        onPressed: _saving ? null : _reset,
                        icon: const Icon(Icons.restore, size: 16),
                        label: Text(strings.restoreDefaultUrl),
                      ),
                      OutlinedButton.icon(
                        onPressed: widget.statusStore.refreshing
                            ? null
                            : () => widget.statusStore.refresh(),
                        icon: const Icon(Icons.refresh, size: 16),
                        label: Text(strings.refreshNow),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
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
            const SizedBox(height: 14),
            AppPanel(
              title: strings.language,
              child: DropdownButtonFormField<String>(
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
                        if (value != null) {
                          _saveLanguage(value);
                        }
                      },
              ),
            ),
            const SizedBox(height: 14),
            AppPanel(
              title: strings.p1Boundary,
              child: Text(
                strings.p1BoundaryText,
                style: const TextStyle(
                  fontSize: 13,
                  color: AppTokens.colorTextSecondary,
                  height: 1.4,
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      final normalized = normalizeDiagnosticsUrl(
        _diagnosticsUrlController.text,
      );
      await widget.settingsStore.updateDiagnosticsUrl(normalized);
      _diagnosticsUrlController.text = normalized;
      await widget.statusStore.refresh();
      _showSnackBar(
        AppStrings.fromCode(
          widget.settingsStore.settings.languageCode,
        ).diagnosticsUrlSaved,
      );
    } on FormatException catch (error) {
      final strings = AppStrings.fromCode(
        widget.settingsStore.settings.languageCode,
      );
      setState(() => _error = strings.diagnosticsUrlError(error.message));
      _showSnackBar(strings.diagnosticsUrlNotSaved);
    } catch (error) {
      setState(() => _error = error.toString());
      _showSnackBar(
        AppStrings.fromCode(
          widget.settingsStore.settings.languageCode,
        ).failedToSaveLocalSettings,
      );
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
  }

  Future<void> _reset() async {
    _diagnosticsUrlController.text = defaultDiagnosticsUrl;
    await _save();
  }

  Future<void> _saveLanguage(String languageCode) async {
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await widget.settingsStore.updateLanguageCode(languageCode);
      _showSnackBar(AppStrings.fromCode(languageCode).languageSaved);
    } catch (error) {
      _showSnackBar(
        AppStrings.fromCode(languageCode).failedToSaveLocalSettings,
      );
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }
}
