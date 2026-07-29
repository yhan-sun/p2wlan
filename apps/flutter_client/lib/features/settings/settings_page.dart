import 'package:flutter/material.dart';

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
        return PageScaffold(
          title: 'Settings',
          subtitle: 'Local Flutter prototype settings only.',
          children: [
            InfoCard(
              title: 'Diagnostics endpoint',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: _diagnosticsUrlController,
                    decoration: InputDecoration(
                      labelText: 'Diagnostics URL',
                      hintText: defaultDiagnosticsUrl,
                      helperText:
                          'Saved only to this Flutter app; daemon config is not changed.',
                      border: const OutlineInputBorder(),
                      errorText: _error,
                    ),
                    keyboardType: TextInputType.url,
                    onSubmitted: (_) => _save(),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 12,
                    runSpacing: 8,
                    children: [
                      FilledButton.icon(
                        onPressed: _saving ? null : _save,
                        icon: _saving
                            ? const SizedBox.square(
                                dimension: 16,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.save_outlined),
                        label: const Text('Save'),
                      ),
                      OutlinedButton.icon(
                        onPressed: _saving ? null : _reset,
                        icon: const Icon(Icons.restore),
                        label: const Text('Restore default URL'),
                      ),
                      OutlinedButton.icon(
                        onPressed: widget.statusStore.refreshing
                            ? null
                            : () => widget.statusStore.refresh(),
                        icon: const Icon(Icons.refresh),
                        label: const Text('Refresh now'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  Text(
                    'Local settings file: ${widget.settingsStore.configPath ?? '—'}',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'This setting changes only where the Flutter read-only UI sends GET /health and GET /status.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (widget.settingsStore.lastError != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      widget.settingsStore.lastError!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 16),
            const InfoCard(
              title: 'P1 boundary',
              child: Text(
                'This prototype only reads GET /health and GET /status. Daemon process lifecycle, elevation, and system networking stay outside this Flutter app.',
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
      _showSnackBar('Diagnostics URL saved locally');
    } on FormatException catch (error) {
      setState(() => _error = error.message);
      _showSnackBar('Diagnostics URL was not saved');
    } catch (error) {
      setState(() => _error = error.toString());
      _showSnackBar('Failed to save local settings');
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

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }
}
