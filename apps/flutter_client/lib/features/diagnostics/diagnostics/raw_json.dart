part of '../diagnostics_page.dart';

class _RawJson extends StatefulWidget {
  const _RawJson({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  State<_RawJson> createState() => _RawJsonState();
}

class _RawJsonState extends State<_RawJson> {
  var _copied = false;
  var _expanded = false;
  DiagnosticsSnapshot? _cachedSnapshot;
  String? _cachedPrettyJson;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.rawStatusJson,
      trailing: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          OutlinedButton.icon(
            onPressed: () => setState(() => _expanded = !_expanded),
            icon: Icon(
              _expanded
                  ? Icons.unfold_less_outlined
                  : Icons.unfold_more_outlined,
              size: 16,
            ),
            label: Text(_expanded ? strings.hideRawJson : strings.showRawJson),
          ),
          OutlinedButton.icon(
            onPressed: () => _copy(_rawJson()),
            icon: Icon(
              _copied ? Icons.check_circle_outline : Icons.copy_all_outlined,
              size: 16,
            ),
            label: Text(_copied ? strings.copied : strings.copy),
          ),
        ],
      ),
      child: _expanded
          ? _RawJsonConsole(raw: _rawJson())
          : Text(
              strings.rawJsonCollapsed,
              style: const TextStyle(
                fontSize: 13,
                height: 1.35,
                color: AppTokens.colorTextSecondary,
              ),
            ),
    );
  }

  String _rawJson() {
    final snapshot = widget.snapshot;
    if (snapshot == null) return redactSensitive(_readableErrorJson());
    if (!identical(snapshot, _cachedSnapshot)) {
      _cachedSnapshot = snapshot;
      // Redact so the raw view (and the copy action) can never carry a live
      // token/ticket even if the daemon snapshot includes one.
      _cachedPrettyJson = redactSensitive(snapshot.prettyJson);
    }
    return _cachedPrettyJson!;
  }

  String _readableErrorJson() {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert({
      'status': widget.statusStore.healthReachable
          ? 'status_unavailable'
          : 'offline',
      'health_endpoint': widget.statusStore.healthReachable
          ? 'reachable'
          : 'offline',
      'status_endpoint': widget.statusStore.statusReachable
          ? 'loaded'
          : widget.statusStore.healthReachable
          ? 'error'
          : 'skipped',
      if (widget.statusStore.lastError != null)
        'error': widget.statusStore.lastError,
      if (widget.statusStore.lastFetchedAt != null)
        'last_refresh': widget.statusStore.lastFetchedAt!.toIso8601String(),
      if (widget.statusStore.lastRequestDuration != null)
        'request_duration_ms':
            widget.statusStore.lastRequestDuration!.inMilliseconds,
    });
  }

  Future<void> _copy(String raw) async {
    final strings = AppStringsScope.of(context);
    await Clipboard.setData(ClipboardData(text: raw));
    if (!mounted) return;
    setState(() => _copied = true);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(strings.copiedDiagnosticsJson),
        duration: const Duration(seconds: 2),
      ),
    );
    await Future<void>.delayed(const Duration(seconds: 2));
    if (mounted) {
      setState(() => _copied = false);
    }
  }
}

class _RawJsonConsole extends StatelessWidget {
  const _RawJsonConsole({required this.raw});

  final String raw;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      constraints: const BoxConstraints(minHeight: 220),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTokens.colorConsoleBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: AppTokens.colorConsoleBorder),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Text(
          raw,
          style: const TextStyle(
            color: AppTokens.colorConsoleText,
            fontFamily: 'monospace',
            fontSize: 12.5,
            height: 1.4,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ),
    );
  }
}
