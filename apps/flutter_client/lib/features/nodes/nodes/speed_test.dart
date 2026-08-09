part of '../nodes_page.dart';

class _SpeedTestDialog extends StatefulWidget {
  const _SpeedTestDialog({
    required this.peer,
    required this.statusStore,
    required this.strings,
  });

  final PeerSnapshot peer;
  final StatusStore statusStore;
  final AppStrings strings;

  @override
  State<_SpeedTestDialog> createState() => _SpeedTestDialogState();
}

class _SpeedTestDialogState extends State<_SpeedTestDialog> {
  static const _testDuration = Duration(seconds: 10);

  Timer? _progressTimer;

  @override
  void initState() {
    super.initState();
    widget.statusStore.addListener(_handleStatusChanged);
    _syncProgressTimer();
  }

  @override
  void dispose() {
    _progressTimer?.cancel();
    widget.statusStore.removeListener(_handleStatusChanged);
    super.dispose();
  }

  void _handleStatusChanged() {
    _syncProgressTimer();
    if (mounted) setState(() {});
  }

  void _syncProgressTimer() {
    if (_runningForPeer) {
      _progressTimer ??= Timer.periodic(const Duration(milliseconds: 100), (_) {
        if (mounted) setState(() {});
      });
      return;
    }
    _progressTimer?.cancel();
    _progressTimer = null;
  }

  bool get _runningForPeer =>
      widget.statusStore.speedTestRunning &&
      widget.statusStore.speedTestMatches(widget.peer);

  bool get _runningElsewhere =>
      widget.statusStore.speedTestRunning && !_runningForPeer;

  void _run() {
    if (!_canRunSpeedTest(widget.peer) || widget.statusStore.speedTestRunning) {
      return;
    }
    unawaited(widget.statusStore.runSpeedTest(widget.peer));
  }

  @override
  Widget build(BuildContext context) {
    final strings = widget.strings;
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final result = widget.statusStore.speedTestResultFor(widget.peer);
    final error = widget.statusStore.speedTestErrorFor(widget.peer);
    final eligible = _canRunSpeedTest(widget.peer);
    final startedAt = widget.statusStore.speedTestStartedAt;
    final elapsed = _runningForPeer && startedAt != null
        ? DateTime.now().difference(startedAt)
        : Duration.zero;
    final cappedElapsed = elapsed > _testDuration ? _testDuration : elapsed;
    final progress =
        cappedElapsed.inMilliseconds / _testDuration.inMilliseconds;
    final dialogSize = MediaQuery.sizeOf(context);
    final maxWidth = dialogSize.width > 560 ? 520.0 : dialogSize.width - 32;

    return Dialog(
      key: const Key('node-speedtest-dialog'),
      insetPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: maxWidth, maxHeight: 560),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 18, 20, 14),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          strings.speedTestTitle,
                          style: TextStyle(
                            color: colorScheme.onSurface,
                            fontSize: 17,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          strings.speedTestPeer(widget.peer.displayName),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: colorScheme.onSurfaceVariant,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  _PathBadge(peer: widget.peer),
                  IconButton(
                    tooltip: strings.close,
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close_rounded, size: 20),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              _SpeedTestDetailRow(
                label: strings.virtualIp,
                value: dash(widget.peer.virtualIp),
              ),
              _SpeedTestDetailRow(
                label: strings.path,
                value: _connectionLabel(strings, widget.peer),
              ),
              const SizedBox(height: 18),
              if (!eligible)
                _SpeedTestMessage(
                  icon: Icons.info_outline_rounded,
                  message: strings.speedTestUnavailable,
                  color: colorScheme.onSurfaceVariant,
                )
              else if (_runningElsewhere)
                _SpeedTestMessage(
                  icon: Icons.hourglass_top_rounded,
                  message: strings.speedTestRunningOn(
                    widget.statusStore.speedTestPeerVirtualIp ?? '',
                  ),
                  color: colorScheme.onSurfaceVariant,
                )
              else if (_runningForPeer) ...[
                LinearProgressIndicator(value: progress),
                const SizedBox(height: 10),
                Row(
                  children: [
                    const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 9),
                    Text(
                      strings.speedTesting,
                      style: TextStyle(
                        color: colorScheme.onSurface,
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const Spacer(),
                    Text(
                      strings.speedTestProgress(cappedElapsed.inSeconds),
                      style: TextStyle(
                        color: colorScheme.onSurfaceVariant,
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ],
                ),
              ] else if (error != null && error.isNotEmpty)
                _SpeedTestMessage(
                  icon: Icons.error_outline_rounded,
                  message: strings.speedTestFailed(error),
                  color: colorScheme.error,
                )
              else if (result != null)
                _SpeedTestResult(result: result, strings: strings)
              else
                _SpeedTestMessage(
                  icon: Icons.speed_rounded,
                  message: strings.speedTestDuration,
                  color: colorScheme.onSurfaceVariant,
                ),
              const SizedBox(height: 20),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: Text(strings.close),
                  ),
                  const SizedBox(width: 8),
                  FilledButton.icon(
                    key: const Key('node-speedtest-start'),
                    onPressed: eligible && !widget.statusStore.speedTestRunning
                        ? _run
                        : null,
                    icon: const Icon(Icons.speed_rounded, size: 18),
                    label: Text(
                      result != null || error != null
                          ? strings.retrySpeedTest
                          : strings.startSpeedTest,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SpeedTestDetailRow extends StatelessWidget {
  const _SpeedTestDetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(
            width: 82,
            child: Text(
              label,
              style: TextStyle(
                color: colorScheme.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: colorScheme.onSurface,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SpeedTestMessage extends StatelessWidget {
  const _SpeedTestMessage({
    required this.icon,
    required this.message,
    required this.color,
  });

  final IconData icon;
  final String message;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 19, color: color),
        const SizedBox(width: 9),
        Expanded(
          child: Text(
            message,
            style: TextStyle(color: color, fontSize: 13, height: 1.35),
          ),
        ),
      ],
    );
  }
}

class _SpeedTestResult extends StatelessWidget {
  const _SpeedTestResult({required this.result, required this.strings});

  final SpeedTestResult result;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 18,
      runSpacing: 2,
      children: [
        MetricTile(
          label: strings.speedTestDownload,
          value: '${result.downloadMbps.toStringAsFixed(1)} Mbps',
          minWidth: 130,
          maxWidth: 180,
        ),
        MetricTile(
          label: strings.speedTestUpload,
          value: '${result.uploadMbps.toStringAsFixed(1)} Mbps',
          minWidth: 130,
          maxWidth: 180,
        ),
        MetricTile(
          label: strings.speedTestTransferred,
          value:
              '${formatBytes(result.downloadBytes)} / ${formatBytes(result.uploadBytes)}',
          detail:
              '${strings.speedTestElapsed}: ${formatDuration(Duration(milliseconds: result.durationMs))}',
          minWidth: 200,
          maxWidth: 260,
        ),
      ],
    );
  }
}
