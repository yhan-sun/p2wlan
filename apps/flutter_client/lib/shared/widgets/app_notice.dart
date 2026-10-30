import 'dart:async';

import 'package:flutter/material.dart';

import 'app_motion.dart';

final _activeNotices = Expando<VoidCallback>();

/// Displays a single non-modal notification near the upper center.
void showAppNotice(
  BuildContext context, {
  required Widget content,
  Duration duration = const Duration(seconds: 4),
}) {
  if (!context.mounted) return;
  final overlay = Navigator.of(context, rootNavigator: true).overlay!;
  // Replacement is immediate, so rapid notices never retain outgoing trees.
  _activeNotices[overlay]?.call();
  final noticeKey = GlobalKey<_NoticeState>();
  late final OverlayEntry entry;
  late final VoidCallback remove;
  var removed = false;
  remove = () {
    if (removed) return;
    removed = true;
    noticeKey.currentState?._cancel();
    if (_activeNotices[overlay] == remove) _activeNotices[overlay] = null;
    entry
      ..remove()
      ..dispose();
  };

  entry = OverlayEntry(
    builder: (_) => _Notice(
      key: noticeKey,
      content: content,
      duration: duration,
      remove: remove,
    ),
  );
  _activeNotices[overlay] = remove;
  overlay.insert(entry);
}

class _Notice extends StatefulWidget {
  const _Notice({
    super.key,
    required this.content,
    required this.duration,
    required this.remove,
  });
  final Widget content;
  final Duration duration;
  final VoidCallback remove;
  @override
  State<_Notice> createState() => _NoticeState();
}

class _NoticeState extends State<_Notice> with SingleTickerProviderStateMixin {
  late final _controller = AnimationController(vsync: this)
    ..addStatusListener(_onStatusChanged);
  Timer? _timer;
  bool _started = false;
  bool _closing = false;

  @override
  void initState() {
    super.initState();
    _timer = Timer(widget.duration, _dismiss);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _controller.duration = AppMotion.durationOf(context);
    if (_controller.duration == Duration.zero) {
      _controller.value = _closing ? 0 : 1;
      if (_closing) widget.remove();
    } else if (!_started) {
      _controller.animateTo(1, curve: AppMotion.curve);
    }
    _started = true;
  }

  void _onStatusChanged(AnimationStatus status) {
    if (_closing && status == AnimationStatus.dismissed) widget.remove();
  }

  void _cancel() {
    _closing = true;
    _timer?.cancel();
    _controller.stop();
  }

  void _dismiss() {
    if (!mounted || _closing) return;
    _timer?.cancel();
    setState(() => _closing = true);
    final duration = AppMotion.feedbackDurationOf(context);
    if (duration == Duration.zero || _controller.value == 0) {
      widget.remove();
    } else {
      _controller.animateBack(0, duration: duration, curve: AppMotion.curve);
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final topInset = (MediaQuery.sizeOf(context).height * .12).clamp(
      24.0,
      96.0,
    );
    return SafeArea(
      child: Align(
        alignment: Alignment.topCenter,
        child: Padding(
          padding: EdgeInsets.fromLTRB(20, topInset, 20, 0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: AnimatedBuilder(
              animation: _controller,
              builder: (context, child) => Opacity(
                opacity: _controller.value,
                child: Transform.translate(
                  offset: Offset(0, -8 * (1 - _controller.value)),
                  child: child,
                ),
              ),
              child: IgnorePointer(
                ignoring: _closing,
                child: ExcludeSemantics(
                  excluding: _closing,
                  child: Stack(
                    children: [
                      IgnorePointer(
                        child: Material(
                          color: colors.surfaceContainerHigh,
                          elevation: 8,
                          shadowColor: colors.shadow.withValues(alpha: .16),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                            side: BorderSide(color: colors.outlineVariant),
                          ),
                          child: Semantics(
                            liveRegion: true,
                            child: Padding(
                              padding: const EdgeInsets.fromLTRB(
                                18,
                                12,
                                52,
                                12,
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.info_outline_rounded,
                                    color: colors.primary,
                                    size: 22,
                                  ),
                                  const SizedBox(width: 12),
                                  Flexible(
                                    child: IntrinsicHeight(
                                      child: DefaultTextStyle(
                                        style: theme.textTheme.bodyMedium!
                                            .copyWith(color: colors.onSurface),
                                        child: widget.content,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                      Positioned(
                        top: 0,
                        right: 0,
                        child: IconButton(
                          tooltip: MaterialLocalizations.of(context)
                              .closeButtonTooltip,
                          onPressed: _dismiss,
                          icon: const Icon(Icons.close_rounded, size: 18),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
