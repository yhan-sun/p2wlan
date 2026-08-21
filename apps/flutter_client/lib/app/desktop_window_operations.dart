import 'dart:async';

/// Serializes calls into the native window plugin.
///
/// The Windows implementation of `window_manager` mutates a shared native
/// window object. Status refreshes, tray actions, and lifecycle callbacks can
/// otherwise issue overlapping method-channel calls while the window is
/// being shown or hidden. Keeping one queue for the whole desktop client
/// avoids that native re-entrancy.
class DesktopWindowOperations {
  DesktopWindowOperations._();

  static Future<void> _tail = Future<void>.value();

  static Future<T> run<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _tail;
    _tail = previous.then<void>(
      (_) => _complete(operation, completer),
      onError: (_, _) => _complete(operation, completer),
    );
    return completer.future;
  }

  static Future<void> _complete<T>(
    Future<T> Function() operation,
    Completer<T> completer,
  ) async {
    try {
      completer.complete(await operation());
    } catch (error, stackTrace) {
      completer.completeError(error, stackTrace);
    }
  }
}
