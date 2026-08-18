/// Three-tier responsive breakpoints shared by the app shell.
///
///   Compact   <  600   phones / very narrow windows
///   Medium    600-1023 tablets / small desktop windows
///   Expanded  >= 1024  wide desktop windows
///
/// Pages may refine their own internal layouts on top of this (e.g. a list
/// flipping to master-detail), but the shell navigation and top-level page
/// width policy hang off these breakpoints.
enum AppBreakpoint { compact, medium, expanded }

abstract final class AppBreakpoints {
  static const compactMaxWidth = 600.0;
  static const expandedMinWidth = 1024.0;

  static AppBreakpoint of(double width) {
    if (width < compactMaxWidth) return AppBreakpoint.compact;
    if (width < expandedMinWidth) return AppBreakpoint.medium;
    return AppBreakpoint.expanded;
  }
}
