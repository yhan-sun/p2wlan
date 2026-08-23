import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../layout/app_breakpoints.dart';

/// A typed option rendered by [AppSelect].
@immutable
class AppSelectOption<T> {
  const AppSelectOption({required this.value, required this.label, this.icon});

  final T value;
  final String label;
  final IconData? icon;
}

/// P2WLAN's consistent select control.
///
/// This replaces the stock dropdown with a product-owned trigger, a compact
/// desktop popover, and a touch-friendly mobile bottom sheet. The selection
/// route closes before [onChanged] runs, which also makes immediate theme and
/// language changes safe and visually deterministic.
class AppSelect<T> extends StatelessWidget {
  const AppSelect({
    super.key,
    required this.value,
    required this.options,
    required this.onChanged,
    this.expanded = false,
    this.width = 208,
    this.tooltip,
    this.menuTitle,
  });

  final T value;
  final List<AppSelectOption<T>> options;
  final ValueChanged<T>? onChanged;
  final bool expanded;
  final double width;
  final String? tooltip;
  final String? menuTitle;

  @override
  Widget build(BuildContext context) {
    assert(options.isNotEmpty, 'AppSelect requires at least one option.');
    assert(
      options.where((option) => option.value == value).length == 1,
      'AppSelect value must match exactly one option.',
    );

    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final selected = options.firstWhere((option) => option.value == value);
    final enabled = onChanged != null;

    return Builder(
      builder: (anchorContext) {
        Future<void> openMenu() => _openMenu(
          context: context,
          anchorContext: anchorContext,
          colors: colors,
        );
        Widget result = OutlinedButton(
          onPressed: enabled ? openMenu : null,
          style: ButtonStyle(
            minimumSize: const WidgetStatePropertyAll(
              Size(0, AppTokens.minTouchTarget),
            ),
            padding: const WidgetStatePropertyAll(
              EdgeInsets.symmetric(horizontal: AppTokens.space12),
            ),
            backgroundColor: WidgetStateProperty.resolveWith((states) {
              if (states.contains(WidgetState.disabled)) {
                return colors.surfaceMuted;
              }
              if (states.contains(WidgetState.hovered)) {
                return colors.hoverSurface;
              }
              return colors.surfaceElevated;
            }),
            foregroundColor: WidgetStateProperty.resolveWith((states) {
              return states.contains(WidgetState.disabled)
                  ? colors.textMuted
                  : colors.textPrimary;
            }),
            side: WidgetStateProperty.resolveWith((states) {
              final focused =
                  states.contains(WidgetState.focused) ||
                  states.contains(WidgetState.pressed);
              return BorderSide(
                color: focused ? theme.colorScheme.primary : colors.border,
                width: focused ? 1.5 : 1,
              );
            }),
            shape: WidgetStatePropertyAll(
              RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              ),
            ),
            elevation: const WidgetStatePropertyAll(0),
          ),
          child: Row(
            children: [
              if (selected.icon != null) ...[
                Icon(selected.icon, size: 18),
                const SizedBox(width: AppTokens.space8),
              ],
              Expanded(
                child: Text(
                  selected.label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.left,
                  style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              const SizedBox(width: AppTokens.space8),
              Icon(
                Icons.keyboard_arrow_down_rounded,
                size: 19,
                color: enabled ? colors.textSecondary : colors.textMuted,
              ),
            ],
          ),
        );
        result = SizedBox(
          width: expanded ? double.infinity : width,
          child: result,
        );
        if (tooltip != null && tooltip!.isNotEmpty) {
          result = Tooltip(message: tooltip!, child: result);
        }
        if (menuTitle != null && menuTitle!.trim().isNotEmpty) {
          result = Semantics(
            container: true,
            button: true,
            enabled: enabled,
            label: menuTitle,
            value: selected.label,
            onTap: enabled ? openMenu : null,
            excludeSemantics: true,
            child: result,
          );
        }
        return result;
      },
    );
  }

  Future<void> _openMenu({
    required BuildContext context,
    required BuildContext anchorContext,
    required P2WlanColors colors,
  }) async {
    final nextValue = _usesMobileSheet(context)
        ? await _openMobileSheet(context)
        : await _openPopover(
            context: context,
            anchorContext: anchorContext,
            colors: colors,
          );
    if (nextValue != null && nextValue != value) onChanged?.call(nextValue);
  }

  bool _usesMobileSheet(BuildContext context) {
    if (kIsWeb) return false;
    final isMobilePlatform = switch (defaultTargetPlatform) {
      TargetPlatform.android ||
      TargetPlatform.iOS ||
      TargetPlatform.fuchsia => true,
      _ => false,
    };
    if (!isMobilePlatform) return false;
    // Stay touch-first when a phone rotates: width alone would turn an
    // 844x390 handset into a desktop popover. Shortest-side is stable across
    // orientation and still lets larger tablets use the anchored menu.
    return MediaQuery.sizeOf(context).shortestSide <
        AppBreakpoints.compactMaxWidth;
  }

  Future<T?> _openMobileSheet(BuildContext context) {
    return showModalBottomSheet<T>(
      context: context,
      useRootNavigator: true,
      isScrollControlled: true,
      useSafeArea: true,
      backgroundColor: Colors.transparent,
      barrierColor: Colors.black.withValues(alpha: 0.52),
      builder: (sheetContext) =>
          _AppSelectSheet<T>(title: menuTitle, value: value, options: options),
    );
  }

  Future<T?> _openPopover({
    required BuildContext context,
    required BuildContext anchorContext,
    required P2WlanColors colors,
  }) async {
    final anchor = anchorContext.findRenderObject() as RenderBox?;
    final overlay =
        Navigator.of(
              context,
              rootNavigator: true,
            ).overlay?.context.findRenderObject()
            as RenderBox?;
    if (anchor == null ||
        overlay == null ||
        !anchor.hasSize ||
        !overlay.hasSize) {
      return null;
    }

    final anchorTopLeft = anchor.localToGlobal(Offset.zero, ancestor: overlay);
    final anchorRect = anchorTopLeft & anchor.size;
    final position = RelativeRect.fromRect(
      anchorRect,
      Offset.zero & overlay.size,
    );

    return showMenu<T>(
      context: context,
      useRootNavigator: true,
      position: position,
      color: colors.surfaceElevated,
      surfaceTintColor: Colors.transparent,
      shadowColor: const Color(0x240F172A),
      elevation: 10,
      menuPadding: const EdgeInsets.all(AppTokens.space6),
      clipBehavior: Clip.antiAlias,
      constraints: BoxConstraints.tightFor(
        width: anchor.size.width < 220 ? 220 : anchor.size.width,
      ),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        side: BorderSide(color: colors.border),
      ),
      items: [
        for (final option in options)
          _AppSelectPopoverItem<T>(
            optionKey: ValueKey<Object>(('app-select-option', option.value)),
            value: option.value,
            selected: option.value == value,
            selectedColor: colors.selectedSurface,
            borderColor: option.value == value
                ? Theme.of(context).colorScheme.primary.withValues(alpha: 0.22)
                : Colors.transparent,
            hoverColor: colors.hoverSurface,
            splashColor: Theme.of(
              context,
            ).colorScheme.primary.withValues(alpha: 0.08),
            child: Row(
              children: [
                if (option.icon != null) ...[
                  Icon(option.icon, size: 18),
                  const SizedBox(width: AppTokens.space8),
                ],
                Expanded(
                  child: Text(
                    option.label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: option.value == value
                          ? Theme.of(context).colorScheme.primary
                          : colors.textPrimary,
                      fontSize: 13,
                      fontWeight: option.value == value
                          ? FontWeight.w600
                          : FontWeight.w500,
                    ),
                  ),
                ),
                if (option.value == value)
                  Icon(
                    Icons.check_rounded,
                    size: 18,
                    color: Theme.of(context).colorScheme.primary,
                  )
                else
                  const SizedBox(width: 18),
              ],
            ),
          ),
      ],
    );
  }
}

/// A popup entry with one clipped shape for its fill, border, hover, focus,
/// and splash states. Flutter's stock [PopupMenuItem] paints its selected
/// highlight around the whole rectangular entry when `initialValue` is used,
/// which visibly cuts through a rounded product menu.
class _AppSelectPopoverItem<T> extends PopupMenuEntry<T> {
  const _AppSelectPopoverItem({
    required this.optionKey,
    required this.value,
    required this.selected,
    required this.selectedColor,
    required this.borderColor,
    required this.hoverColor,
    required this.splashColor,
    required this.child,
  });

  final Key optionKey;
  final T value;
  final bool selected;
  final Color selectedColor;
  final Color borderColor;
  final Color hoverColor;
  final Color splashColor;
  final Widget child;

  @override
  double get height => 48;

  @override
  bool represents(T? value) => value == this.value;

  @override
  State<_AppSelectPopoverItem<T>> createState() =>
      _AppSelectPopoverItemState<T>();
}

class _AppSelectPopoverItemState<T> extends State<_AppSelectPopoverItem<T>> {
  @override
  Widget build(BuildContext context) {
    final radius = BorderRadius.circular(AppTokens.radiusMd);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: AppTokens.space2),
      child: Semantics(
        button: true,
        selected: widget.selected,
        child: Material(
          key: ValueKey<Object>(('app-select-option-surface', widget.value)),
          color: widget.selected ? widget.selectedColor : Colors.transparent,
          shape: RoundedRectangleBorder(
            borderRadius: radius,
            side: BorderSide(color: widget.borderColor),
          ),
          clipBehavior: Clip.antiAlias,
          child: InkWell(
            key: widget.optionKey,
            onTap: () => Navigator.pop<T>(context, widget.value),
            mouseCursor: SystemMouseCursors.click,
            borderRadius: radius,
            hoverColor: widget.hoverColor,
            focusColor: widget.hoverColor,
            splashColor: widget.splashColor,
            child: SizedBox(
              height: 44,
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: AppTokens.space12,
                ),
                child: widget.child,
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _AppSelectSheet<T> extends StatelessWidget {
  const _AppSelectSheet({
    required this.title,
    required this.value,
    required this.options,
  });

  final String? title;
  final T value;
  final List<AppSelectOption<T>> options;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final media = MediaQuery.of(context);
    return Container(
      key: const Key('app-select-mobile-sheet'),
      constraints: BoxConstraints(maxHeight: media.size.height * 0.72),
      decoration: BoxDecoration(
        color: colors.surfaceElevated,
        borderRadius: const BorderRadius.vertical(
          top: Radius.circular(AppTokens.radiusLg * 1.5),
        ),
        border: Border(top: BorderSide(color: colors.border)),
        boxShadow: const [
          BoxShadow(
            color: Color(0x33000000),
            blurRadius: 28,
            offset: Offset(0, -8),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: AppTokens.space10),
          Container(
            width: 38,
            height: 4,
            decoration: BoxDecoration(
              color: colors.borderStrong,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          if (title != null && title!.trim().isNotEmpty) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(
                AppTokens.space20,
                AppTokens.space14,
                AppTokens.space8,
                AppTokens.space8,
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      title!,
                      style: TextStyle(
                        color: theme.colorScheme.onSurface,
                        fontSize: 17,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  IconButton(
                    key: const Key('app-select-sheet-close'),
                    tooltip: MaterialLocalizations.of(
                      context,
                    ).closeButtonTooltip,
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close_rounded),
                  ),
                ],
              ),
            ),
            Divider(height: 1, color: colors.divider),
          ] else
            const SizedBox(height: AppTokens.space10),
          Flexible(
            child: ListView.separated(
              shrinkWrap: true,
              padding: const EdgeInsets.fromLTRB(
                AppTokens.space12,
                AppTokens.space8,
                AppTokens.space12,
                AppTokens.space16,
              ),
              itemCount: options.length,
              separatorBuilder: (_, _) =>
                  const SizedBox(height: AppTokens.space6),
              itemBuilder: (context, index) {
                final option = options[index];
                final selected = option.value == value;
                return Semantics(
                  selected: selected,
                  button: true,
                  child: Material(
                    color: selected
                        ? colors.selectedSurface
                        : Colors.transparent,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                      side: BorderSide(
                        color: selected
                            ? theme.colorScheme.primary.withValues(alpha: 0.28)
                            : colors.border,
                      ),
                    ),
                    clipBehavior: Clip.antiAlias,
                    child: InkWell(
                      key: ValueKey<Object>((
                        'app-select-option',
                        option.value,
                      )),
                      onTap: () {
                        HapticFeedback.selectionClick();
                        Navigator.of(context).pop(option.value);
                      },
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(minHeight: 54),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: AppTokens.space14,
                            vertical: AppTokens.space10,
                          ),
                          child: Row(
                            children: [
                              if (option.icon != null) ...[
                                Container(
                                  width: 34,
                                  height: 34,
                                  alignment: Alignment.center,
                                  decoration: BoxDecoration(
                                    color: selected
                                        ? theme.colorScheme.primary.withValues(
                                            alpha: 0.10,
                                          )
                                        : colors.surfaceMuted,
                                    borderRadius: BorderRadius.circular(
                                      AppTokens.radiusSm,
                                    ),
                                  ),
                                  child: Icon(
                                    option.icon,
                                    size: 18,
                                    color: selected
                                        ? theme.colorScheme.primary
                                        : colors.textSecondary,
                                  ),
                                ),
                                const SizedBox(width: AppTokens.space12),
                              ],
                              Expanded(
                                child: Text(
                                  option.label,
                                  style: TextStyle(
                                    color: selected
                                        ? theme.colorScheme.primary
                                        : colors.textPrimary,
                                    fontSize: 15,
                                    fontWeight: selected
                                        ? FontWeight.w700
                                        : FontWeight.w600,
                                  ),
                                ),
                              ),
                              const SizedBox(width: AppTokens.space12),
                              AnimatedContainer(
                                duration: AppTokens.durationFast,
                                width: 24,
                                height: 24,
                                alignment: Alignment.center,
                                decoration: BoxDecoration(
                                  color: selected
                                      ? theme.colorScheme.primary
                                      : Colors.transparent,
                                  shape: BoxShape.circle,
                                  border: Border.all(
                                    color: selected
                                        ? theme.colorScheme.primary
                                        : colors.borderStrong,
                                  ),
                                ),
                                child: selected
                                    ? Icon(
                                        Icons.check_rounded,
                                        size: 16,
                                        color: theme.colorScheme.onPrimary,
                                      )
                                    : null,
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
