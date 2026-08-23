import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';

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
/// This replaces the stock dropdown with a product-owned trigger and popup
/// surface. The popup route closes before [onChanged] runs, which also makes
/// immediate theme and language changes safe and visually deterministic.
class AppSelect<T> extends StatelessWidget {
  const AppSelect({
    super.key,
    required this.value,
    required this.options,
    required this.onChanged,
    this.expanded = false,
    this.width = 208,
    this.tooltip,
  });

  final T value;
  final List<AppSelectOption<T>> options;
  final ValueChanged<T>? onChanged;
  final bool expanded;
  final double width;
  final String? tooltip;

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

    final select = Builder(
      builder: (anchorContext) {
        return OutlinedButton(
          onPressed: enabled
              ? () => _openMenu(
                  context: context,
                  anchorContext: anchorContext,
                  colors: colors,
                )
              : null,
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
      },
    );

    final sized = SizedBox(
      width: expanded ? double.infinity : width,
      child: select,
    );
    if (tooltip == null || tooltip!.isEmpty) return sized;
    return Tooltip(message: tooltip!, child: sized);
  }

  Future<void> _openMenu({
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
      return;
    }

    final anchorTopLeft = anchor.localToGlobal(Offset.zero, ancestor: overlay);
    final anchorRect = anchorTopLeft & anchor.size;
    final position = RelativeRect.fromRect(
      anchorRect,
      Offset.zero & overlay.size,
    );

    final nextValue = await showMenu<T>(
      context: context,
      useRootNavigator: true,
      position: position,
      initialValue: value,
      color: colors.surfaceElevated,
      surfaceTintColor: Colors.transparent,
      shadowColor: const Color(0x240F172A),
      elevation: 10,
      constraints: BoxConstraints.tightFor(width: anchor.size.width),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        side: BorderSide(color: colors.border),
      ),
      items: [
        for (final option in options)
          PopupMenuItem<T>(
            key: ValueKey<Object>(('app-select-option', option.value)),
            value: option.value,
            height: 42,
            padding: EdgeInsets.zero,
            mouseCursor: SystemMouseCursors.click,
            child: Container(
              height: 42,
              padding: const EdgeInsets.symmetric(
                horizontal: AppTokens.space12,
              ),
              color: option.value == value
                  ? colors.selectedSurface
                  : Colors.transparent,
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
          ),
      ],
    );
    if (nextValue != null && nextValue != value) onChanged?.call(nextValue);
  }
}
