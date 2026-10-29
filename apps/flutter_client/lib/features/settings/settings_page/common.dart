part of '../settings_page.dart';

/// A preference row: label + optional description on the left, value/control on
/// the right, with a hairline divider below. The whole row is the touch target
/// (>= 44px), and a chevron hints that it opens a detail/edit surface.
class _PreferenceRow extends StatelessWidget {
  const _PreferenceRow({
    required this.label,
    this.subtitle,
    this.value,
    this.onTap,
    this.trailing,
    this.showDivider = true,
  });

  final String label;
  final String? subtitle;
  final String? value;

  /// Whole-row tap (chevron rows / category rows).
  final VoidCallback? onTap;

  /// Optional explicit control (switch, dropdown, …); when present it wins
  /// over [value].
  final Widget? trailing;
  final bool showDivider;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final hasTrailing = trailing != null;
    final labelContent = Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                label,
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface,
                ),
              ),
              if (subtitle != null && subtitle!.isNotEmpty) ...[
                const SizedBox(height: 2),
                Text(
                  subtitle!,
                  style: TextStyle(
                    fontSize: 12,
                    height: 1.3,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
      ],
    );

    final Widget trailingContent;
    if (hasTrailing) {
      trailingContent = trailing!;
    } else {
      trailingContent = Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Flexible(
            child: Text(
              value ?? '',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.end,
              style: TextStyle(
                fontSize: 14,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          if (onTap != null) ...[
            const SizedBox(width: AppTokens.space4),
            Icon(
              Icons.chevron_right_rounded,
              size: 20,
              color: theme.colorScheme.outline,
            ),
          ],
        ],
      );
    }

    final content = Semantics(
      button: onTap != null,
      label: label,
      child: InkWell(
        onTap: onTap,
        customBorder: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        ),
        child: Container(
          constraints: const BoxConstraints(minHeight: 60),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space8,
            vertical: AppTokens.space12,
          ),
          child: LayoutBuilder(
            builder: (context, constraints) {
              final largeText = MediaQuery.textScalerOf(context).scale(14) > 18;
              final stack = trailing != null
                  ? constraints.maxWidth < 500 || largeText
                  : value != null && (constraints.maxWidth < 300 || largeText);
              if (stack) {
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    labelContent,
                    const SizedBox(height: 12),
                    Align(
                      alignment: Alignment.centerLeft,
                      child: trailingContent,
                    ),
                  ],
                );
              }
              return Row(
                children: [
                  Expanded(child: labelContent),
                  const SizedBox(width: AppTokens.space12),
                  if (hasTrailing)
                    ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 248),
                      child: trailingContent,
                    )
                  else
                    Flexible(
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: trailingContent,
                      ),
                    ),
                ],
              );
            },
          ),
        ),
      ),
    );
    return Column(
      children: [
        content,
        if (showDivider)
          Divider(height: 1, color: theme.colorScheme.outlineVariant),
      ],
    );
  }
}

class _SettingsSurface extends StatelessWidget {
  const _SettingsSurface({
    required this.child,
    this.padding = const EdgeInsets.all(AppTokens.space6),
  });

  final Widget child;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final radius = BorderRadius.circular(12);
    return Container(
      decoration: BoxDecoration(borderRadius: radius),
      child: Material(
        color: colors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: radius,
          side: BorderSide(color: colors.border),
        ),
        clipBehavior: Clip.antiAlias,
        child: Padding(padding: padding, child: child),
      ),
    );
  }
}

/// A category page title ("← General" on root/detail, plain on desktop).
class _DetailHeader extends StatelessWidget {
  const _DetailHeader({required this.title, this.onBack, this.subtitle});

  final String title;
  final String? subtitle;
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = AppStringsScope.of(context);
    final leading = onBack == null
        ? null
        : IconButton(
            tooltip: strings.back,
            icon: const Icon(Icons.arrow_back_rounded),
            onPressed: onBack,
          );
    final titleRow = Row(
      children: [
        ?leading,
        Expanded(
          child: Text(
            title,
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.w700,
              color: theme.colorScheme.onSurface,
            ),
          ),
        ),
      ],
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        titleRow,
        if (subtitle != null && subtitle!.isNotEmpty) ...[
          const SizedBox(height: 3),
          Padding(
            padding: EdgeInsets.only(left: onBack == null ? 2 : 12),
            child: Text(
              subtitle!,
              style: TextStyle(
                fontSize: 12,
                height: 1.3,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ],
        const SizedBox(height: AppTokens.space10),
      ],
    );
  }
}

/// A lightweight heading and one bordered group, with consistent spacing.
class _SettingsGroup extends StatelessWidget {
  const _SettingsGroup({
    required this.title,
    required this.children,
    this.subtitle,
  });
  final String title;
  final String? subtitle;
  final List<Widget> children;
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: _SettingsSurface(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              title,
              style: TextStyle(
                fontSize: 14,
                height: 1.3,
                fontWeight: FontWeight.w600,
                color: theme.colorScheme.onSurface,
              ),
            ),
            if (subtitle != null) ...[
              const SizedBox(height: 4),
              Text(
                subtitle!,
                style: TextStyle(
                  fontSize: 12,
                  height: 1.45,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            const SizedBox(height: 18),
            ...children,
          ],
        ),
      ),
    );
  }
}

/// Technical values remain selectable and readable, with a direct copy action.
class _SettingsValue extends StatelessWidget {
  const _SettingsValue({required this.label, required this.value});
  final String label;
  final String value;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 10),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label, style: Theme.of(context).textTheme.bodySmall),
              const SizedBox(height: 4),
              SelectableText(
                value,
                key: PageStorageKey('settings-value-$label-$value'),
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ],
          ),
        ),
        IconButton(
          tooltip: AppStringsScope.of(context).copy,
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: value));
            if (context.mounted) {
              showAppNotice(
                context,
                content: Text(AppStringsScope.of(context).copied),
              );
            }
          },
          icon: const Icon(Icons.copy_outlined, size: 18),
        ),
      ],
    ),
  );
}

/// A regular TextField used inside settings details. Bounded width on desktop
/// (never spans the whole page), full width on mobile.
class _SettingsField extends StatelessWidget {
  const _SettingsField({
    required this.controller,
    required this.label,
    this.helper,
    this.hintText,
    this.keyboardType,
    this.obscureText = false,
    this.errorText,
    this.onSubmitted,
    this.textInputAction,
    this.focusNode,
    this.onChanged,
  });

  final TextEditingController controller;
  final String label;
  final String? helper;
  final String? hintText;
  final TextInputType? keyboardType;
  final bool obscureText;
  final String? errorText;
  final ValueChanged<String>? onSubmitted;
  final TextInputAction? textInputAction;
  final FocusNode? focusNode;
  final ValueChanged<String>? onChanged;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 640),
        child: TextField(
          controller: controller,
          focusNode: focusNode,
          onChanged: onChanged,
          keyboardType: keyboardType,
          textInputAction: textInputAction,
          obscureText: obscureText,
          autocorrect: false,
          enableSuggestions: false,
          smartDashesType: SmartDashesType.disabled,
          smartQuotesType: SmartQuotesType.disabled,
          onSubmitted: onSubmitted,
          onTapOutside: (_) => FocusManager.instance.primaryFocus?.unfocus(),
          decoration: InputDecoration(
            labelText: label,
            hintText: hintText,
            helperText: helper,
            helperMaxLines: 3,
            errorText: errorText,
            errorMaxLines: 3,
          ),
        ),
      ),
    );
  }
}

/// The "unsaved changes" bar. Appears only while a category has edits that are
/// not yet persisted, and disappears once saving succeeds (dirty is recomputed
/// against the store).
class _SaveBar extends StatelessWidget {
  const _SaveBar({
    required this.busy,
    required this.onSave,
    required this.onUndo,
    this.restartRequired = false,
  });

  final bool busy;
  final VoidCallback onSave;
  final VoidCallback onUndo;
  final bool restartRequired;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLow,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space12,
        vertical: AppTokens.space10,
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final label = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                busy
                    ? (strings.isZh ? '正在保存更改' : 'Saving changes')
                    : strings.unsavedChanges,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface,
                ),
              ),
              if (restartRequired) ...[
                const SizedBox(height: 2),
                Text(
                  strings.settingsReconnectImpact,
                  style: TextStyle(
                    fontSize: 12,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          );
          final save = FilledButton.icon(
            key: const Key('settings-save-button'),
            onPressed: busy ? null : onSave,
            icon: busy
                ? const SizedBox.square(
                    dimension: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.save_outlined, size: 16),
            label: Text(
              busy ? (strings.isZh ? '保存中…' : 'Saving…') : strings.saveChanges,
            ),
          );
          final actions = Wrap(
            alignment: WrapAlignment.end,
            spacing: 8,
            runSpacing: 8,
            children: [
              TextButton(
                key: const Key('settings-undo-button'),
                onPressed: busy ? null : onUndo,
                child: Text(strings.settingsUndo),
              ),
              save,
            ],
          );
          if (constraints.maxWidth < 620 ||
              MediaQuery.textScalerOf(context).scale(14) > 18) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                label,
                const SizedBox(height: AppTokens.space10),
                actions,
              ],
            );
          }
          return Row(
            children: [
              Expanded(child: label),
              const SizedBox(width: AppTokens.space14),
              actions,
            ],
          );
        },
      ),
    );
  }
}

/// Restrained error surface shown near the top of a category detail when a
/// save fails validation. Not a giant red banner.
class _SettingsErrorNotice extends StatelessWidget {
  const _SettingsErrorNotice({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: c.dangerSurface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: c.dangerBorder),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space12),
        child: Text(
          message,
          style: TextStyle(color: c.dangerText, fontSize: 13, height: 1.35),
        ),
      ),
    );
  }
}

/// Pending-restart notice. Kept lightweight; a restart button is offered only
/// when the local daemon can actually be controlled.
class _PendingRestartNotice extends StatelessWidget {
  const _PendingRestartNotice({
    required this.busy,
    required this.onRestart,
    required this.canRestart,
  });

  final bool busy;
  final bool canRestart;
  final Future<void> Function() onRestart;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final message = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          strings.restartRequired,
          style: TextStyle(
            color: colors.warningText,
            fontSize: 13,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 3),
        Text(
          canRestart
              ? strings.restartRequiredDetail
              : strings.restartWillApplyLater,
          style: TextStyle(
            color: colors.warningText,
            fontSize: 12,
            height: 1.35,
          ),
        ),
      ],
    );
    return Container(
      decoration: BoxDecoration(
        color: colors.warningSurface,
        border: Border.all(color: colors.warningBorder),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
      ),
      padding: const EdgeInsets.all(AppTokens.space12),
      child: LayoutBuilder(
        builder: (context, constraints) {
          if (!canRestart) return message;
          final action = FilledButton.icon(
            onPressed: busy ? null : onRestart,
            icon: busy
                ? const SizedBox.square(
                    dimension: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.restart_alt_rounded, size: 17),
            label: Text(strings.restartNow),
          );
          if (constraints.maxWidth < 540) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                message,
                const SizedBox(height: AppTokens.space10),
                action,
              ],
            );
          }
          return Row(
            children: [
              Expanded(child: message),
              const SizedBox(width: AppTokens.space14),
              action,
            ],
          );
        },
      ),
    );
  }
}
