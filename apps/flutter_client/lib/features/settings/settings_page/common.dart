part of '../settings_page.dart';

const _settingsControlWidth = 248.0;

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
    this.inlineControl = false,
    this.controlHasLabel = false,
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
  final bool inlineControl;
  final bool controlHasLabel;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final desktop = _usesDesktopSettings(context);
    final titleStyle = theme.textTheme.bodyMedium?.copyWith(
      fontWeight: FontWeight.w500,
    );
    final descriptionStyle = theme.textTheme.bodySmall?.copyWith(
      color: theme.colorScheme.onSurfaceVariant,
    );
    final hasTrailing = trailing != null;
    final labelContent = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        ExcludeSemantics(
          excluding: controlHasLabel,
          child: Semantics(
            container: true,
            child: Text(label, style: titleStyle),
          ),
        ),
        if (subtitle != null && subtitle!.isNotEmpty) ...[
          const SizedBox(height: AppTokens.space4),
          Semantics(
            container: true,
            child: Text(subtitle!, style: descriptionStyle),
          ),
        ],
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
      child: InkWell(
        onTap: onTap,
        customBorder: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        ),
        child: Container(
          constraints: BoxConstraints(minHeight: desktop ? 48 : 60),
          padding: EdgeInsets.symmetric(
            vertical: desktop ? AppTokens.space6 : AppTokens.space12,
          ),
          child: LayoutBuilder(
            builder: (context, constraints) {
              if (inlineControl) {
                if (desktop) {
                  return MergeSemantics(
                    child: Row(
                      children: [
                        Expanded(child: labelContent),
                        const SizedBox(width: AppTokens.space12),
                        trailingContent,
                      ],
                    ),
                  );
                }
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    MergeSemantics(
                      child: Row(
                        children: [
                          Expanded(child: Text(label, style: titleStyle)),
                          const SizedBox(width: AppTokens.space12),
                          trailingContent,
                        ],
                      ),
                    ),
                    if (subtitle != null && subtitle!.isNotEmpty)
                      Text(subtitle!, style: descriptionStyle),
                  ],
                );
              }
              final largeText = MediaQuery.textScalerOf(context).scale(14) > 18;
              final stack = trailing != null
                  ? constraints.maxWidth < (desktop ? 420 : 500) || largeText
                  : value != null && (constraints.maxWidth < 300 || largeText);
              if (stack) {
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    labelContent,
                    const SizedBox(height: AppTokens.space12),
                    Align(
                      alignment: AlignmentDirectional.centerStart,
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
                      constraints: const BoxConstraints(
                        maxWidth: _settingsControlWidth,
                      ),
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
        if (desktop)
          Material(type: MaterialType.transparency, child: content)
        else
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
  const _DetailHeader({required this.title, this.onBack});

  static double leadingExtent({required bool desktop}) =>
      _backSize(desktop) + _backGap(desktop);

  static double _backSize(bool desktop) =>
      desktop ? AppTokens.desktopControlHeight : AppTokens.minTouchTarget;

  static double _backGap(bool desktop) =>
      desktop ? AppTokens.space4 : AppTokens.space8;

  final String title;
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final desktop = _usesDesktopSettings(context);
    return Row(
      children: [
        if (onBack != null) ...[
          SizedBox.square(
            dimension: _backSize(desktop),
            child: AppBackButton(
              key: const Key('settings-category-back'),
              onPressed: onBack,
            ),
          ),
          SizedBox(width: _backGap(desktop)),
        ],
        Expanded(
          child: Semantics(
            header: true,
            child: Text(
              title,
              style: desktop
                  ? theme.textTheme.titleLarge
                  : theme.textTheme.titleMedium,
            ),
          ),
        ),
      ],
    );
  }
}

/// Groups related preferences under a heading and a shared boundary.
class _SettingsGroup extends StatelessWidget {
  const _SettingsGroup({
    required this.title,
    required this.children,
    this.subtitle,
    this.headingStatus,
  });
  final String title;
  final String? subtitle;
  final String? headingStatus;
  final List<Widget> children;
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final desktop = _usesDesktopSettings(context);
    final titleStyle = desktop
        ? theme.textTheme.titleSmall
        : theme.textTheme.titleMedium;
    final heading = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (headingStatus case final message?)
          Row(
            children: [
              Expanded(
                child: Semantics(
                  header: true,
                  child: Text(title, style: titleStyle),
                ),
              ),
              const SizedBox(width: AppTokens.space8),
              Flexible(
                child: Semantics(
                  container: true,
                  liveRegion: true,
                  child: Text(
                    message,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: titleStyle?.copyWith(
                      color: theme.colorScheme.primary,
                    ),
                  ),
                ),
              ),
            ],
          )
        else
          Semantics(header: true, child: Text(title, style: titleStyle)),
        if (subtitle != null) ...[
          const SizedBox(height: AppTokens.space4),
          Text(
            subtitle!,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
    if (desktop) {
      return Padding(
        padding: const EdgeInsets.only(bottom: AppTokens.space16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            heading,
            const SizedBox(height: AppTokens.space6),
            const Divider(height: 1),
            const SizedBox(height: AppTokens.space4),
            ...children,
          ],
        ),
      );
    }
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: _SettingsSurface(
        padding: EdgeInsets.all(
          MediaQuery.sizeOf(context).width < 480 ? 16 : 20,
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [heading, const SizedBox(height: 16), ...children],
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
    this.asPreference = false,
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
  final bool asPreference;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final desktop = _usesDesktopSettings(context);
    // The macOS Flutter bridge uses a native editable view that doesn't expose
    // the Flutter field label. Keep the adjacent static text discoverable too.
    final keepVisibleLabelInSemantics = theme.platform == TargetPlatform.macOS;
    final field = TextField(
      key: ValueKey('settings-field-$label'),
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
        labelText: desktop ? null : label,
        floatingLabelBehavior: FloatingLabelBehavior.always,
        floatingLabelStyle: const TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.w600,
        ),
        constraints: desktop
            ? const BoxConstraints(minHeight: AppTokens.desktopControlHeight)
            : null,
        visualDensity: desktop ? VisualDensity.standard : null,
        hintText: hintText,
        helper: helper == null || (desktop && asPreference)
            ? null
            : Text(
                helper!,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
        errorText: errorText,
        errorMaxLines: 3,
      ),
    );
    final labeledField = Semantics(container: true, label: label, child: field);
    if (desktop && asPreference) {
      return _PreferenceRow(
        label: label,
        subtitle: errorText == null ? helper : null,
        controlHasLabel: !keepVisibleLabelInSemantics,
        trailing: SizedBox(width: _settingsControlWidth, child: labeledField),
        showDivider: false,
      );
    }
    return Align(
      alignment: AlignmentDirectional.centerStart,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 640),
        child: desktop
            ? Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  ExcludeSemantics(
                    excluding: !keepVisibleLabelInSemantics,
                    child: Semantics(
                      container: true,
                      child: Text(label, style: theme.textTheme.titleSmall),
                    ),
                  ),
                  const SizedBox(height: AppTokens.space4),
                  labeledField,
                ],
              )
            : field,
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
          final label = Semantics(
            liveRegion: true,
            child: Column(
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
            ),
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
            label: IndexedStack(
              index: busy ? 1 : 0,
              alignment: Alignment.center,
              children: [
                Text(strings.saveChanges),
                Text(strings.isZh ? '保存中…' : 'Saving…'),
              ],
            ),
          );
          final undo = TextButton(
            key: const Key('settings-undo-button'),
            onPressed: busy ? null : onUndo,
            child: Text(strings.settingsUndo),
          );
          final largeText = MediaQuery.textScalerOf(context).scale(14) > 18;
          if (constraints.maxWidth < 400 || largeText) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                label,
                const SizedBox(height: 12),
                save,
                const SizedBox(height: 4),
                Align(alignment: Alignment.centerRight, child: undo),
              ],
            );
          }
          final actions = Row(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.end,
            children: [undo, const SizedBox(width: 8), save],
          );
          if (constraints.maxWidth < 620) {
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
    return Semantics(
      liveRegion: true,
      child: DecoratedBox(
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
    final message = Semantics(
      liveRegion: true,
      child: Column(
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
                ? (strings.isZh
                      ? '重新连接会短暂中断本机默认连接。'
                      : 'Reconnecting briefly interrupts the default local connection.')
                : strings.restartWillApplyLater,
            style: TextStyle(
              color: colors.warningText,
              fontSize: 12,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
    return Container(
      decoration: BoxDecoration(
        color: colors.warningSurface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
      ),
      padding: const EdgeInsets.all(AppTokens.space12),
      child: LayoutBuilder(
        builder: (context, constraints) {
          if (!canRestart) return message;
          final action = TextButton.icon(
            onPressed: busy ? null : onRestart,
            icon: busy
                ? const SizedBox.square(
                    dimension: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.restart_alt_rounded, size: 17),
            label: Text(strings.restartNow),
          );
          if (constraints.maxWidth < 420 ||
              MediaQuery.textScalerOf(context).scale(14) > 18) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
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
