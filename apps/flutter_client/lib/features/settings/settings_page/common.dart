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
    this.leading,
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
  final Widget? leading;
  final bool showDivider;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final hasTrailing = trailing != null;
    final labelContent = Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        if (leading != null) ...[
          leading!,
          const SizedBox(width: AppTokens.space12),
        ],
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
          constraints: const BoxConstraints(minHeight: 48),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space8,
            vertical: AppTokens.space6,
          ),
          child: LayoutBuilder(
            builder: (context, constraints) {
              // Keep category summaries and simple controls on a shared
              // baseline on phones. Only stack when the available content
              // width is genuinely too small; the previous 460px cutoff made
              // a normal 390px handset stack every value underneath its label
              // and left the settings page visually misaligned.
              if (constraints.maxWidth < 340) {
                final trailingWidth = constraints.maxWidth < 220
                    ? constraints.maxWidth
                    : 220.0;
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    labelContent,
                    const SizedBox(height: AppTokens.space4),
                    Align(
                      alignment: Alignment.centerRight,
                      child: SizedBox(
                        width: hasTrailing
                            ? trailingWidth
                            : constraints.maxWidth,
                        child: Align(
                          alignment: Alignment.centerRight,
                          child: trailingContent,
                        ),
                      ),
                    ),
                  ],
                );
              }
              if (hasTrailing) {
                return Row(
                  children: [
                    Expanded(child: labelContent),
                    const SizedBox(width: AppTokens.space12),
                    Flexible(
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: trailingContent,
                      ),
                    ),
                  ],
                );
              }
              return Row(
                children: [
                  Expanded(child: labelContent),
                  const SizedBox(width: AppTokens.space12),
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
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final radius = BorderRadius.circular(AppTokens.radiusLg);
    return Container(
      decoration: BoxDecoration(
        borderRadius: radius,
        boxShadow: theme.brightness == Brightness.dark
            ? const []
            : AppTokens.shadowBorder,
      ),
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
              fontWeight: FontWeight.w600,
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

/// Lightweight subsection label inside a category detail (virtual network /
/// UDP / relay…). Muted and small — never a big heading or card.
class _SubsectionLabel extends StatelessWidget {
  const _SubsectionLabel(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(
        top: AppTokens.space6,
        bottom: AppTokens.space6,
      ),
      child: Text(
        title,
        style: TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.4,
          color: theme.colorScheme.primary,
        ),
      ),
    );
  }
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

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520),
        child: TextField(
          controller: controller,
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
            errorText: errorText,
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
    this.restartRequired = false,
  });

  final bool busy;
  final VoidCallback onSave;
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
                strings.unsavedChanges,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface,
                ),
              ),
              if (restartRequired) ...[
                const SizedBox(height: 2),
                Text(
                  strings.restartWillApplyLater,
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
              restartRequired
                  ? strings.saveChangesRestartRequired
                  : strings.saveChanges,
            ),
          );
          if (constraints.maxWidth < 480) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                label,
                const SizedBox(height: AppTokens.space10),
                save,
              ],
            );
          }
          return Row(
            children: [
              Expanded(child: label),
              const SizedBox(width: AppTokens.space14),
              save,
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
