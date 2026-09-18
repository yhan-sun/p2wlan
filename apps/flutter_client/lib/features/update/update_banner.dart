import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/update/update_models.dart';

class UpdateBanner extends StatelessWidget {
  const UpdateBanner({
    super.key,
    required this.result,
    required this.onOpen,
    required this.onDismiss,
  });

  final UpdateCheckResult result;
  final VoidCallback onOpen;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final update = result.update;
    if (!result.hasUpdate || update == null) return const SizedBox.shrink();
    return Material(
      color: colors.selectedSurface,
      child: Container(
        key: const Key('automatic-update-banner'),
        width: double.infinity,
        padding: const EdgeInsets.fromLTRB(
          AppTokens.space16,
          AppTokens.space10,
          AppTokens.space8,
          AppTokens.space10,
        ),
        decoration: BoxDecoration(
          border: Border(
            bottom: BorderSide(color: theme.colorScheme.outlineVariant),
          ),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Icon(
              Icons.system_update_outlined,
              color: theme.colorScheme.primary,
            ),
            const SizedBox(width: AppTokens.space12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    strings.updateBannerTitle,
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    strings.updateBannerBody(
                      result.currentAppVersion,
                      update.version.tag,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: AppTokens.space8),
            FilledButton(
              key: const Key('automatic-update-open-button'),
              onPressed: onOpen,
              child: Text(strings.viewNewVersion),
            ),
            IconButton(
              key: const Key('automatic-update-dismiss-button'),
              tooltip: strings.dismissUpdate,
              onPressed: onDismiss,
              icon: const Icon(Icons.close_rounded),
            ),
          ],
        ),
      ),
    );
  }
}
