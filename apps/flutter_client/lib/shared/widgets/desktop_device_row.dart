import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/presentation/network_overview.dart';
import '../formatters.dart';
import 'app_motion.dart';
import 'app_notice.dart';
import 'desktop_icon.dart';
import 'device_type_icon.dart';
import 'status_badge.dart';

const _previewBreakpoint = 390.0;
const _previewAddressWidth = 106.0;
const _previewPathWidth = 88.0;
const _previewRttWidth = 56.0;
const _previewActionWidth = 28.0;
const _catalogColumnBreakpoint = 660.0;
const _catalogPadding = AppTokens.space20;
const _catalogActionSize = 24.0;

bool _showPreviewColumns(BuildContext context, double width) =>
    width >= _previewBreakpoint &&
    MediaQuery.textScalerOf(context).scale(13) <= 17;

bool _showCatalogColumns(BuildContext context, double width) =>
    width >= _catalogColumnBreakpoint &&
    MediaQuery.textScalerOf(context).scale(13) <= 17;

/// Column labels for a group of [DesktopDeviceRow]s. Narrow windows keep the
/// same metrics in each row's second line.
class DesktopDeviceListHeader extends StatelessWidget {
  const DesktopDeviceListHeader({
    super.key,
    this.identityLabel,
    this.catalog = false,
  });

  final String? identityLabel;
  final bool catalog;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    if (catalog) {
      return LayoutBuilder(
        builder: (context, constraints) {
          final wide = _showCatalogColumns(context, constraints.maxWidth);
          return Container(
            constraints: const BoxConstraints(minHeight: 38),
            decoration: BoxDecoration(
              border: Border(bottom: BorderSide(color: colors.divider)),
            ),
            padding: const EdgeInsets.symmetric(
              horizontal: _catalogPadding,
              vertical: AppTokens.space8,
            ),
            child: DefaultTextStyle(
              style: Theme.of(context).textTheme.labelSmall!.copyWith(
                color: colors.textSecondary,
                fontWeight: FontWeight.w500,
              ),
              child: _CatalogColumns(
                identity: Text(identityLabel ?? strings.deviceName),
                address: Text(strings.isZh ? '虚拟 IP' : 'Virtual IP'),
                status: Text(strings.isZh ? '状态' : 'Status'),
                path: Text(strings.isZh ? '连接方式' : 'Path'),
                latency: const Text('RTT'),
                wide: wide,
              ),
            ),
          );
        },
      );
    }
    return LayoutBuilder(
      builder: (context, constraints) => DefaultTextStyle(
        style: Theme.of(context).textTheme.labelSmall!
            .copyWith(color: colors.textMuted, fontWeight: FontWeight.w500),
        child: Container(
          decoration: BoxDecoration(
            border: Border(bottom: BorderSide(color: colors.divider)),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space8,
            vertical: AppTokens.space6,
          ),
          child: Row(
            children: [
              Expanded(child: Text(identityLabel ?? strings.deviceName)),
              if (_showPreviewColumns(context, constraints.maxWidth))
                _PreviewMetrics(
                  address: Text(strings.isZh ? '虚拟 IP' : 'Virtual IP'),
                  path: Text(strings.isZh ? '连接' : 'Path'),
                  latency: const Text('RTT'),
                ),
              const SizedBox(width: _previewActionWidth),
            ],
          ),
        ),
      ),
    );
  }
}

/// A read-only view of one scoped peer. Device commands stay with the caller
/// that owns that scope; copying only uses the address shown in this row.
class DesktopDeviceRow extends StatefulWidget {
  const DesktopDeviceRow({
    super.key,
    required this.item,
    this.onOpen,
    this.onDiagnostics,
    this.onSpeedTest,
    this.onRename,
    this.scopeLabel,
    this.selected = false,
    this.rowKey,
    this.catalog = false,
    this.lastInCatalog = false,
  });

  final NetworkPeerSnapshot item;
  final VoidCallback? onOpen;
  final VoidCallback? onDiagnostics;
  final VoidCallback? onSpeedTest;
  final VoidCallback? onRename;
  final String? scopeLabel;
  final bool selected;
  final Key? rowKey;
  final bool catalog;
  final bool lastInCatalog;

  @override
  State<DesktopDeviceRow> createState() => _DesktopDeviceRowState();
}

class _DesktopDeviceRowState extends State<DesktopDeviceRow> {
  final _menu = MenuController();
  final _focusNode = FocusNode(debugLabel: 'Device row');
  var _menuOpen = false;
  var _hovered = false;
  var _rowFocused = false;

  @override
  void dispose() {
    _focusNode.dispose();
    super.dispose();
  }

  Future<void> _copyAddress() async {
    final address = widget.item.peer.virtualIp.trim();
    if (address.isEmpty) return;
    final strings = AppStringsScope.of(context);
    try {
      await Clipboard.setData(ClipboardData(text: address));
      if (!mounted) return;
      showAppNotice(context, content: Text(strings.copied));
    } on PlatformException {
      if (!mounted) return;
      showAppNotice(
        context,
        content: Text(strings.isZh ? '无法复制 IP' : 'Could not copy the IP'),
      );
    }
  }

  void _openMenu([Offset? position]) {
    _focusNode.requestFocus();
    _menu.open(position: position);
  }

  @override
  Widget build(BuildContext context) {
    final item = widget.item;
    final peer = item.peer;
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final hasAddress = peer.virtualIp.trim().isNotEmpty;
    final hasMenu =
        hasAddress ||
        widget.onOpen != null ||
        widget.onDiagnostics != null ||
        widget.onSpeedTest != null ||
        widget.onRename != null;
    final menuLabel = strings.isZh ? '设备操作' : 'Device actions';
    final selected = widget.selected || _menuOpen;
    return MenuAnchor(
      controller: _menu,
      childFocusNode: _focusNode,
      onOpen: () => setState(() => _menuOpen = true),
      onClose: () {
        if (mounted) setState(() => _menuOpen = false);
      },
      style: MenuStyle(
        alignment: AlignmentDirectional.bottomEnd,
        backgroundColor: WidgetStatePropertyAll(colors.surfaceElevated),
        elevation: const WidgetStatePropertyAll(2),
        side: WidgetStatePropertyAll(BorderSide(color: colors.border)),
      ),
      menuChildren: [
        if (widget.onOpen != null)
          MenuItemButton(
            autofocus: true,
            leadingIcon: const Icon(Icons.arrow_forward_rounded, size: 16),
            onPressed: widget.onOpen,
            child: Text(strings.deviceDetails),
          ),
        if (hasAddress)
          MenuItemButton(
            autofocus: widget.onOpen == null,
            leadingIcon: const Icon(Icons.copy_outlined, size: 16),
            onPressed: _copyAddress,
            child: Text(strings.copyVirtualIp),
          ),
        if (widget.onRename != null)
          MenuItemButton(
            leadingIcon: const DesktopIcon('pencil', size: 16),
            onPressed: widget.onRename,
            child: Text(strings.renameDevice),
          ),
        if (widget.onDiagnostics != null)
          MenuItemButton(
            autofocus: widget.onOpen == null && !hasAddress,
            leadingIcon: const Icon(Icons.monitor_heart_outlined, size: 16),
            onPressed: widget.onDiagnostics,
            child: Text(strings.diagnostics),
          ),
        if (widget.onSpeedTest != null)
          MenuItemButton(
            autofocus:
                widget.onOpen == null &&
                !hasAddress &&
                widget.onDiagnostics == null,
            leadingIcon: const Icon(Icons.speed_rounded, size: 16),
            onPressed: widget.onSpeedTest,
            child: Text(strings.speedTest),
          ),
      ],
      builder: (context, controller, _) {
        final radius = widget.catalog
            ? widget.lastInCatalog
                  ? const BorderRadius.vertical(
                      bottom: Radius.circular(AppTokens.radiusLg - 1),
                    )
                  : BorderRadius.zero
            : BorderRadius.circular(AppTokens.radiusSm);
        Widget row = Material(
          type: MaterialType.transparency,
          child: Semantics(
            selected: selected,
            child: InkWell(
              key: widget.rowKey,
              focusNode: _focusNode,
              onFocusChange: widget.catalog ? null : (_) => setState(() {}),
              mouseCursor: widget.onOpen == null
                  ? SystemMouseCursors.basic
                  : SystemMouseCursors.click,
              onTap: widget.onOpen == null
                  ? null
                  : () {
                      _focusNode.requestFocus();
                      widget.onOpen!();
                    },
              onSecondaryTapDown: hasMenu
                  ? (details) => _openMenu(details.localPosition)
                  : null,
              hoverColor: colors.hoverSurface,
              focusColor: colors.selectedSurface,
              borderRadius: radius,
              child: widget.catalog
                  ? _CatalogDeviceRow(
                      item: item,
                      scopeLabel: widget.scopeLabel,
                      borderRadius: radius,
                      last: widget.lastInCatalog,
                      highlighted: selected || _rowFocused,
                      showActions: _hovered || _rowFocused || _menuOpen,
                      onCopy: hasAddress ? _copyAddress : null,
                      onRename: widget.onRename,
                      canOpen: widget.onOpen != null,
                    )
                  : _buildPreview(
                      context,
                      colors,
                      controller,
                      selected,
                      hasMenu,
                      menuLabel,
                    ),
            ),
          ),
        );
        if (widget.catalog) {
          row = MouseRegion(
            onEnter: (_) => setState(() => _hovered = true),
            onExit: (_) => setState(() => _hovered = false),
            child: Focus(
              canRequestFocus: false,
              skipTraversal: true,
              onFocusChange: (value) => setState(() => _rowFocused = value),
              child: row,
            ),
          );
        }
        return CallbackShortcuts(
          bindings: {
            if (hasMenu) ...{
              const SingleActivator(LogicalKeyboardKey.contextMenu): _openMenu,
              const SingleActivator(LogicalKeyboardKey.f10, shift: true):
                  _openMenu,
            },
            if (hasAddress) ...{
              const SingleActivator(LogicalKeyboardKey.keyC, meta: true):
                  _copyAddress,
              const SingleActivator(LogicalKeyboardKey.keyC, control: true):
                  _copyAddress,
            },
          },
          child: row,
        );
      },
    );
  }

  Widget _buildPreview(
    BuildContext context,
    P2WlanColors colors,
    MenuController controller,
    bool selected,
    bool hasMenu,
    String menuLabel,
  ) {
    final item = widget.item;
    final peer = item.peer;
    final theme = Theme.of(context);
    final metricStyle = _metricStyle(theme, colors);
    return AnimatedContainer(
      duration: AppMotion.feedbackDurationOf(context),
      curve: AppMotion.curve,
      decoration: BoxDecoration(
        color: selected && !_focusNode.hasFocus ? colors.selectedSurface : null,
        border: Border(bottom: BorderSide(color: colors.divider)),
      ),
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space8,
        vertical: AppTokens.space4,
      ),
      constraints: BoxConstraints(
        minHeight: MediaQuery.sizeOf(context).width < 900 ? 47 : 54,
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final columns = _showPreviewColumns(
            context,
            constraints.maxWidth + AppTokens.space16,
          );
          final address = Text(
            dash(peer.virtualIp),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: metricStyle,
          );
          final latency = Text(
            item.online ? formatLatency(peer.latencyMs) : '—',
            maxLines: columns ? 1 : null,
            overflow: columns ? TextOverflow.ellipsis : TextOverflow.clip,
            style: metricStyle,
          );
          final path = _CatalogDevicePath(item: item);
          return Row(
            children: [
              _CatalogDeviceIcon(item: item),
              const SizedBox(width: AppTokens.space10),
              Expanded(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      dash(peer.displayName),
                      overflow: TextOverflow.ellipsis,
                      maxLines: columns ? 1 : 2,
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    if (widget.scopeLabel case final scope?)
                      Text(
                        scope,
                        overflow: TextOverflow.ellipsis,
                        maxLines: 1,
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontSize: 11,
                          color: colors.textMuted,
                        ),
                      ),
                    if (!columns)
                      Wrap(
                        spacing: AppTokens.space8,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          address,
                          SizedBox(width: _previewPathWidth, child: path),
                          latency,
                        ],
                      ),
                  ],
                ),
              ),
              if (columns)
                _PreviewMetrics(address: address, path: path, latency: latency),
              SizedBox(
                width: _previewActionWidth,
                child: hasMenu
                    ? IconButton(
                        tooltip: menuLabel,
                        onPressed: () {
                          if (controller.isOpen) {
                            controller.close();
                          } else {
                            _openMenu();
                          }
                        },
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints.tightFor(
                          width: _previewActionWidth,
                          height: _previewActionWidth,
                        ),
                        icon: DesktopIcon(
                          'more',
                          size: 16,
                          color: colors.textMuted,
                        ),
                      )
                    : null,
              ),
            ],
          );
        },
      ),
    );
  }
}

class _CatalogColumns extends StatelessWidget {
  const _CatalogColumns({
    required this.identity,
    required this.address,
    required this.status,
    required this.path,
    required this.latency,
    required this.wide,
    this.tail,
  });

  final Widget identity;
  final Widget address;
  final Widget status;
  final Widget path;
  final Widget latency;
  final bool wide;
  final Widget? tail;

  @override
  Widget build(BuildContext context) {
    if (!wide) {
      return Row(
        children: [
          Expanded(child: identity),
          SizedBox(width: _catalogActionSize, child: tail),
        ],
      );
    }
    return Row(
      spacing: AppTokens.space12,
      children: [
        Expanded(child: identity),
        SizedBox(width: 144, child: address),
        SizedBox(width: 124, child: status),
        SizedBox(width: 103, child: path),
        SizedBox(width: 62, child: latency),
        SizedBox(width: _catalogActionSize, child: tail),
      ],
    );
  }
}

class _CatalogDeviceRow extends StatelessWidget {
  const _CatalogDeviceRow({
    required this.item,
    required this.scopeLabel,
    required this.borderRadius,
    required this.last,
    required this.highlighted,
    required this.showActions,
    required this.onCopy,
    required this.onRename,
    required this.canOpen,
  });

  final NetworkPeerSnapshot item;
  final String? scopeLabel;
  final BorderRadius borderRadius;
  final bool last;
  final bool highlighted;
  final bool showActions;
  final VoidCallback? onCopy;
  final VoidCallback? onRename;
  final bool canOpen;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    final peer = item.peer;
    final largeText = MediaQuery.textScalerOf(context).scale(13) > 17;
    final caption = [
      if (peer.platform.trim().isNotEmpty) peer.platform.trim(),
      ?scopeLabel,
    ].join(' · ');
    final name = Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Flexible(
          child: Text(
            dash(peer.displayName),
            maxLines: largeText ? null : 1,
            overflow: largeText ? TextOverflow.clip : TextOverflow.ellipsis,
            style: theme.textTheme.bodyMedium!.copyWith(
              color: colors.textPrimary,
              fontSize: 14,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        const SizedBox(width: AppTokens.space6),
        _QuickDeviceAction(
          key: Key('node-quick-rename-${peer.nodeId}'),
          tooltip: strings.renameDevice,
          icon: 'pencil',
          onPressed: showActions ? onRename : null,
        ),
      ],
    );
    final address = Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Flexible(
          child: Text(
            dash(peer.virtualIp),
            maxLines: largeText ? null : 1,
            overflow: largeText ? TextOverflow.clip : TextOverflow.ellipsis,
            style: _metricStyle(theme, colors),
          ),
        ),
        const SizedBox(width: AppTokens.space4),
        _QuickDeviceAction(
          key: Key('node-quick-copy-${peer.nodeId}'),
          tooltip: strings.copyVirtualIp,
          icon: 'copy',
          onPressed: showActions ? onCopy : null,
        ),
      ],
    );
    final status = _CatalogDeviceStatus(item: item);
    final path = _CatalogDevicePath(item: item);
    final latency = _DeviceValue(
      value: item.online ? formatLatency(peer.latencyMs) : '—',
    );
    return Container(
      constraints: const BoxConstraints(minHeight: 60),
      decoration: BoxDecoration(
        color: highlighted ? colors.selectedSurface : null,
        border: last ? null : Border(bottom: BorderSide(color: colors.divider)),
        borderRadius: last ? borderRadius : null,
      ),
      padding: const EdgeInsets.symmetric(
        horizontal: _catalogPadding,
        vertical: AppTokens.space8,
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final wide = _showCatalogColumns(
            context,
            constraints.maxWidth + 2 * _catalogPadding,
          );
          return _CatalogColumns(
            wide: wide,
            identity: Row(
              spacing: AppTokens.space10,
              children: [
                _CatalogDeviceIcon(item: item),
                Expanded(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      name,
                      if (caption.isNotEmpty)
                        Text(
                          caption,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodySmall!.copyWith(
                            color: colors.textMuted,
                          ),
                        ),
                      if (!wide)
                        Wrap(
                          spacing: AppTokens.space12,
                          runSpacing: AppTokens.space4,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          children: [
                            address,
                            status,
                            if (item.online) ...[path, latency],
                          ],
                        ),
                    ],
                  ),
                ),
              ],
            ),
            address: address,
            status: status,
            path: path,
            latency: latency,
            tail: canOpen
                ? DesktopIcon(
                    'chevron-right',
                    size: 15,
                    color: colors.textMuted,
                  )
                : null,
          );
        },
      ),
    );
  }
}

class _QuickDeviceAction extends StatelessWidget {
  const _QuickDeviceAction({
    super.key,
    required this.tooltip,
    required this.icon,
    required this.onPressed,
  });

  final String tooltip;
  final String icon;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    return SizedBox.square(
      dimension: _catalogActionSize,
      child: onPressed == null
          ? null
          : IconButton(
              tooltip: tooltip,
              onPressed: onPressed,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints.tightFor(
                width: _catalogActionSize,
                height: _catalogActionSize,
              ),
              visualDensity: VisualDensity.standard,
              style: IconButton.styleFrom(
                backgroundColor: colors.surfaceElevated,
                foregroundColor: Theme.of(context).colorScheme.primary,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(6),
                  side: BorderSide(color: colors.border),
                ),
              ),
              icon: DesktopIcon(icon, size: 13),
            ),
    );
  }
}

class _CatalogDeviceIcon extends StatelessWidget {
  const _CatalogDeviceIcon({required this.item});

  final NetworkPeerSnapshot item;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final icon = peerDeviceKind(item.peer) == PeerDeviceKind.phone
        ? 'smartphone'
        : 'laptop';
    return Container(
      width: 34,
      height: 34,
      decoration: BoxDecoration(
        color: item.online ? colors.selectedSurface : colors.surfaceMuted,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
      ),
      alignment: Alignment.center,
      child: DesktopIcon(
        icon,
        key: Key('node-device-icon-${item.peer.nodeId}'),
        size: 17,
        color: item.online
            ? Theme.of(context).colorScheme.primary
            : colors.textMuted,
      ),
    );
  }
}

class _CatalogDeviceStatus extends StatelessWidget {
  const _CatalogDeviceStatus({required this.item});

  final NetworkPeerSnapshot item;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final (label, tone) = !item.current
        ? (strings.stale, StatusTone.warn)
        : item.online
        ? (strings.online, StatusTone.good)
        : (strings.offline, StatusTone.neutral);
    final badge = StatusBadge(label: label, tone: tone, compact: true);
    if (!item.current || item.online) return badge;
    final seen = item.peer.lastSeenAt;
    final elapsed = seen == null ? null : DateTime.now().difference(seen);
    final colors = P2WlanColors.of(context);
    final relative = _relativeLastSeen(strings, elapsed);
    final error = item.peer.lastError?.trim();
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (error == null || error.isEmpty)
          badge
        else
          Row(
            mainAxisSize: MainAxisSize.min,
            spacing: AppTokens.space4,
            children: [
              Flexible(child: badge),
              Tooltip(
                message: error,
                child: Icon(
                  Icons.warning_amber_rounded,
                  size: 13,
                  color: colors.warningText,
                ),
              ),
            ],
          ),
        Padding(
          padding: const EdgeInsetsDirectional.only(start: AppTokens.space12),
          child: Text(
            relative,
            key: Key('node-last-seen-${item.peer.nodeId}'),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            semanticsLabel: elapsed == null || elapsed.isNegative
                ? '${strings.lastSeen}: ${strings.unavailable}'
                : '${strings.lastSeen}: $relative',
            style: Theme.of(context).textTheme.labelSmall!.copyWith(
              color: colors.textMuted,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
      ],
    );
  }
}

String _relativeLastSeen(AppStrings strings, Duration? elapsed) {
  if (elapsed == null || elapsed.isNegative) return '—';
  if (elapsed.inMinutes == 0) return strings.isZh ? '刚刚' : 'Just now';
  final (amount, unitZh, unitEn) = elapsed.inDays > 0
      ? (elapsed.inDays, '天', 'day')
      : elapsed.inHours > 0
      ? (elapsed.inHours, '小时', 'hour')
      : (elapsed.inMinutes, '分钟', 'minute');
  return strings.isZh
      ? '$amount $unitZh前'
      : "$amount $unitEn${amount == 1 ? '' : 's'} ago";
}

class _CatalogDevicePath extends StatelessWidget {
  const _CatalogDevicePath({required this.item});

  final NetworkPeerSnapshot item;

  @override
  Widget build(BuildContext context) {
    if (!item.online) return const _DeviceValue(value: '—');
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final (label, text, background) = item.peer.isDirectVerified
        ? (
            strings.isZh ? 'P2P 直连' : strings.direct,
            colors.direct,
            colors.selectedSurface,
          )
        : item.peer.isRelayVerified
        ? (
            strings.isZh ? 'Relay 中继' : strings.relay,
            colors.relay,
            colors.warningSurface,
          )
        : (strings.probing, colors.probing, colors.surfaceMuted);
    final error = item.peer.lastError?.trim();
    final chip = Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space8,
        vertical: AppTokens.space2,
      ),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(100),
      ),
      child: Text(
        label,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: Theme.of(context).textTheme.labelSmall!
            .copyWith(color: text, fontWeight: FontWeight.w600),
      ),
    );
    return Align(
      alignment: AlignmentDirectional.centerStart,
      widthFactor: 1,
      heightFactor: 1,
      child: error == null || error.isEmpty
          ? chip
          : Tooltip(message: error, child: chip),
    );
  }
}

class _PreviewMetrics extends StatelessWidget {
  const _PreviewMetrics({
    required this.address,
    required this.path,
    required this.latency,
  });

  final Widget address;
  final Widget path;
  final Widget latency;

  @override
  Widget build(BuildContext context) => Row(
    children: [
      SizedBox(width: _previewAddressWidth, child: address),
      SizedBox(width: _previewPathWidth, child: path),
      SizedBox(width: _previewRttWidth, child: latency),
    ],
  );
}

TextStyle _metricStyle(ThemeData theme, P2WlanColors colors) =>
    theme.textTheme.bodySmall!.copyWith(
      color: colors.textSecondary,
      fontFeatures: AppTokens.tabularFontFeatures,
    );

class _DeviceValue extends StatelessWidget {
  const _DeviceValue({required this.value});

  final String value;

  @override
  Widget build(BuildContext context) {
    if (value.isEmpty) return const SizedBox.shrink();
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final wrap = MediaQuery.textScalerOf(context).scale(13) > 17;
    final unitStart = value.lastIndexOf(' ');
    return AppEntrance(
      identity: value,
      child: Text.rich(
        TextSpan(
          text: unitStart < 0 ? value : value.substring(0, unitStart),
          children: [
            if (unitStart >= 0)
              TextSpan(
                text: value.substring(unitStart),
                style: TextStyle(color: colors.textMuted),
              ),
          ],
        ),
        maxLines: wrap ? null : 1,
        overflow: wrap ? TextOverflow.clip : TextOverflow.ellipsis,
        style: _metricStyle(theme, colors),
      ),
    );
  }
}
