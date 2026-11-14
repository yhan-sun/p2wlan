import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/presentation/network_overview.dart';
import '../formatters.dart';
import 'app_motion.dart';
import 'app_notice.dart';
import 'device_type_icon.dart';

const _metricBreakpoint = 468.0;
const _pathWidth = 96.0;
const _rttWidth = 68.0;
const _rateWidth = 88.0;
const _actionWidth = 36.0;
const _identityIconSize = 32.0;

bool _showMetricColumns(BuildContext context, double width) =>
    width >= _metricBreakpoint &&
    MediaQuery.textScalerOf(context).scale(13) <= 17;

/// Column labels for a group of [DesktopDeviceRow]s. Narrow windows keep the
/// same metrics in each row's second line.
class DesktopDeviceListHeader extends StatelessWidget {
  const DesktopDeviceListHeader({super.key, this.identityLabel});

  final String? identityLabel;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    return LayoutBuilder(
      builder: (context, constraints) => DefaultTextStyle(
        style: Theme.of(context).textTheme.labelSmall!
            .copyWith(color: colors.textSecondary, fontWeight: FontWeight.w500),
        child: Container(
          decoration: BoxDecoration(
            border: Border(bottom: BorderSide(color: colors.divider)),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: AppTokens.space12,
            vertical: AppTokens.space8,
          ),
          child: Row(
            children: [
              Expanded(child: Text(identityLabel ?? strings.deviceName)),
              if (_showMetricColumns(context, constraints.maxWidth))
                _DeviceMetricColumns(
                  path: Text(strings.isZh ? '连接方式' : 'Path'),
                  latency: const Text('RTT'),
                  rate: Text(strings.isZh ? '速率' : 'Rate'),
                ),
              const SizedBox(width: _actionWidth),
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
    this.scopeLabel,
    this.selected = false,
    this.rowKey,
  });

  final NetworkPeerSnapshot item;
  final VoidCallback? onOpen;
  final VoidCallback? onDiagnostics;
  final VoidCallback? onSpeedTest;
  final String? scopeLabel;
  final bool selected;
  final Key? rowKey;

  @override
  State<DesktopDeviceRow> createState() => _DesktopDeviceRowState();
}

class _DesktopDeviceRowState extends State<DesktopDeviceRow> {
  final _menu = MenuController();
  final _focusNode = FocusNode(debugLabel: 'Device row');
  var _menuOpen = false;

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
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final hasAddress = peer.virtualIp.trim().isNotEmpty;
    final hasMenu =
        hasAddress ||
        widget.onOpen != null ||
        widget.onDiagnostics != null ||
        widget.onSpeedTest != null;
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
      builder: (context, controller, _) => CallbackShortcuts(
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
        child: Material(
          type: MaterialType.transparency,
          child: Semantics(
            selected: selected,
            child: InkWell(
              key: widget.rowKey,
              focusNode: _focusNode,
              onFocusChange: (_) => setState(() {}),
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
              borderRadius: BorderRadius.circular(AppTokens.radiusSm),
              child: AnimatedContainer(
                duration: AppMotion.feedbackDurationOf(context),
                curve: AppMotion.curve,
                decoration: BoxDecoration(
                  color: selected && !_focusNode.hasFocus
                      ? colors.selectedSurface
                      : null,
                  border: Border(bottom: BorderSide(color: colors.divider)),
                ),
                padding: const EdgeInsets.symmetric(
                  horizontal: AppTokens.space12,
                  vertical: AppTokens.space4,
                ),
                child: LayoutBuilder(
                  builder: (context, constraints) {
                    final columns = _showMetricColumns(
                      context,
                      constraints.maxWidth + AppTokens.space24,
                    );
                    final path = _DevicePathLabel(item: item);
                    final latency = _DeviceValue(
                      value: item.online ? formatLatency(peer.latencyMs) : '',
                    );
                    final rate = _DeviceValue(
                      value: item.online
                          ? formatTransferRate(item.transferBytesPerSecond)
                          : '',
                    );
                    final metrics = _DeviceMetricColumns(
                      path: path,
                      latency: latency,
                      rate: rate,
                    );
                    return Row(
                      children: [
                        _DeviceIdentityIcon(item: item),
                        const SizedBox(width: AppTokens.space12),
                        Expanded(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                dash(peer.displayName),
                                overflow: TextOverflow.ellipsis,
                                maxLines: columns ? 1 : 2,
                                style: theme.textTheme.titleMedium!.copyWith(
                                  fontSize: 14,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              Row(
                                children: [
                                  Flexible(
                                    child: Text(
                                      dash(peer.virtualIp),
                                      overflow: TextOverflow.ellipsis,
                                      maxLines: 1,
                                      style: theme.textTheme.bodySmall!
                                          .copyWith(
                                            color: colors.textSecondary,
                                            fontFeatures:
                                                AppTokens.tabularFontFeatures,
                                          ),
                                    ),
                                  ),
                                  if (widget.scopeLabel case final scope?)
                                    Flexible(
                                      child: Tooltip(
                                        message: scope,
                                        child: Text(
                                          '  ·  $scope',
                                          overflow: TextOverflow.ellipsis,
                                          maxLines: 1,
                                          style: theme.textTheme.bodySmall!
                                              .copyWith(
                                                color: colors.textMuted,
                                              ),
                                        ),
                                      ),
                                    ),
                                ],
                              ),
                              if (!columns)
                                Wrap(
                                  spacing: AppTokens.space12,
                                  crossAxisAlignment: WrapCrossAlignment.center,
                                  children: [
                                    path,
                                    if (item.online && peer.latencyMs != null)
                                      Text(
                                        'RTT ${formatLatency(peer.latencyMs)}',
                                        style: _metricStyle(theme, colors),
                                      ),
                                    if (item.online &&
                                        item.transferBytesPerSecond != null)
                                      rate,
                                  ],
                                ),
                            ],
                          ),
                        ),
                        if (columns) metrics,
                        SizedBox(
                          width: _actionWidth,
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
                                  visualDensity: VisualDensity.compact,
                                  icon: Icon(
                                    Icons.more_horiz_rounded,
                                    size: 18,
                                    color: colors.textSecondary,
                                  ),
                                )
                              : null,
                        ),
                      ],
                    );
                  },
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _DeviceMetricColumns extends StatelessWidget {
  const _DeviceMetricColumns({
    required this.path,
    required this.latency,
    required this.rate,
  });

  final Widget path;
  final Widget latency;
  final Widget rate;

  @override
  Widget build(BuildContext context) => Row(
    children: [
      SizedBox(width: _pathWidth, child: path),
      SizedBox(
        width: _rttWidth,
        child: Align(alignment: AlignmentDirectional.centerEnd, child: latency),
      ),
      SizedBox(
        width: _rateWidth,
        child: Align(alignment: AlignmentDirectional.centerEnd, child: rate),
      ),
      const SizedBox(width: AppTokens.space8),
    ],
  );
}

class _DeviceIdentityIcon extends StatelessWidget {
  const _DeviceIdentityIcon({required this.item});

  final NetworkPeerSnapshot item;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final (label, dot) = !item.current
        ? (strings.stale, colors.warningDot)
        : item.online
        ? (strings.online, colors.successDot)
        : (strings.offline, colors.neutralDot);
    return Tooltip(
      message: label,
      child: SizedBox.square(
        dimension: _identityIconSize,
        child: Stack(
          children: [
            Positioned.fill(
              child: DecoratedBox(
                decoration: BoxDecoration(
                  color: colors.surfaceMuted,
                  borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                ),
                child: Icon(
                  key: Key('node-device-icon-${item.peer.nodeId}'),
                  peerDeviceIcon(item.peer),
                  size: 17,
                  color: colors.textSecondary,
                ),
              ),
            ),
            PositionedDirectional(
              end: 0,
              bottom: 0,
              child: DecoratedBox(
                decoration: BoxDecoration(
                  color: dot,
                  shape: BoxShape.circle,
                  border: Border.all(color: colors.surface, width: 1),
                ),
                child: const SizedBox.square(dimension: AppTokens.space8),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _DevicePathLabel extends StatelessWidget {
  const _DevicePathLabel({required this.item});

  final NetworkPeerSnapshot item;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final (label, color, icon) = !item.current
        ? (strings.stale, colors.warningText, Icons.history_rounded)
        : !item.online
        ? (strings.offline, colors.offline, Icons.link_off_rounded)
        : item.peer.isDirectVerified
        ? (strings.direct, colors.direct, Icons.north_east_rounded)
        : item.peer.isRelayVerified
        ? (strings.relay, colors.relay, Icons.alt_route_rounded)
        : (strings.probing, colors.probing, Icons.more_horiz_rounded);
    final error = item.peer.lastError?.trim();
    return AppEntrance(
      identity: label,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: AppTokens.space4),
          Flexible(
            child: Text(
              label,
              overflow: TextOverflow.ellipsis,
              maxLines: 1,
              style: Theme.of(context).textTheme.bodySmall!
                  .copyWith(fontWeight: FontWeight.w600, color: color),
            ),
          ),
          if (error != null && error.isNotEmpty) ...[
            const SizedBox(width: AppTokens.space4),
            Tooltip(
              message: error,
              child: Icon(
                Icons.warning_amber_rounded,
                size: 13,
                color: colors.warningText,
              ),
            ),
          ],
        ],
      ),
    );
  }
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
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: _metricStyle(theme, colors),
      ),
    );
  }
}
