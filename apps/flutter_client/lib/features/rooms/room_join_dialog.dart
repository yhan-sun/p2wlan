import 'dart:convert';

import 'package:flutter/material.dart';

import '../../core/rooms/room_api.dart';
import '../../app/p2wlan_colors.dart';
import 'room_strings.dart';

class RoomJoinRequest {
  const RoomJoinRequest(this.code, {this.password, this.invitation});
  final String code;
  final String? password;
  final String? invitation;
}

/// One input supports both existing join formats, with validation before the
/// caller can make a request. Invitation credentials remain in the URI fragment.
class RoomJoinDialog extends StatefulWidget {
  const RoomJoinDialog({
    super.key,
    required this.server,
    required this.onJoin,
    required this.isCurrent,
    this.initial = '',
    this.languageCode = 'zh-CN',
  });
  final String server;
  final String initial;
  final String languageCode;
  // A null result means the owning account session is no longer current.
  final Future<FriendRoom?> Function(RoomJoinRequest request) onJoin;
  final bool Function() isCurrent;

  @override
  State<RoomJoinDialog> createState() => _RoomJoinDialogState();
}

class _RoomJoinDialogState extends State<RoomJoinDialog> {
  RoomStrings get _strings => RoomStrings.fromCode(widget.languageCode);
  String _s(String source, [List<Object?> values = const []]) =>
      _strings.text(source, values);
  final _formKey = GlobalKey<FormState>();
  late final _room = TextEditingController(text: widget.initial);
  final _password = TextEditingController();
  bool _obscurePassword = true;
  bool _submitting = false;
  String? _error;

  bool get _isInvitation => _room.text.trim().contains(':');

  @override
  void dispose() {
    _room.dispose();
    _password.dispose();
    super.dispose();
  }

  String? _validateRoom(String? value) {
    final input = value?.trim() ?? '';
    if (RegExp(r'^[0-9]{8}$').hasMatch(input)) return null;
    if (!_isInvitation) return _s("请输入 8 位房间号或完整的邀请链接");
    try {
      RoomInvitation.parse(input, widget.server);
      return null;
    } on RoomException catch (error) {
      return _strings.error(error);
    } on FormatException {
      return _s("邀请链接格式无效");
    }
  }

  Future<void> _submit() async {
    if (_submitting || _formKey.currentState?.validate() != true) return;
    if (!widget.isCurrent()) {
      _finish(null);
      return;
    }
    final input = _room.text.trim();
    final RoomJoinRequest request;
    if (_isInvitation) {
      final invite = RoomInvitation.parse(input, widget.server);
      request = RoomJoinRequest(invite.code, invitation: invite.token);
    } else {
      request = RoomJoinRequest(input, password: _password.text);
    }
    FocusScope.of(context).unfocus();
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final room = await widget.onJoin(request);
      if (!mounted) return;
      _finish(widget.isCurrent() ? room : null);
    } catch (error) {
      if (!mounted) return;
      if (!widget.isCurrent()) {
        _finish(null);
        return;
      }
      setState(() {
        _submitting = false;
        _error = _strings.error(error);
      });
    }
  }

  void _finish(FriendRoom? room) {
    final route = ModalRoute.of(context);
    if (route?.isCurrent == true) {
      Navigator.pop(context, room);
    } else if (route != null) {
      // A late result may only dismiss this form, never a newer route.
      Navigator.of(context).removeRoute(route, room);
    }
  }

  @override
  Widget build(BuildContext context) => PopScope<FriendRoom>(
    canPop: !_submitting,
    child: AlertDialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 24),
      titlePadding: const EdgeInsets.fromLTRB(24, 24, 24, 16),
      contentPadding: const EdgeInsets.symmetric(horizontal: 24),
      actionsPadding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
      title: Row(
        children: [
          Icon(
            Icons.meeting_room_outlined,
            color: Theme.of(context).colorScheme.primary,
            size: 24,
          ),
          const SizedBox(width: 12),
          Expanded(child: Text(_s("加入房间"))),
        ],
      ),
      content: SizedBox(
        width: 460,
        child: SingleChildScrollView(
          child: Form(
            key: _formKey,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  _s("输入房间号与密码，或粘贴好友发来的邀请链接。"),
                  style: Theme.of(context).textTheme.bodyMedium
                      ?.copyWith(color: P2WlanColors.of(context).textSecondary),
                ),
                const SizedBox(height: 20),
                TextFormField(
                  key: const ValueKey('房间号'),
                  controller: _room,
                  enabled: !_submitting,
                  autofocus: true,
                  autocorrect: false,
                  enableSuggestions: false,
                  maxLength: 4096,
                  minLines: 1,
                  maxLines: 4,
                  decoration: InputDecoration(
                    labelText: _s("房间号或邀请链接"),
                    hintText: _s("8 位房间号，或 p2wlan://join…"),
                    counterText: '',
                    border: OutlineInputBorder(),
                  ),
                  validator: _validateRoom,
                  onChanged: (_) => setState(() {}),
                ),
                const SizedBox(height: 16),
                if (_isInvitation)
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: P2WlanColors.of(context).surfaceMuted,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          Icons.link_rounded,
                          size: 18,
                          color: P2WlanColors.of(context).textSecondary,
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            _s("使用邀请加入，无需密码。确认后加入当前服务器上的房间。"),
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ),
                      ],
                    ),
                  )
                else
                  TextFormField(
                    key: const ValueKey('房间密码'),
                    controller: _password,
                    enabled: !_submitting,
                    obscureText: _obscurePassword,
                    autocorrect: false,
                    enableSuggestions: false,
                    maxLength: 72,
                    decoration: InputDecoration(
                      labelText: _s("房间密码"),
                      helperText: _s("请向房主索取房间密码"),
                      counterText: '',
                      border: const OutlineInputBorder(),
                      suffixIcon: IconButton(
                        tooltip: _obscurePassword ? _s("显示房间密码") : _s("隐藏房间密码"),
                        onPressed: _submitting
                            ? null
                            : () => setState(
                                () => _obscurePassword = !_obscurePassword,
                              ),
                        icon: Icon(
                          _obscurePassword
                              ? Icons.visibility_outlined
                              : Icons.visibility_off_outlined,
                        ),
                      ),
                    ),
                    validator: (value) {
                      final length = utf8.encode(value ?? '').length;
                      return length < 8 || length > 72
                          ? _s("密码需为 8–72 字节")
                          : null;
                    },
                    onFieldSubmitted: (_) => _submit(),
                  ),
                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Semantics(
                    liveRegion: true,
                    child: Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: P2WlanColors.of(context).dangerSurface,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: P2WlanColors.of(context).dangerBorder,
                        ),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(
                            Icons.error_outline_rounded,
                            size: 20,
                            color: P2WlanColors.of(context).dangerText,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              _error!,
                              style: TextStyle(
                                color: P2WlanColors.of(context).dangerText,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.pop(context),
          child: Text(_s("取消")),
        ),
        FilledButton(
          onPressed: _submitting ? null : _submit,
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (_submitting) ...[
                SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    semanticsLabel: _s("正在加入房间"),
                  ),
                ),
                const SizedBox(width: 8),
              ],
              Text(_submitting ? _s("正在加入…") : _s("确认")),
            ],
          ),
        ),
      ],
    ),
  );
}
