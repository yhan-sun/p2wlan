import 'package:p2wlan_flutter_client/shared/widgets/app_notice.dart';

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/capabilities/platform_capabilities.dart';
import '../../core/rooms/room_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../app/app_strings.dart';
import '../nodes/nodes_page.dart';
import '../../core/rooms/room_profiles.dart';
import '../../core/rooms/room_connectivity.dart';
import '../../core/rooms/parallel_rooms.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';

class RoomsPage extends StatefulWidget {
  const RoomsPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.initialInvitation,
    this.onInvitationHandled,
    this.initialRoomId,
    this.onRoomSelected,
    this.api,
    this.capabilities,
    this.embedded = false,
    this.showHeader = true,
  });
  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool embedded;
  final bool showHeader;
  final Uri? initialInvitation;
  final VoidCallback? onInvitationHandled;
  final String? initialRoomId;
  final ValueChanged<String?>? onRoomSelected;
  final RoomApi? api;
  final PlatformCapabilities? capabilities;
  @override
  State<RoomsPage> createState() => _RoomsPageState();
}

class _RoomsPageState extends State<RoomsPage> {
  RoomApi? _apiInstance;
  RoomApi get _api => _apiInstance!;
  List<FriendRoom> _rooms = [];
  RoomRoster? _roster;
  final Map<String, RoomRoster> _rosters = {};
  final _localIdentities = <String, Map<String, String>>{};
  final _autoConnect = <String, bool>{};
  List<Map<String, dynamic>> _invites = [];
  String? _selectedId;
  String? _error;
  String? _operationError;
  bool _loading = true;
  bool _busy = false;
  bool _refreshing = false;
  Timer? _timer;
  Duration? _scheduledInterval;
  final _roomViewRevision = ValueNotifier<int>(0);
  int _generation = 0;

  ParallelRooms get _parallel => widget.statusStore.parallelRooms;

  void _parallelChanged() {
    if (mounted) {
      setState(() {});
      _roomViewRevision.value++;
      _scheduleTimer();
    }
  }

  bool _isPeerTransitional(PeerSnapshot p) {
    if (!p.online) return false;
    final state = p.state.toLowerCase();
    if (state.contains('connect') ||
        state.contains('handshake') ||
        state.contains('prob') ||
        state.contains('punch')) {
      return true;
    }
    if (p.path == 'probing' || p.path == 'direct_trial') return true;
    if (p.path == 'relay' && !p.isRelayVerified) return true;
    if (p.path == 'direct' && !p.isDirectVerified) return true;
    return false;
  }

  bool _hasTransitionalConnection() {
    for (final session in _parallel.sessions.values) {
      if (session.phase == RoomConnectionPhase.starting) return true;
      if (session.phase == RoomConnectionPhase.running) {
        final snap = session.snapshot;
        if (snap == null) return true;
        final onlinePeers = snap.peers.where((p) => p.online);
        if (onlinePeers.any(_isPeerTransitional)) {
          return true;
        }
      }
    }
    final primaryRoomId = widget.settingsStore.settings.networkId;
    if (isRoomNetwork(primaryRoomId)) {
      if (widget.statusStore.daemonStarting) return true;
      final snap = widget.statusStore.snapshot;
      if (snap != null && snap.networkId == primaryRoomId) {
        final onlinePeers = snap.peers.where((p) => p.online);
        if (onlinePeers.any(_isPeerTransitional)) {
          return true;
        }
      }
    }
    return false;
  }

  void _scheduleTimer() {
    if (!mounted) return;
    final hasTransitional = _hasTransitionalConnection();
    final interval = hasTransitional
        ? const Duration(milliseconds: 500)
        : const Duration(seconds: 5);
    if (_timer?.isActive == true && _scheduledInterval == interval) return;
    _timer?.cancel();
    _scheduledInterval = interval;
    _timer = Timer(interval, () {
      _timer = null;
      _scheduledInterval = null;
      if (!mounted) return;
      if (!_busy && !_refreshing) {
        unawaited(_refresh(silent: true).whenComplete(_scheduleTimer));
      } else {
        _scheduleTimer();
      }
    });
  }

  bool get _canConnect =>
      (widget.capabilities ?? PlatformCapabilities.current())
          .canActAsLocalVpnNode;
  bool get _sameSession {
    if (_apiInstance == null) return false;
    try {
      return widget.settingsStore.settings.authToken == _api.token &&
          roomControlServer(widget.settingsStore.settings.controlServer) ==
              _api.server;
    } catch (_) {
      return false;
    }
  }

  @override
  void initState() {
    super.initState();
    _parallel.addListener(_parallelChanged);
    widget.statusStore.addListener(_parallelChanged);
    final settings = widget.settingsStore.settings;
    try {
      if (settings.authToken.trim().isEmpty) {
        throw const RoomException('请先登录控制服务器后使用好友房间');
      }
      _apiInstance =
          widget.api ??
          RoomApi(server: settings.controlServer, token: settings.authToken);
    } catch (error) {
      _error = _message(error);
      _loading = false;
      return;
    }
    _selectedId =
        widget.initialRoomId ??
        (isRoomNetwork(settings.networkId) ? settings.networkId : null);
    unawaited(_refresh());
    _scheduleTimer();
    _handleInvitation();
  }

  @override
  void didUpdateWidget(covariant RoomsPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.initialInvitation != oldWidget.initialInvitation) {
      _handleInvitation();
    }
  }

  void _handleInvitation() {
    final invitation = widget.initialInvitation;
    if (invitation == null) return;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      await _joinWithLink(invitation.toString());
      if (mounted) widget.onInvitationHandled?.call();
    });
  }

  @override
  void dispose() {
    _parallel.removeListener(_parallelChanged);
    widget.statusStore.removeListener(_parallelChanged);
    _timer?.cancel();
    _roomViewRevision.dispose();
    _generation++;
    if (widget.api == null) _apiInstance?.close();
    super.dispose();
  }

  Future<void> _loadLocalIdentity(FriendRoom room) async {
    final settings = widget.settingsStore.settings;
    try {
      final identity = await widget.statusStore.daemonController
          .roomDeviceIdentity(selectRoomSettings(settings, room));
      if (!mounted ||
          !_sameSession ||
          widget.settingsStore.settings.authToken != settings.authToken) {
        return;
      }
      if (identity != null &&
          (identity['public_key'] != _localIdentities[room.id]?['public_key'] ||
              identity['node_id'] != _localIdentities[room.id]?['node_id'])) {
        setState(() => _localIdentities[room.id] = identity);
      }
    } catch (_) {
      /* No readable local profile yet. */
    }
  }

  Future<void> _refresh({bool silent = false}) async {
    if (!mounted || !_sameSession || _refreshing) return;
    _refreshing = true;
    final generation = ++_generation;
    final selected = _selectedId;
    try {
      final rooms = await _api.list();
      if (!_sameSession) return;
      if (_parallel.supported) {
        for (final room in rooms) {
          unawaited(_parallel.recover(room));
        }
      }
      final id = rooms.any((room) => room.id == selected) ? selected : null;
      final roster = id == null ? null : await _api.roster(id);
      if (roster != null && _parallel.supported && _canConnect) {
        final preference = await _parallel.connectionPreference(roster.room);
        _autoConnect[roster.room.id] = preference.autoConnect;
      }
      if (roster != null && _canConnect) {
        unawaited(_loadLocalIdentity(roster.room));
      }
      // Older servers lack card summaries; fetch their rosters in bounded batches.
      final summaries = <String, RoomRoster>{};
      final legacy = rooms
          .where((room) => room.memberCount == null && room.id != id)
          .toList();
      for (var offset = 0; offset < legacy.length; offset += 4) {
        final batch = legacy.skip(offset).take(4);
        await Future.wait(
          batch.map((room) async {
            summaries[room.id] = await _api.roster(room.id);
          }),
        );
      }
      if (roster != null) summaries[roster.room.id] = roster;
      final invites = roster?.room.isOwner == true
          ? (await _api.request('GET', [id!, 'invites']))['invites'] as List? ??
                const []
          : const [];
      if (!mounted || generation != _generation || !_sameSession) return;
      setState(() {
        _rooms = rooms;
        _rosters.removeWhere((id, _) => !rooms.any((room) => room.id == id));
        _rosters.addAll(summaries);
        _selectedId = id;
        _roster = roster;
        _invites = invites
            .map((item) => Map<String, dynamic>.from(item as Map))
            .toList();
        _error = null;
      });
      _roomViewRevision.value++;
      widget.onRoomSelected?.call(id);
    } catch (error) {
      if (mounted && generation == _generation && _sameSession) {
        setState(() => _error = _message(error));
      }
    } finally {
      _refreshing = false;
      if (mounted && generation == _generation) {
        setState(() => _loading = false);
      }
    }
  }

  String _memberLabel(String id) {
    if (id == _apiInstance?.userId) return '我';
    for (final member in _roster?.members ?? <Map<String, dynamic>>[]) {
      if (member['user_id'] == id) {
        if (!member.containsKey('username')) return '用户名暂不可用';
        final name = (member['username'] as String? ?? '').trim();
        if (name.isNotEmpty) return name;
      }
    }
    return '未设置用户名';
  }

  String _connectionLabel(
    ParallelRoomSession? session, [
    DiagnosticsSnapshot? snapshot,
  ]) {
    if (session != null) {
      switch (session.phase) {
        case RoomConnectionPhase.stopping:
          return '断开中';
        case RoomConnectionPhase.unavailable:
          return '连接不可用';
        case RoomConnectionPhase.failed:
          return '需处理';
        case RoomConnectionPhase.starting:
          if (snapshot == null && session.snapshot == null) return '本机启动';
        case RoomConnectionPhase.running:
          break;
      }
    }

    final currentSnapshot = snapshot ?? session?.snapshot;
    if (currentSnapshot == null) {
      return session?.phase == RoomConnectionPhase.starting
          ? '本机启动'
          : (session == null ? '未连接' : '连接中');
    }

    if (currentSnapshot.peerSnapshotStale) return '状态待更新';
    return RoomConnectivitySummary.fromPeers(currentSnapshot.peers).label;
  }

  String _message(Object error) =>
      error is RoomException ? error.message : '操作未完成，请检查连接后重试';

  Future<void> _run(
    Future<void> Function() operation, {
    String? success,
  }) async {
    if (_busy || !mounted) return;
    if (!_sameSession) {
      setState(() => _operationError = '登录账号或服务器已变化，请重新登录。');
      return;
    }
    _generation++;
    setState(() {
      _busy = true;
      _operationError = null;
    });
    try {
      await operation();
      if (mounted && _sameSession && success != null) _notify(success);
    } catch (error) {
      if (mounted && _sameSession) {
        setState(() => _operationError = _message(error));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
    while (mounted && _refreshing) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (mounted) await _refresh();
  }

  void _notify(String message) {
    showAppNotice(context, content: Text(message));
  }

  Future<bool> _confirm(String title, String message) async {
    return await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: Text(title),
            content: Text(message),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('确认'),
              ),
            ],
          ),
        ) ??
        false;
  }

  Future<List<String>?> _form(
    String title,
    List<_RoomField> fields, {
    String? description,
  }) async {
    if (!_sameSession) {
      setState(() => _error = '请先登录当前控制服务器后使用好友房间');
      return null;
    }
    return showDialog<List<String>>(
      context: context,
      builder: (_) => _RoomInputDialog(
        title: title,
        fields: fields,
        description: description,
      ),
    );
  }

  _RoomField get _passwordField => _RoomField(
    '房间密码',
    secret: true,
    maxLength: 72,
    hint: '8–72 字节，不会写入分享链接',
    validate: (value) {
      final length = utf8.encode(value ?? '').length;
      return length < 8 || length > 72 ? '密码需为 8–72 字节' : null;
    },
  );
  _RoomField _nameField([String initial = '']) => _RoomField(
    '房间名称',
    initial: initial,
    maxLength: 64,
    validate: (value) =>
        value == null ||
            value.trim().isEmpty ||
            value.runes.length > 64 ||
            RegExp(r'[\r\n\x00]').hasMatch(value)
        ? '请输入 1–64 个字符的名称'
        : null,
  );

  Future<void> _create() async {
    final values = await _form('创建好友房间', [
      _nameField(),
      _passwordField,
    ], description: '每个账号可以创建一个房间。服务器会分配独立的 10.21.x.0/24 网段，不改变你的个人网络。');
    if (values == null || !mounted) return;
    await _run(() async {
      _selectedId = (await _api.create(values[0].trim(), values[1])).id;
    }, success: '房间已创建');
  }

  Future<void> _join() async {
    final values = await _form('通过房间号加入', [
      _RoomField(
        '房间号',
        maxLength: 8,
        number: true,
        validate: (value) => RegExp(r'^[0-9]{8}$').hasMatch(value?.trim() ?? '')
            ? null
            : '请输入 8 位房间号',
      ),
      _passwordField,
    ], description: '加入后可在房间列表中连接此网络。加入多个房间不会自动把不同房间桥接在一起。');
    if (values == null || !mounted) return;
    await _run(() async {
      _selectedId = (await _api.join(values[0].trim(), password: values[1])).id;
    }, success: '账号已加入房间，点击“连接本机”开始互联');
  }

  Future<void> _joinWithLink([String initial = '']) async {
    if (!mounted || _busy) return;
    final values = await _form('通过邀请链接加入', [
      _RoomField(
        '邀请链接',
        initial: initial,
        multiline: true,
        maxLength: 4096,
        validate: (value) {
          try {
            RoomInvitation.parse(value ?? '', _api.server);
            return null;
          } catch (error) {
            return _message(error);
          }
        },
      ),
    ], description: '仅加入当前控制服务器上的房间。确认前不会发送邀请，也不会自动切换服务器。');
    if (values == null || !mounted) return;
    await _run(() async {
      final invite = RoomInvitation.parse(values[0], _api.server);
      _selectedId = (await _api.join(invite.code, invitation: invite.token)).id;
    }, success: '账号已加入房间，点击“连接本机”开始互联');
  }

  Future<void> _connect(FriendRoom? room) async {
    if (!_canConnect || _busy) return;
    if (_parallel.supported && room != null) {
      await _run(() async {
        if (widget.settingsStore.settings.networkId == room.id) {
          final stopped = await widget.statusStore.stopPrimaryDaemon();
          if (!stopped.ok) throw const RoomException('旧的单房间运行时未能停止');
          await widget.settingsStore.updateSettings(
            personalNetworkSettings(widget.settingsStore.settings),
          );
        }
        if (!mounted || !_sameSession) return;
        final result = await _parallel.connect(room);
        if (!result.ok) throw RoomException(result.message);
      }, success: '已连接房间');
      return;
    }
    final name = room?.name ?? '个人网络';
    if (!await _confirm(
          '连接$name',
          _parallel.supported
              ? '将启动个人网络，已连接的并行房间保持运行。'
              : '此平台仍使用单活动网络，将断开当前网络后连接$name。',
        ) ||
        !mounted) {
      return;
    }
    await _run(() async {
      final stopped = await widget.statusStore.stopPrimaryDaemon();
      if (!stopped.ok) throw const RoomException('旧网络未能停止，未切换网络');
      if (!mounted || !_sameSession) return;
      final current = widget.settingsStore.settings;
      final next = room == null
          ? (isRoomNetwork(current.networkId)
                ? personalNetworkSettings(current)
                : current)
          : selectRoomSettings(current, room);
      if (room != null) roomProfileId(next);
      await widget.settingsStore.updateSettings(next);
      if (!mounted || !_sameSession) return;
      final started = await widget.statusStore.startDaemon();
      if (!started.ok) throw RoomException(started.message);
    }, success: '网络连接已启动');
  }

  Future<void> _disconnectRoom(FriendRoom room) async {
    await _run(() async {
      final result =
          _parallel.session(room.id) == null &&
              widget.settingsStore.settings.networkId == room.id
          ? await widget.statusStore.stopPrimaryDaemon()
          : await _parallel.disconnect(room.id);
      if (!result.ok) throw RoomException(result.message);
      await _parallel.forgetConnectionIntent(room);
    }, success: '已断开本机，其他设备和房间保持运行');
  }

  Future<void> _edit(FriendRoom room, bool password) async {
    final values = await _form(
      password ? '更改房间密码' : '重命名房间',
      [password ? _passwordField : _nameField(room.name)],
      description: password
          ? '更改密码会同时撤销所有现有邀请链接。已加入成员不受影响；要阻止其再次加入，请封禁账号。'
          : null,
    );
    if (values == null || !mounted) return;
    await _run(() async {
      await _api.request(
        'PATCH',
        [room.id],
        {
          password ? 'password' : 'name': password
              ? values[0]
              : values[0].trim(),
        },
      );
    }, success: '房间设置已保存');
  }

  Future<void> _issueInvite(FriendRoom room) async {
    final values = await _form('生成邀请链接', [
      _RoomField(
        '有效小时数',
        initial: '24',
        number: true,
        validate: (v) => _range(v, 1, 168),
      ),
      _RoomField(
        '最多加入账号数',
        initial: '10',
        number: true,
        validate: (v) => _range(v, 1, 1000),
      ),
    ], description: '链接持有者可免密码加入。可以随时撤销；同一账号重复加入不重复消耗次数。');
    if (values == null || !mounted) return;
    await _run(() async {
      final data = await _api.request(
        'POST',
        [room.id, 'invites'],
        {
          'ttl_seconds': int.parse(values[0].trim()) * 3600,
          'max_uses': int.parse(values[1].trim()),
        },
      );
      final token = data['invite_token'] as String? ?? '';
      final link = RoomInvitation(
        _api.server,
        room.code,
        token,
      ).toUri().toString();
      RoomInvitation.parse(link, _api.server);
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('分享房间'),
          content: SizedBox(
            width: 460,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('${room.name} · ${room.code}'),
                  const SizedBox(height: 12),
                  const Text('此链接仅在本次生成后显示。只发送给可信好友；好友可点击链接，或在 P2WLAN 中粘贴加入。'),
                  const SizedBox(height: 12),
                  SelectableText(link),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('关闭'),
            ),
            FilledButton.icon(
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: link));
                if (context.mounted) Navigator.pop(context);
              },
              icon: const Icon(Icons.copy_rounded),
              label: const Text('复制邀请链接'),
            ),
          ],
        ),
      );
    });
  }

  String? _range(String? value, int min, int max) {
    final number = int.tryParse(value?.trim() ?? '');
    return number == null || number < min || number > max
        ? '请输入 $min–$max 的整数'
        : null;
  }

  Future<void> _removeMember(FriendRoom room, String user, bool ban) async {
    if (!await _confirm(
          ban ? '封禁成员' : '移除成员',
          ban
              ? '该账号的所有房间设备将断开，解除封禁前无法再次加入。'
              : '该账号的所有房间设备将断开，但持有有效密码或邀请时仍可重新加入。',
        ) ||
        !mounted) {
      return;
    }
    await _run(() async {
      await _api.request(ban ? 'PUT' : 'DELETE', [
        room.id,
        ban ? 'bans' : 'members',
        user,
      ]);
    }, success: ban ? '成员已封禁' : '成员已移除');
  }

  Future<void> _changeIp(FriendRoom room, Map<String, dynamic> device) async {
    final values = await _form('分配设备 IP', [
      _RoomField(
        '虚拟 IP',
        initial: device['virtual_ip'] as String? ?? '',
        maxLength: 15,
        validate: (value) => validRoomIp(value?.trim() ?? '', room.cidr)
            ? null
            : '请输入 ${room.cidr} 中的可用主机地址',
      ),
    ], description: 'IP 不得与其他设备重复。保存后旧连接和凭证将被撤销，该设备需要重新连接房间。');
    if (values == null || !mounted) return;
    if (values[0].trim() == device['virtual_ip']) {
      _notify('地址未变化，无需重新连接');
      return;
    }
    await _run(() async {
      final result = await _api.request(
        'PATCH',
        [room.id, 'devices', device['id'] as String],
        {'virtual_ip': values[0].trim()},
      );
      if (mounted && _sameSession) {
        _notify(
          result['reconnect_required'] == false
              ? '地址未变化，无需重新连接'
              : 'IP 已分配，请让该设备重新连接房间',
        );
      }
    });
  }

  Future<void> _deleteDevice(
    FriendRoom room,
    Map<String, dynamic> device,
  ) async {
    if (!await _confirm('删除房间设备', '将断开该设备。其账号仍是成员，可以重新连接；要阻止重新加入，请封禁账号。') ||
        !mounted) {
      return;
    }
    await _run(() async {
      await _api.request('DELETE', [
        room.id,
        'devices',
        device['id'] as String,
      ]);
    }, success: '房间设备已删除');
  }

  Map<String, dynamic>? _accessFor(
    FriendRoom room,
    Map<String, dynamic> device,
  ) {
    for (final access
        in _rosters[room.id]?.deviceAccess ?? <Map<String, dynamic>>[]) {
      if ((device['id'] != null && access['device_id'] == device['id']) ||
          (device['public_key'] != null &&
              access['public_key'] == device['public_key'])) {
        return access;
      }
    }
    return null;
  }

  bool _isLocalDevice(FriendRoom room, Map<String, dynamic> device) {
    final identity = _localIdentities[room.id];
    if (identity == null) return false;
    return (identity['node_id']!.isNotEmpty &&
            (device['id'] == identity['node_id'] ||
                device['node_id'] == identity['node_id'])) ||
        (identity['public_key'] != null &&
            _accessFor(room, device)?['public_key'] == identity['public_key']);
  }

  Future<void> _controlDevice(
    FriendRoom room,
    Map<String, dynamic> device,
    Map<String, dynamic> access,
    String action,
  ) async {
    final title = switch (action) {
      'disconnect' => '断开此设备',
      'block' => '禁止此设备连接此房间',
      'unblock' => '解除设备限制',
      _ => '批准此设备',
    };
    final message = switch (action) {
      'disconnect' => '只断开这台设备，并停止其自动恢复连接。账号仍是成员，其他设备保持连接。之后可以在该设备上手动连接。',
      'block' => '这台设备将断开，解除限制前无法连接此房间。同账号其他设备不受影响。',
      _ => '设备获得连接资格，但不会自动上线。请在该设备上点击“连接本机”。',
    };
    if (!await _confirm(title, message) || !mounted) return;
    await _run(() async {
      await _api.request('POST', [
        room.id,
        'device-access',
        access['id'] as String,
        action,
      ]);
      if (_isLocalDevice(room, device) &&
          (action == 'disconnect' || action == 'block')) {
        final stopped = await _parallel.disconnect(room.id);
        if (!stopped.ok) throw RoomException(stopped.message);
        if (widget.settingsStore.settings.networkId == room.id && _canConnect) {
          final primary = await widget.statusStore.stopPrimaryDaemon();
          if (!primary.ok) throw RoomException(primary.message);
        }
        await _parallel.forgetConnectionIntent(room);
      }
    }, success: '$title：已完成');
  }

  Future<void> _leave(FriendRoom room) async {
    if (!await _confirm(
          room.isOwner ? '解散房间' : '退出房间',
          room.isOwner
              ? '将移除所有成员并撤销房间凭证。此操作不可恢复，重新创建会获得新房间号。'
              : '此账号的所有设备都会退出该房间。只想让当前设备下线，请使用“断开本机”。个人网络和其他房间不受影响。',
        ) ||
        !mounted) {
      return;
    }
    await _run(() async {
      final result = await _parallel.disconnect(room.id);
      if (!result.ok) throw const RoomException('本地并行房间未能停止，尚未退出');
      if (widget.settingsStore.settings.networkId == room.id) {
        if (_canConnect) {
          final stopped = await widget.statusStore.stopPrimaryDaemon();
          if (!stopped.ok) throw const RoomException('本地房间网络无法停止，尚未退出房间');
        }
      }
      await _parallel.forgetConnectionIntent(room);
      await _api.request(room.isOwner ? 'DELETE' : 'POST', [
        room.id,
        if (!room.isOwner) 'leave',
      ]);
      if (widget.settingsStore.settings.networkId == room.id) {
        await widget.settingsStore.updateSettings(
          personalNetworkSettings(widget.settingsStore.settings),
        );
      }
      _selectedId = null;
    }, success: room.isOwner ? '房间已解散' : '已退出房间');
  }

  Widget _surfaceCard({required Widget child, bool selected = false}) {
    final colors = Theme.of(context).colorScheme;
    return Card(
      elevation: 0,
      margin: const EdgeInsets.only(bottom: 8),
      color: selected ? colors.secondaryContainer : colors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: selected ? colors.primary : colors.outlineVariant,
        ),
      ),
      clipBehavior: Clip.antiAlias,
      child: child,
    );
  }

  Future<void> _selectRoom(String id) async {
    setState(() {
      _selectedId = id;
      _roster = null;
      _loading = true;
    });
    _generation++;
    while (mounted && _refreshing) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (mounted) await _refresh();
  }

  Widget _roomList() {
    if (_rooms.isEmpty) {
      return _loading
          ? const SizedBox.shrink()
          : const Padding(
              padding: EdgeInsets.all(32),
              child: Text(
                '还没有房间，创建一个或向好友索取房间号与密码。',
                textAlign: TextAlign.center,
              ),
            );
    }
    return LayoutBuilder(
      builder: (context, constraints) {
        const gap = 12.0;
        final columns = ((constraints.maxWidth + gap) / 292).floor().clamp(
          1,
          6,
        );
        final width = (constraints.maxWidth - gap * (columns - 1)) / columns;
        return Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            for (final room in _rooms)
              SizedBox(width: width, child: _roomCard(room)),
          ],
        );
      },
    );
  }

  Widget _roomCard(FriendRoom room) {
    final roster = _rosters[room.id];
    final onlineIds = roster?.devices
        .where((d) => d['online'] == true)
        .map((d) => d['user_id'])
        .toSet();
    final total = room.memberCount ?? roster?.members.length;
    final online =
        room.onlineMemberCount ??
        roster?.members.where((m) => onlineIds!.contains(m['user_id'])).length;
    var owner = room.ownerUsername.trim();
    if (owner.isEmpty && roster != null) {
      for (final member in roster.members) {
        if (member['user_id'] == room.ownerId) {
          owner = (member['username'] as String? ?? '').trim();
        }
      }
    }
    if (room.isOwner) owner = owner.isEmpty ? '我' : '$owner（我）';
    final session = _parallel.session(room.id);
    return Material(
      color: Colors.transparent,
      borderRadius: BorderRadius.circular(14),
      clipBehavior: Clip.antiAlias,
      child: Ink(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: Theme.of(context).brightness == Brightness.dark
                ? const Color(0xff315448)
                : const Color(0xffdcebe2),
          ),
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            stops: const [0, 0.48, 1],
            colors: Theme.of(context).brightness == Brightness.dark
                ? const [
                    Color(0xff202926),
                    Color(0xff22362b),
                    Color(0xff28513a),
                  ]
                : const [Colors.white, Color(0xfff5fbf7), Color(0xffccefd8)],
          ),
        ),
        child: InkWell(
          key: ValueKey('room-card-${room.id}'),
          borderRadius: BorderRadius.circular(12),
          onTap: _busy ? null : () => _selectRoom(room.id),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.meeting_room_outlined),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        room.name,
                        style: Theme.of(context).textTheme.titleMedium,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    const Icon(Icons.chevron_right_rounded),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  '房主 · ${owner.isEmpty ? '未设置用户名' : owner}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 24,
                  runSpacing: 12,
                  children: [
                    _deviceMetric(
                      '在线 / 总人数',
                      '${online ?? '—'} / ${total ?? '—'}',
                    ),
                    Tooltip(
                      message: '本机到房主在线设备的实测延迟；多台设备取最低值。',
                      child: _deviceMetric('房主延迟', _ownerLatency(room, roster)),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        '房间号 ${room.code}',
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ),
                    if (room.locked)
                      const Tooltip(
                        message: '已锁定新成员加入',
                        child: Icon(Icons.lock_outline, size: 16),
                      ),
                    Text(
                      _connectionLabel(session, _roomSnapshot(room)),
                      style: Theme.of(context).textTheme.labelMedium,
                    ),
                  ],
                ),
                if (_roomSnapshot(room) case final snapshot?) ...[
                  const SizedBox(height: 8),
                  Text(
                    snapshot.peerSnapshotStale
                        ? '链路信息待更新'
                        : RoomConnectivitySummary.fromPeers(snapshot.peers)
                              .details,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
                if (session?.message case final message?) ...[
                  const SizedBox(height: 8),
                  Text(
                    message,
                    maxLines: 3,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  String _ownerLatency(FriendRoom room, RoomRoster? roster) {
    if (room.isOwner) return '我是房主';
    final snapshot = _roomSnapshot(room);
    if (snapshot == null) return '连接后测量';
    if (snapshot.peerSnapshotStale) return '待更新';
    final ips = room.memberCount != null
        ? room.ownerDeviceIps
        : [
            for (final d in roster?.devices ?? <Map<String, dynamic>>[])
              if (d['user_id'] == room.ownerId && d['online'] == true)
                d['virtual_ip'] as String? ?? '',
          ];
    if (ips.isEmpty) {
      return roster != null || room.memberCount != null ? '房主离线' : '未测得';
    }
    final latencies =
        snapshot.peers
            .where((p) => ips.contains(p.virtualIp))
            .map((p) => p.latencyMs)
            .whereType<int>()
            .toList()
          ..sort();
    return latencies.isEmpty ? '未测得' : '${latencies.first} ms';
  }

  DiagnosticsSnapshot? _roomSnapshot(FriendRoom room) {
    final session = _parallel.session(room.id);
    final snapshot = session != null
        ? (session.phase == RoomConnectionPhase.running
              ? session.snapshot
              : null)
        : (widget.settingsStore.settings.networkId == room.id &&
                  !widget.statusStore.snapshotStale &&
                  widget.statusStore.online
              ? widget.statusStore.snapshot
              : null);
    return snapshot?.networkId == room.id ? snapshot : null;
  }

  bool _deviceOnline(
    Map<String, dynamic> device,
    DiagnosticsSnapshot? snapshot,
    List<PeerSnapshot> peers,
  ) {
    final ip = device['virtual_ip'];
    if (snapshot != null &&
        ip is String &&
        ip.isNotEmpty &&
        ip == snapshot.virtualIp) {
      return true;
    }
    for (final peer in peers) {
      if (peer.nodeId == device['node_id'] ||
          (ip is String && ip.isNotEmpty && peer.virtualIp == ip)) {
        return peer.online;
      }
    }
    return device['online'] == true;
  }

  Widget _stateBadge(String label, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.10),
      borderRadius: BorderRadius.circular(20),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(Icons.circle, size: 6, color: color),
        const SizedBox(width: 5),
        Text(
          label,
          style: TextStyle(
            color: color,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    ),
  );

  Widget _deviceList(RoomRoster roster) {
    final snapshot = _roomSnapshot(roster.room);
    final peers = snapshot?.peerSnapshotStale == false
        ? snapshot!.peers
        : <PeerSnapshot>[];
    final devices = [
      for (final device in roster.devices) {...device},
    ];
    for (final access in roster.deviceAccess) {
      if (!devices.any(
        (device) =>
            device['id'] == access['device_id'] && access['device_id'] != '',
      )) {
        devices.add({
          'device_name': access['device_name'],
          'user_id': access['user_id'],
          'platform': access['platform'],
          'public_key': access['public_key'],
          'online': false,
        });
      }
    }
    for (final peer in peers) {
      if (!devices.any(
        (d) =>
            d['node_id'] == peer.nodeId ||
            (peer.virtualIp.isNotEmpty && d['virtual_ip'] == peer.virtualIp),
      )) {
        devices.add({
          'node_id': peer.nodeId,
          'device_name': peer.displayName,
          'virtual_ip': peer.virtualIp,
          'online': peer.online,
        });
      }
    }
    if (snapshot != null &&
        snapshot.virtualIp.isNotEmpty &&
        !devices.any((d) => d['virtual_ip'] == snapshot.virtualIp)) {
      devices.insert(0, {
        'node_id': snapshot.nodeId,
        'device_name': widget.settingsStore.settings.deviceName,
        'virtual_ip': snapshot.virtualIp,
        'user_id': _api.userId,
        'online': true,
      });
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          '设备与连接 · ${devices.length}',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        if (devices.isEmpty)
          const Padding(
            padding: EdgeInsets.all(20),
            child: Text('还没有设备连接。连接房间后，设备 IP 和连接质量会显示在这里。'),
          ),
        for (final user in <String>{
          ...roster.members.map((member) => member['user_id'] as String? ?? ''),
          ...devices.map((device) => device['user_id'] as String? ?? ''),
        }) ...[
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Text(
              '${user.isEmpty ? '成员信息同步中' : _memberLabel(user)} · ${user == roster.room.ownerId ? '房主' : '成员'} · ${devices.where((d) => (d['user_id'] ?? '') == user).length} 台设备',
              style: Theme.of(context).textTheme.titleSmall,
            ),
          ),
          if (!devices.any((d) => (d['user_id'] ?? '') == user))
            const Text('尚无设备连接'),
          for (final device in devices.where(
            (d) => (d['user_id'] ?? '') == user,
          ))
            _deviceCard(roster.room, device, snapshot, peers),
        ],
      ],
    );
  }

  Future<void> _showRoomDeviceDetails(
    FriendRoom room,
    Map<String, dynamic> device,
  ) async {
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => AnimatedBuilder(
        animation: _roomViewRevision,
        builder: (context, _) {
          final snapshot = _sameSession ? _roomSnapshot(room) : null;
          final peers = snapshot != null && !snapshot.peerSnapshotStale
              ? snapshot.peers
              : <PeerSnapshot>[];
          final ip = device['virtual_ip'] as String? ?? '';
          final candidates =
              _rosters[room.id]?.devices ?? <Map<String, dynamic>>[];
          var current = device;
          for (final candidate in candidates) {
            if (device['id'] != null && candidate['id'] == device['id']) {
              current = candidate;
              break;
            }
          }
          PeerSnapshot? peer;
          for (final candidate in peers) {
            if (candidate.nodeId == current['node_id'] ||
                (ip.isNotEmpty &&
                    candidate.virtualIp == current['virtual_ip'])) {
              peer = candidate;
              break;
            }
          }
          final local =
              snapshot != null && current['virtual_ip'] == snapshot.virtualIp;
          final available = _sameSession && _rooms.any((r) => r.id == room.id);
          final user = current['user_id'] as String? ?? '';
          return DeviceDetailsDialog(
            strings: AppStrings.fromCode(
              widget.settingsStore.settings.languageCode,
            ),
            peer: peer,
            contextHeader: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                '${room.name} · ${user == room.ownerId ? '房主' : '成员'} · ${_memberLabel(user)}',
              ),
            ),
            content: !available
                ? const Text('房间或登录状态已变化，请关闭详情后重试。')
                : peer != null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _deviceCard(
                        room,
                        current,
                        snapshot,
                        peers,
                        interactive: false,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        local
                            ? '本机在此房间的连接信息'
                            : '当前没有可用的实时链路信息。设备连接后可查看链路与实测延迟。',
                      ),
                      const SizedBox(height: 12),
                      SelectableText('房间网段：${room.cidr}'),
                      if ((current['platform'] as String? ?? '').isNotEmpty)
                        Text('系统：${current['platform']}'),
                      if ((current['app_version'] as String? ?? '').isNotEmpty)
                        Text('版本：${current['app_version']}'),
                    ],
                  ),
            onCopy: (value, _) async {
              await Clipboard.setData(ClipboardData(text: value));
              if (mounted) _notify('已复制');
            },
          );
        },
      ),
    );
  }

  Widget _deviceCard(
    FriendRoom room,
    Map<String, dynamic> device,
    DiagnosticsSnapshot? snapshot,
    List<PeerSnapshot> peers, {
    bool interactive = true,
  }) {
    final ip = device['virtual_ip'] as String? ?? '';
    final local =
        _isLocalDevice(room, device) ||
        (snapshot != null && ip.isNotEmpty && ip == snapshot.virtualIp);
    PeerSnapshot? peer;
    for (final candidate in peers) {
      if (candidate.nodeId == device['node_id'] ||
          (ip.isNotEmpty && candidate.virtualIp == ip)) {
        peer = candidate;
        break;
      }
    }
    final access = _accessFor(room, device);
    final state = access?['state'] as String? ?? 'allowed';
    final online = state == 'allowed' && _deviceOnline(device, snapshot, peers);
    final path = local
        ? '本机'
        : !online
        ? '未连接'
        : snapshot == null
        ? '本机未连接'
        : snapshot.peerSnapshotStale
        ? '状态待更新'
        : peer == null
        ? (online ? '等待发现' : '离线')
        : switch (peer.path) {
            'direct' => '直连',
            'relay' => '中继',
            'offline' => '离线',
            _ => '建立连接中',
          };
    final latency = peer?.latencyMs;
    final colors = Theme.of(context).colorScheme;
    final green = Theme.of(context).brightness == Brightness.dark
        ? const Color(0xff72dba0)
        : const Color(0xff18834b);
    final statusColor = online ? green : colors.onSurfaceVariant;
    final userId = device['user_id'] as String? ?? '';
    final owner = userId.isNotEmpty && userId == room.ownerId;
    final username = userId.isEmpty ? '成员信息同步中' : _memberLabel(userId);
    final identity = '${owner ? '房主' : '成员'} · $username';
    final latencyLabel = local
        ? '无需测量'
        : !online
        ? '—'
        : snapshot == null
        ? '连接后测量'
        : snapshot.peerSnapshotStale
        ? '待更新'
        : latency == null
        ? '未测得'
        : '$latency ms';
    return _surfaceCard(
      child: InkWell(
        key: ValueKey(
          'room-device-${device['id'] ?? device['public_key'] ?? ip}',
        ),
        onTap: interactive ? () => _showRoomDeviceDetails(room, device) : null,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Icon(Icons.computer_rounded, color: statusColor),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${device['device_name'] ?? '设备'}${local ? '（本机）' : ''}',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                        const SizedBox(height: 4),
                        Text(
                          identity,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  _stateBadge(
                    state == 'blocked'
                        ? '已禁止'
                        : state == 'pending'
                        ? '待审批'
                        : state == 'paused'
                        ? '已断开'
                        : online
                        ? '在线'
                        : '离线',
                    statusColor,
                  ),
                  if (interactive) ...[
                    const SizedBox(width: 6),
                    Icon(
                      Icons.chevron_right_rounded,
                      size: 18,
                      color: colors.onSurfaceVariant,
                    ),
                  ],
                  if ((room.isOwner ||
                          userId == _api.userId &&
                              state != 'pending' &&
                              (state != 'blocked' ||
                                  access?['blocked_by'] == _api.userId)) &&
                      (access != null ||
                          room.isOwner && device['id'] is String))
                    PopupMenuButton<String>(
                      tooltip: '管理设备',
                      enabled: !_busy,
                      onSelected: (action) => action == 'ip'
                          ? _changeIp(room, device)
                          : action == 'delete'
                          ? _deleteDevice(room, device)
                          : _controlDevice(room, device, access!, action),
                      itemBuilder: (_) => [
                        if (room.isOwner &&
                            device['id'] is String &&
                            (device['id'] as String).isNotEmpty)
                          const PopupMenuItem(
                            value: 'ip',
                            child: Text('分配 IP'),
                          ),
                        if (access != null) ...[
                          if (state == 'allowed')
                            const PopupMenuItem(
                              value: 'disconnect',
                              child: Text('断开此设备'),
                            ),
                          if (state != 'blocked' &&
                              (state != 'pending' || room.isOwner))
                            const PopupMenuItem(
                              value: 'block',
                              child: Text('禁止此设备连接此房间'),
                            ),
                          if (state == 'blocked' &&
                              (room.isOwner ||
                                  access['blocked_by'] == _api.userId))
                            const PopupMenuItem(
                              value: 'unblock',
                              child: Text('解除设备限制'),
                            ),
                          if (state == 'pending' && room.isOwner)
                            const PopupMenuItem(
                              value: 'approve',
                              child: Text('批准此设备'),
                            ),
                        ] else if (room.isOwner)
                          const PopupMenuItem(
                            value: 'delete',
                            child: Text('删除设备'),
                          ),
                      ],
                    ),
                ],
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 24,
                runSpacing: 12,
                children: [
                  SizedBox(
                    width: 180,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('虚拟 IP', style: TextStyle(fontSize: 12)),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Flexible(
                              child: SelectableText(
                                ip.isEmpty ? '待分配' : ip,
                                style: const TextStyle(
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                            if (ip.isNotEmpty)
                              IconButton(
                                tooltip: '复制 IP',
                                visualDensity: VisualDensity.compact,
                                iconSize: 16,
                                icon: const Icon(Icons.copy_rounded),
                                onPressed: () async {
                                  await Clipboard.setData(
                                    ClipboardData(text: ip),
                                  );
                                  if (mounted) _notify('IP 已复制');
                                },
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  _deviceMetric('连接', path),
                  SizedBox(
                    width: 110,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '端到端延迟',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          latencyLabel,
                          style: TextStyle(
                            fontWeight: FontWeight.w600,
                            color: latency == null
                                ? colors.onSurfaceVariant
                                : latency < 80
                                ? green
                                : latency < 150
                                ? colors.onSurface
                                : colors.error,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _deviceMetric(String label, String value) => SizedBox(
    width: 96,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: Theme.of(context).textTheme.bodySmall),
        const SizedBox(height: 8),
        Text(value, style: const TextStyle(fontWeight: FontWeight.w600)),
      ],
    ),
  );

  Widget _roomDetails(RoomRoster roster) {
    final room = roster.room;
    final connection = _parallel.session(room.id);
    final primaryConnected = connection == null && _roomSnapshot(room) != null;
    final active =
        connection != null ||
        widget.settingsStore.settings.networkId == room.id;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _surfaceCard(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        room.name,
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 5,
                      ),
                      decoration: BoxDecoration(
                        color: Theme.of(context).colorScheme.secondaryContainer,
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(
                        _connectionLabel(connection, _roomSnapshot(room)),
                        style: Theme.of(context).textTheme.labelMedium,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                SelectableText('房间号 ${room.code}  ·  ${room.cidr}'),
                if (_roomSnapshot(room) case final snapshot?) ...[
                  const SizedBox(height: 8),
                  Text('本机 IP：${snapshot.virtualIp}'),
                  if (!snapshot.peerSnapshotStale)
                    Text(
                      RoomConnectivitySummary.fromPeers(snapshot.peers).details,
                    ),
                ],
                if (connection?.message case final message?) ...[
                  const SizedBox(height: 8),
                  Semantics(liveRegion: true, child: Text(message)),
                ],
                const SizedBox(height: 8),
                Text(
                  _parallel.supported
                      ? '本机已连接 ${_parallel.activeConnections}/${_parallel.maxConnections} 个房间；各房间独立运行。'
                      : '此平台使用单活动网络，连接本房间将断开当前网络。',
                ),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    if (_canConnect)
                      FilledButton.icon(
                        onPressed: _busy
                            ? null
                            : () => connection != null || primaryConnected
                                  ? _disconnectRoom(room)
                                  : _connect(room),
                        icon: Icon(
                          connection == null && !primaryConnected
                              ? Icons.lan_outlined
                              : Icons.link_off,
                        ),
                        label: Text(
                          connection != null || primaryConnected
                              ? '断开本机'
                              : active
                              ? '重新连接本机'
                              : '连接本机',
                        ),
                      ),
                    OutlinedButton.icon(
                      onPressed: _busy
                          ? null
                          : () async {
                              await Clipboard.setData(
                                ClipboardData(text: room.code),
                              );
                              if (mounted) _notify('房间号已复制');
                            },
                      icon: const Icon(Icons.copy_rounded),
                      label: const Text('复制房间号'),
                    ),
                    if (!room.isOwner)
                      TextButton.icon(
                        onPressed: _busy ? null : () => _leave(room),
                        icon: const Icon(Icons.exit_to_app_rounded),
                        label: const Text('退出房间'),
                      ),
                    if (room.isOwner)
                      OutlinedButton.icon(
                        onPressed: _busy || room.locked
                            ? null
                            : () => _issueInvite(room),
                        icon: const Icon(Icons.link_rounded),
                        label: const Text('生成邀请'),
                      ),
                  ],
                ),
                if (connection == null && !primaryConnected) ...[
                  const SizedBox(height: 12),
                  Text(
                    active
                        ? (_parallel.supported ? '重新连接以启用多房间互联。' : '当前房间网络')
                        : '已加入，连接后即可访问房间内的设备。',
                  ),
                ],
                if (connection?.message != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(
                      connection!.message!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ),
                if (!_canConnect) const Text('此平台仅支持房间管理，不能创建本地虚拟网卡。'),
              ],
            ),
          ),
        ),
        if (_parallel.supported && _canConnect)
          SwitchListTile.adaptive(
            title: const Text('启动时自动连接此房间'),
            subtitle: const Text('仅对本机生效；手动或远程断开后，需重新手动连接'),
            value: _autoConnect[room.id] ?? false,
            onChanged: _busy
                ? null
                : (value) => _run(() async {
                    await _parallel.setAutoConnect(room, value);
                    _autoConnect[room.id] = value;
                  }),
          ),
        const SizedBox(height: 16),
        _deviceList(roster),
        if (roster.members.any((member) => !member.containsKey('username')))
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Text(
              '当前控制服务器尚未提供用户名，更新服务器后可同步显示。',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
        const SizedBox(height: 12),
        ExpansionTile(
          title: Text(
            '${room.isOwner ? '成员管理' : '房间成员'} · ${roster.members.length}',
          ),
          children: [
            for (final member in roster.members)
              _surfaceCard(
                child: ListTile(
                  leading: Icon(
                    member['role'] == 'owner'
                        ? Icons.star_outline_rounded
                        : Icons.person_outline_rounded,
                  ),
                  title: Text(_memberLabel(member['user_id'] as String? ?? '')),
                  subtitle: Text(member['role'] == 'owner' ? '房主' : '成员'),
                  trailing: room.isOwner && member['role'] != 'owner'
                      ? PopupMenuButton<bool>(
                          enabled: !_busy,
                          onSelected: (ban) => _removeMember(
                            room,
                            member['user_id'] as String,
                            ban,
                          ),
                          itemBuilder: (_) => const [
                            PopupMenuItem(value: false, child: Text('移除成员')),
                            PopupMenuItem(value: true, child: Text('封禁成员')),
                          ],
                        )
                      : null,
                ),
              ),
          ],
        ),
        if (room.isOwner)
          ExpansionTile(
            title: const Text('房间设置'),
            children: [
              ...[
                const Divider(height: 28),
                if (room.deviceControls)
                  SwitchListTile.adaptive(
                    title: const Text('新设备需要房主审批'),
                    subtitle: const Text(
                      '已有设备保持当前权限；新设备批准后仍需在本机连接。房主身份属于账号，不绑定创建房间的设备。',
                    ),
                    value: roster.deviceApprovalRequired,
                    onChanged: _busy
                        ? null
                        : (value) => _run(() async {
                            await _api.request(
                              'PUT',
                              [room.id, 'device-policy'],
                              {'require_approval': value},
                            );
                          }),
                  ),
                SwitchListTile.adaptive(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('锁定新成员加入'),
                  subtitle: const Text('锁定后密码和邀请都无法添加新成员'),
                  value: room.locked,
                  onChanged: _busy
                      ? null
                      : (value) => _run(() async {
                          await _api.request(
                            'PATCH',
                            [room.id],
                            {'join_locked': value},
                          );
                        }),
                ),
                Wrap(
                  spacing: 8,
                  children: [
                    TextButton(
                      onPressed: _busy ? null : () => _edit(room, false),
                      child: const Text('重命名'),
                    ),
                    TextButton(
                      onPressed: _busy ? null : () => _edit(room, true),
                      child: const Text('更改密码'),
                    ),
                    TextButton.icon(
                      onPressed: _busy ? null : () => _leave(room),
                      icon: const Icon(Icons.delete_outline),
                      label: const Text('解散房间'),
                    ),
                  ],
                ),
              ],
            ],
          ),
        if (room.isOwner)
          ExpansionTile(
            title: const Text('邀请管理'),
            children: [
              if (_invites.isEmpty)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 12),
                  child: Text('尚未生成邀请；已生成链接的凭证不会再次返回。'),
                ),
              for (final invite in _invites)
                _surfaceCard(
                  child: ListTile(
                    title: Text(
                      '已使用 ${invite['uses']} / ${invite['max_uses']} 次',
                    ),
                    subtitle: Text(
                      '有效期至 ${DateTime.fromMillisecondsSinceEpoch((invite['expires_at'] as num).toInt() * 1000).toLocal()}${invite['revoked'] == true ? ' · 已撤销' : ''}',
                    ),
                    trailing: IconButton(
                      tooltip: '撤销邀请',
                      icon: const Icon(Icons.link_off_rounded),
                      onPressed: _busy || invite['revoked'] == true
                          ? null
                          : () async {
                              if (await _confirm(
                                    '撤销邀请',
                                    '链接将不能再用于加入，已加入成员不受影响。',
                                  ) &&
                                  mounted) {
                                await _run(() async {
                                  await _api.request('DELETE', [
                                    room.id,
                                    'invites',
                                    invite['id'] as String,
                                  ]);
                                });
                              }
                            },
                    ),
                  ),
                ),
              if (roster.bannedUserIds.isNotEmpty) ...[
                const SizedBox(height: 16),
                Text('封禁账号', style: Theme.of(context).textTheme.titleMedium),
                for (final user in roster.bannedUserIds)
                  _surfaceCard(
                    child: ListTile(
                      title: const Text('已封禁成员'),
                      trailing: TextButton(
                        onPressed: _busy
                            ? null
                            : () async {
                                if (await _confirm(
                                      '解除封禁',
                                      '该账号仍需使用有效密码或邀请重新加入。',
                                    ) &&
                                    mounted) {
                                  await _run(() async {
                                    await _api.request('DELETE', [
                                      room.id,
                                      'bans',
                                      user,
                                    ]);
                                  });
                                }
                              },
                        child: const Text('解除封禁'),
                      ),
                    ),
                  ),
              ],
            ],
          ),
      ],
    );
  }

  Widget _overviewHeader() => LayoutBuilder(
    builder: (context, constraints) {
      final actions = Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          FilledButton.icon(
            onPressed: _busy || _rooms.any((room) => room.isOwner)
                ? null
                : _create,
            icon: const Icon(Icons.add_rounded),
            label: const Text('创建房间'),
          ),
          OutlinedButton.icon(
            onPressed: _busy ? null : _join,
            icon: const Icon(Icons.meeting_room_outlined),
            label: const Text('加入房间'),
          ),
          OutlinedButton.icon(
            onPressed: _busy ? null : () => _joinWithLink(),
            icon: const Icon(Icons.link_rounded),
            label: const Text('粘贴邀请'),
          ),
        ],
      );
      if (!widget.showHeader) return actions;
      final title = Text('互联', style: Theme.of(context).textTheme.titleLarge);
      if (constraints.maxWidth >= 520) {
        return Row(children: [title, const Spacer(), actions]);
      }
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [title, const SizedBox(height: 8), actions],
      );
    },
  );

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: widget.settingsStore,
    builder: (context, _) => Scaffold(
      appBar: widget.embedded
          ? null
          : AppBar(
              title: const Text('互联'),
              actions: [
                IconButton(
                  tooltip: '刷新房间',
                  onPressed: _busy ? null : () => _refresh(),
                  icon: const Icon(Icons.refresh_rounded),
                ),
              ],
            ),
      body: SafeArea(
        child: RefreshIndicator(
          onRefresh: _refresh,
          child: ListView(
            padding: const EdgeInsets.fromLTRB(20, 12, 20, 20),
            children: [
              Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 1800),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      if (_selectedId == null) _overviewHeader(),
                      if (_rooms.isEmpty) ...[
                        const SizedBox(height: 8),
                        Text(
                          _parallel.supported
                              ? '和好友加入同一房间，连接后即可互访。可同时连接多个房间。'
                              : '和好友加入同一房间。此平台目前仍为单活动网络。',
                        ),
                      ],
                      const SizedBox(height: 12),
                      if (_selectedId != null)
                        Align(
                          alignment: Alignment.centerLeft,
                          child: TextButton.icon(
                            onPressed: _busy
                                ? null
                                : () {
                                    setState(() {
                                      _selectedId = null;
                                      _roster = null;
                                    });
                                    _generation++;
                                    widget.onRoomSelected?.call(null);
                                  },
                            icon: const Icon(Icons.arrow_back_rounded),
                            label: const Text('返回房间'),
                          ),
                        ),
                      if (_busy || _loading)
                        const Padding(
                          padding: EdgeInsets.symmetric(vertical: 16),
                          child: LinearProgressIndicator(),
                        ),
                      if (_operationError != null || _error != null)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          child: Semantics(
                            liveRegion: true,
                            child: Card(
                              color: Theme.of(context)
                                  .colorScheme
                                  .errorContainer,
                              child: Padding(
                                padding: const EdgeInsets.all(16),
                                child: Row(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Icon(Icons.error_outline),
                                    const SizedBox(width: 12),
                                    Expanded(
                                      child: Text(_operationError ?? _error!),
                                    ),
                                    IconButton(
                                      tooltip: '关闭提示',
                                      onPressed: () => setState(() {
                                        _operationError = null;
                                        _error = null;
                                      }),
                                      icon: const Icon(Icons.close),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ),
                        ),
                      const SizedBox(height: 4),
                      if (_selectedId == null) ...[
                        _roomList(),
                        const SizedBox(height: 16),
                      ],
                      if (_roster != null) _roomDetails(_roster!),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    ),
  );
}

class _RoomField {
  const _RoomField(
    this.label, {
    this.initial = '',
    this.hint,
    this.secret = false,
    this.multiline = false,
    this.number = false,
    this.maxLength = 128,
    this.validate,
  });
  final String label;
  final String initial;
  final String? hint;
  final bool secret;
  final bool multiline;
  final bool number;
  final int maxLength;
  final String? Function(String?)? validate;
}

class _RoomInputDialog extends StatefulWidget {
  const _RoomInputDialog({
    required this.title,
    required this.fields,
    this.description,
  });
  final String title;
  final List<_RoomField> fields;
  final String? description;
  @override
  State<_RoomInputDialog> createState() => _RoomInputDialogState();
}

class _RoomInputDialogState extends State<_RoomInputDialog> {
  final _formKey = GlobalKey<FormState>();
  late final _controllers = widget.fields
      .map((field) => TextEditingController(text: field.initial))
      .toList();
  @override
  void dispose() {
    for (final controller in _controllers) {
      controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.title),
    content: SizedBox(
      width: 460,
      child: SingleChildScrollView(
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (widget.description != null) ...[
                Text(widget.description!),
                const SizedBox(height: 20),
              ],
              for (var i = 0; i < widget.fields.length; i++)
                Padding(
                  padding: const EdgeInsets.only(bottom: 14),
                  child: TextFormField(
                    key: ValueKey(widget.fields[i].label),
                    controller: _controllers[i],
                    autofocus: i == 0,
                    obscureText: widget.fields[i].secret,
                    autocorrect: false,
                    enableSuggestions: !widget.fields[i].secret,
                    maxLength: widget.fields[i].maxLength,
                    maxLines: widget.fields[i].multiline ? 4 : 1,
                    keyboardType: widget.fields[i].number
                        ? TextInputType.number
                        : TextInputType.text,
                    decoration: InputDecoration(
                      labelText: widget.fields[i].label,
                      helperText: widget.fields[i].hint,
                      border: const OutlineInputBorder(),
                    ),
                    validator: widget.fields[i].validate,
                  ),
                ),
            ],
          ),
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: () {
          if (_formKey.currentState?.validate() == true) {
            Navigator.pop(
              context,
              _controllers.map((controller) => controller.text).toList(),
            );
          }
        },
        child: const Text('确认'),
      ),
    ],
  );
}
