import 'package:p2wlan_flutter_client/shared/widgets/app_notice.dart';

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/capabilities/platform_capabilities.dart';
import '../../core/rooms/room_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../app/app_strings.dart';
import '../../app/p2wlan_colors.dart';
import '../../app/app_tokens.dart';
import '../../shared/widgets/app_motion.dart';
import '../../shared/widgets/status_badge.dart';
import 'room_join_dialog.dart';
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
    this.onReauthenticate,
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
  final VoidCallback? onReauthenticate;
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
  final _rosterErrors = <String, String>{};
  final _rosterUpdatedAt = <String, DateTime>{};
  String? _invitesError;
  final _localIdentities = <String, Map<String, String>>{};
  final _autoConnect = <String, bool>{};
  List<Map<String, dynamic>> _invites = [];
  String? _invitesRoomId;
  String? _selectedId;
  String? _error;
  String? _operationError;
  RoomException? _authenticationError;
  int _authenticationFailureRevision = 0;
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
    if (_authenticationError != null) {
      _timer?.cancel();
      _timer = null;
      _scheduledInterval = null;
      return;
    }
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

  bool Function() _sessionGuard() {
    final settings = widget.settingsStore;
    final status = widget.statusStore;
    final account = accountSessionKey(settings.settings);
    final revision = status.sessionRevision;
    return () =>
        mounted &&
        identical(settings, widget.settingsStore) &&
        identical(status, widget.statusStore) &&
        _sameSession &&
        accountSessionKey(settings.settings) == account &&
        status.sessionRevision == revision;
  }

  @override
  void initState() {
    super.initState();
    _parallel.addListener(_parallelChanged);
    widget.statusStore.addListener(_parallelChanged);
    final settings = widget.settingsStore.settings;
    try {
      if (settings.authToken.trim().isEmpty) {
        throw const RoomException('请先登录控制服务器后使用房间', code: 'auth_expired');
      }
      _apiInstance =
          widget.api ??
          RoomApi(server: settings.controlServer, token: settings.authToken);
    } catch (error) {
      if (_isAuthenticationError(error)) {
        _authenticationError = error as RoomException;
      } else {
        _error = _message(error);
      }
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
      final isCurrent = _sessionGuard();
      await _join(invitation.toString());
      if (isCurrent() && widget.initialInvitation == invitation) {
        widget.onInvitationHandled?.call();
      }
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
    final isCurrent = _sessionGuard();
    final settings = widget.settingsStore.settings;
    try {
      final identity = await widget.statusStore.daemonController
          .roomDeviceIdentity(selectRoomSettings(settings, room));
      if (!isCurrent()) {
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
    if (!mounted ||
        !_sameSession ||
        _refreshing ||
        silent && _authenticationError != null) {
      return;
    }
    if (_authenticationError != null) {
      setState(() => _refreshing = true);
    } else {
      _refreshing = true;
    }
    final isCurrent = _sessionGuard();
    final generation = ++_generation;
    final authenticationFailureRevision = _authenticationFailureRevision;
    bool refreshIsCurrent() =>
        generation == _generation &&
        authenticationFailureRevision == _authenticationFailureRevision &&
        isCurrent();
    final selected = _selectedId;
    try {
      final rooms = await _api.list();
      if (!refreshIsCurrent()) return;
      if (_parallel.supported) {
        for (final room in rooms) {
          unawaited(_parallel.recover(room));
        }
      }
      final id = rooms.any((room) => room.id == selected) ? selected : null;
      final summaries = <String, RoomRoster>{};
      final errors = <String, String>{};
      Future<void> loadRoster(FriendRoom room) async {
        if (!refreshIsCurrent()) return;
        try {
          summaries[room.id] = await _api.roster(room.id);
        } catch (error) {
          if (!refreshIsCurrent()) return;
          if (_isAuthenticationError(error)) rethrow;
          errors[room.id] = _message(error);
        }
      }

      final requested = rooms
          .where((room) => room.id == id || room.memberCount == null)
          .toList();
      // Keep legacy-server summary requests bounded and independent: a single
      // failed roster must not hide the list or another room's details.
      for (var offset = 0; offset < requested.length; offset += 4) {
        await Future.wait(
          requested.skip(offset).take(4).map(loadRoster),
          eagerError: true,
        );
        if (!refreshIsCurrent()) return;
      }
      final roster = summaries[id];
      bool? autoConnect;
      if (roster != null && _parallel.supported && _canConnect) {
        final preference = await _parallel.connectionPreference(roster.room);
        if (!refreshIsCurrent()) return;
        autoConnect = preference.autoConnect;
      }
      List<Map<String, dynamic>>? invites;
      String? invitesError;
      if (roster?.room.isOwner == true) {
        try {
          final data = await _api.request('GET', [id!, 'invites']);
          invites = (data['invites'] as List? ?? const [])
              .map((item) => Map<String, dynamic>.from(item as Map))
              .toList();
        } catch (error) {
          if (_isAuthenticationError(error)) rethrow;
          invitesError = _message(error);
        }
      }
      if (!refreshIsCurrent()) return;
      setState(() {
        _rooms = rooms;
        bool removed(String roomId) => !rooms.any((room) => room.id == roomId);
        _rosters.removeWhere((roomId, _) => removed(roomId));
        _rosterErrors.removeWhere((roomId, _) => removed(roomId));
        _rosterUpdatedAt.removeWhere((roomId, _) => removed(roomId));
        _rosters.addAll(summaries);
        for (final roomId in summaries.keys) {
          _rosterErrors.remove(roomId);
          _rosterUpdatedAt[roomId] = DateTime.now();
        }
        _rosterErrors.addAll(errors);
        _selectedId = id;
        _roster = _rosters[id];
        if (autoConnect != null && id != null) _autoConnect[id] = autoConnect;
        if (id != _invitesRoomId || roster?.room.isOwner == false) {
          _invites = [];
        }
        _invitesRoomId = id;
        if (invites != null) _invites = invites;
        _invitesError = invitesError;
        if (errors.isEmpty && invitesError == null) _authenticationError = null;
        _error = null;
      });
      if (roster != null && _canConnect) {
        unawaited(_loadLocalIdentity(roster.room));
      }
      _roomViewRevision.value++;
      widget.onRoomSelected?.call(id);
    } catch (error) {
      if (refreshIsCurrent()) {
        if (_recordAuthenticationError(error, isCurrent)) return;
        setState(() {
          _error = _message(error);
          // A failed list also makes cached control-plane device presence stale.
          for (final room in _rooms) {
            _rosterErrors[room.id] = _message(error);
          }
        });
      }
    } finally {
      _refreshing = false;
      if (mounted && generation == _generation) {
        setState(() => _loading = false);
      }
      if (isCurrent()) _scheduleTimer();
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

    if (_snapshotStale(currentSnapshot)) return '状态待更新';
    return RoomConnectivitySummary.fromSnapshot(currentSnapshot).label;
  }

  String _message(Object error) =>
      error is RoomException ? error.message : '操作未完成，请检查连接后重试';

  bool _isAuthenticationError(Object error) =>
      error is RoomException && error.code == 'auth_expired';

  bool _recordAuthenticationError(Object error, bool Function() isCurrent) {
    if (!_isAuthenticationError(error) || !isCurrent()) return false;
    final failure = error as RoomException;
    setState(() {
      _authenticationFailureRevision++;
      _authenticationError = failure;
      _error = null;
      _operationError = null;
      for (final room in _rooms) {
        _rosterErrors[room.id] = failure.message;
      }
    });
    _roomViewRevision.value++;
    _scheduleTimer();
    return true;
  }

  bool get _serverActionsBusy => _busy || _authenticationError != null;

  Future<void> _run(
    Future<void> Function(bool Function() isCurrent) operation, {
    String? success,
    bool requiresAuthentication = true,
  }) async {
    if (_busy ||
        !mounted ||
        requiresAuthentication && _authenticationError != null) {
      return;
    }
    if (!_sameSession) {
      setState(() => _operationError = '登录账号或服务器已变化，请重新登录。');
      return;
    }
    final isCurrent = _sessionGuard();
    _generation++;
    setState(() {
      _busy = true;
      _operationError = null;
    });
    try {
      await operation(isCurrent);
      if (isCurrent() && success != null) _notify(success);
    } catch (error) {
      if (isCurrent()) {
        if (!_recordAuthenticationError(error, isCurrent)) {
          setState(() => _operationError = _message(error));
        }
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
    while (isCurrent() && _authenticationError == null && _refreshing) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (isCurrent() && _authenticationError == null) await _refresh();
  }

  void _notify(String message) {
    showAppNotice(context, content: Text(message));
  }

  bool _snapshotStale(DiagnosticsSnapshot snapshot) =>
      snapshot.peerSnapshotStale ||
      snapshot.capturedRevision != snapshot.revision;

  String _deviceDataLabel(
    Map<String, dynamic> device,
    DiagnosticsSnapshot? snapshot,
  ) => snapshot != null && _snapshotStale(snapshot)
      ? '状态待更新'
      : roomDeviceDataLabel(device, snapshot);

  Future<bool> _copyText(String value, {String? success}) async {
    final isCurrent = _sessionGuard();
    if (!isCurrent()) return false;
    try {
      await Clipboard.setData(ClipboardData(text: value));
    } catch (_) {
      if (isCurrent()) _notify('复制失败，请手动选择并复制');
      return false;
    }
    if (!isCurrent()) return false;
    if (success != null) _notify(success);
    return true;
  }

  Future<bool> _confirm(String title, String message) async {
    final isCurrent = _sessionGuard();
    if (!isCurrent()) return false;
    final confirmed = await showDialog<bool>(
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
    );
    return confirmed == true && isCurrent();
  }

  Future<List<String>?> _form(
    String title,
    List<_RoomField> fields, {
    String? description,
  }) async {
    if (_authenticationError != null) return null;
    if (!_sameSession) {
      setState(() => _error = '请先登录当前控制服务器后使用房间');
      return null;
    }
    final isCurrent = _sessionGuard();
    final result = await showDialog<List<String>>(
      context: context,
      builder: (_) => _RoomInputDialog(
        title: title,
        fields: fields,
        description: description,
      ),
    );
    return isCurrent() ? result : null;
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
    final values = await _form('创建房间', [
      _nameField(),
      _passwordField,
    ], description: '每个账号可以创建一个房间。服务器会分配独立的 10.21.x.0/24 网段，不改变你的个人网络。');
    if (values == null || !mounted) return;
    await _run((isCurrent) async {
      final room = await _api.create(values[0].trim(), values[1]);
      if (isCurrent()) _selectedId = room.id;
    }, success: '房间已创建');
  }

  Future<void> _join([String initial = '']) async {
    if (!mounted || _serverActionsBusy) return;
    if (!_sameSession) {
      setState(() => _operationError = '请先登录当前控制服务器后使用房间');
      return;
    }
    final isCurrent = _sessionGuard();
    final room = await showDialog<FriendRoom>(
      context: context,
      builder: (_) => RoomJoinDialog(
        server: _api.server,
        initial: initial,
        isCurrent: isCurrent,
        onJoin: (request) async {
          if (!isCurrent() || _authenticationError != null) return null;
          try {
            final joined = await _api.join(
              request.code,
              password: request.password,
              invitation: request.invitation,
            );
            return isCurrent() ? joined : null;
          } catch (error) {
            if (!isCurrent()) return null;
            if (_recordAuthenticationError(error, isCurrent)) return null;
            rethrow;
          }
        },
      ),
    );
    if (room == null || !isCurrent()) return;
    await _run((isCurrent) async {
      if (isCurrent()) _selectedId = room.id;
    }, success: '账号已加入房间，点击“连接本机”开始互联');
  }

  Future<void> _connect(FriendRoom? room) async {
    if (!_canConnect || _serverActionsBusy) return;
    if (_parallel.supported && room != null) {
      await _run((isCurrent) async {
        if (widget.settingsStore.settings.networkId == room.id) {
          final stopped = await widget.statusStore.stopPrimaryDaemon();
          if (!isCurrent()) return;
          if (!stopped.ok) throw const RoomException('旧的单房间运行时未能停止');
          await widget.settingsStore.updateSettings(
            personalNetworkSettings(widget.settingsStore.settings),
          );
        }
        if (!isCurrent()) return;
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
    await _run((isCurrent) async {
      final stopped = await widget.statusStore.stopPrimaryDaemon();
      if (!isCurrent()) return;
      if (!stopped.ok) throw const RoomException('旧网络未能停止，未切换网络');
      final current = widget.settingsStore.settings;
      final next = room == null
          ? (isRoomNetwork(current.networkId)
                ? personalNetworkSettings(current)
                : current)
          : selectRoomSettings(current, room);
      if (room != null) roomProfileId(next);
      await widget.settingsStore.updateSettings(next);
      if (!isCurrent()) return;
      final started = await widget.statusStore.startDaemon();
      if (!started.ok) throw RoomException(started.message);
    }, success: '网络连接已启动');
  }

  Future<void> _disconnectRoom(FriendRoom room) async {
    await _run(
      (isCurrent) async {
        final result =
            _parallel.session(room.id) == null &&
                widget.settingsStore.settings.networkId == room.id
            ? await widget.statusStore.stopPrimaryDaemon()
            : await _parallel.disconnect(room.id);
        if (!isCurrent()) return;
        if (!result.ok) throw RoomException(result.message);
        await _parallel.forgetConnectionIntent(room);
      },
      success: '已断开本机，其他设备和房间保持运行',
      requiresAuthentication: false,
    );
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
    await _run((isCurrent) async {
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
    await _run((isCurrent) async {
      final data = await _api.request(
        'POST',
        [room.id, 'invites'],
        {
          'ttl_seconds': int.parse(values[0].trim()) * 3600,
          'max_uses': int.parse(values[1].trim()),
        },
      );
      if (!isCurrent()) return;
      final token = data['invite_token'] as String? ?? '';
      final link = RoomInvitation(
        _api.server,
        room.code,
        token,
      ).toUri().toString();
      RoomInvitation.parse(link, _api.server);
      if (!mounted || !isCurrent()) return;
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
                if (!isCurrent()) return;
                final route = ModalRoute.of(context);
                final copied = await _copyText(link);
                if (copied &&
                    isCurrent() &&
                    context.mounted &&
                    route?.isCurrent == true) {
                  Navigator.pop(context);
                }
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
    await _run((isCurrent) async {
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
    await _run((isCurrent) async {
      final result = await _api.request(
        'PATCH',
        [room.id, 'devices', device['id'] as String],
        {'virtual_ip': values[0].trim()},
      );
      if (isCurrent()) {
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
    await _run((isCurrent) async {
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
    await _run((isCurrent) async {
      await _api.request('POST', [
        room.id,
        'device-access',
        access['id'] as String,
        action,
      ]);
      if (!isCurrent()) return;
      if (_isLocalDevice(room, device) &&
          (action == 'disconnect' || action == 'block')) {
        final stopped = await _parallel.disconnect(room.id);
        if (!isCurrent()) return;
        if (!stopped.ok) throw RoomException(stopped.message);
        if (widget.settingsStore.settings.networkId == room.id && _canConnect) {
          final primary = await widget.statusStore.stopPrimaryDaemon();
          if (!isCurrent()) return;
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
    await _run((isCurrent) async {
      final result = await _parallel.disconnect(room.id);
      if (!isCurrent()) return;
      if (!result.ok) throw const RoomException('本地并行房间未能停止，尚未退出');
      if (widget.settingsStore.settings.networkId == room.id) {
        if (_canConnect) {
          final stopped = await widget.statusStore.stopPrimaryDaemon();
          if (!isCurrent()) return;
          if (!stopped.ok) throw const RoomException('本地房间网络无法停止，尚未退出房间');
        }
      }
      await _parallel.forgetConnectionIntent(room);
      if (!isCurrent()) return;
      await _api.request(room.isOwner ? 'DELETE' : 'POST', [
        room.id,
        if (!room.isOwner) 'leave',
      ]);
      if (!isCurrent()) return;
      if (widget.settingsStore.settings.networkId == room.id) {
        await widget.settingsStore.updateSettings(
          personalNetworkSettings(widget.settingsStore.settings),
        );
      }
      if (isCurrent()) _selectedId = null;
    }, success: room.isOwner ? '房间已解散' : '已退出房间');
  }

  Widget _surfaceCard({required Widget child, bool selected = false}) {
    final colors = P2WlanColors.of(context);
    return Card(
      elevation: 0,
      margin: const EdgeInsets.only(bottom: 8),
      color: selected ? colors.selectedSurface : colors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: selected ? colors.borderStrong : colors.border),
      ),
      clipBehavior: Clip.antiAlias,
      child: child,
    );
  }

  Future<void> _selectRoom(String id) async {
    final isCurrent = _sessionGuard();
    if (!isCurrent()) return;
    setState(() {
      _selectedId = id;
      _roster = _rosters[id];
      _loading = _authenticationError == null;
    });
    if (_authenticationError != null) {
      widget.onRoomSelected?.call(id);
      return;
    }
    _generation++;
    while (isCurrent() && _refreshing) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (isCurrent()) await _refresh();
  }

  Widget _roomList() {
    if (_rooms.isEmpty) {
      if (_loading || _authenticationError != null) {
        return const SizedBox.shrink();
      }
      final palette = P2WlanColors.of(context);
      return _surfaceCard(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 40),
          child: Column(
            children: [
              Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  color: palette.selectedSurface,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Icon(
                  Icons.meeting_room_outlined,
                  size: 28,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
              const SizedBox(height: 18),
              Text(
                '和好友连接到同一房间',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 380),
                child: Text(
                  '输入好友发来的房间号或邀请链接。也可以创建房间，邀请其他设备加入。',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium
                      ?.copyWith(color: palette.textSecondary),
                ),
              ),
              const SizedBox(height: 20),
              TextButton.icon(
                onPressed: _serverActionsBusy ? null : () => _join(),
                icon: const Icon(Icons.login_rounded),
                label: const Text('输入房间号或邀请链接'),
              ),
            ],
          ),
        ),
      );
    }
    return LayoutBuilder(
      builder: (context, constraints) {
        const gap = 16.0;
        final minCardWidth =
            340 * MediaQuery.textScalerOf(context).scale(14) / 14;
        final columns = ((constraints.maxWidth + gap) / minCardWidth)
            .floor()
            .clamp(1, _rooms.length.clamp(1, 4));
        final width = (constraints.maxWidth - gap * (columns - 1)) / columns;
        return Wrap(
          spacing: gap,
          runSpacing: gap,
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
    final snapshot = _roomSnapshot(room);
    final colors = P2WlanColors.of(context);
    return _surfaceCard(
      child: _RoomActionSurface(
        key: ValueKey('room-card-${room.id}'),
        label: '查看房间 ${room.name}',
        onTap: _busy ? null : () => _selectRoom(room.id),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: Wrap(
                      spacing: 10,
                      runSpacing: 6,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        Text(
                          room.name,
                          style: Theme.of(context).textTheme.titleMedium
                              ?.copyWith(fontWeight: FontWeight.w700),
                        ),
                        _connectionBadge(room),
                        if (room.locked)
                          const Tooltip(
                            message: '已锁定新成员加入',
                            child: Icon(Icons.lock_outline, size: 16),
                          ),
                      ],
                    ),
                  ),
                  Icon(
                    Icons.chevron_right_rounded,
                    color: colors.textMuted,
                    size: 20,
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                '房主 · ${owner.isEmpty ? '未设置用户名' : owner}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 10),
              Wrap(
                spacing: 24,
                runSpacing: 8,
                children: [
                  _roomMetric('在线 / 总人数', '${online ?? '—'} / ${total ?? '—'}'),
                  if (!room.isOwner)
                    Tooltip(
                      message: '本机到房主在线设备的实测延迟；多台设备取最低值。',
                      child: _roomMetric('房主延迟', _ownerLatency(room, roster)),
                    ),
                ],
              ),
              if (_rosterErrors.containsKey(room.id)) ...[
                const SizedBox(height: 10),
                Text(
                  roster == null ? '成员信息暂不可用，点击房间可重试' : '成员信息更新失败，显示上次结果',
                  style: Theme.of(context).textTheme.bodySmall
                      ?.copyWith(color: colors.warningText),
                ),
              ],
              if (snapshot != null && _snapshotStale(snapshot)) ...[
                const SizedBox(height: 10),
                Text('链路信息待更新', style: Theme.of(context).textTheme.bodySmall),
              ],
              if (session?.message case final message?) ...[
                const SizedBox(height: 10),
                Text(message, style: Theme.of(context).textTheme.bodySmall),
              ],
              const SizedBox(height: 10),
              LayoutBuilder(
                builder: (context, constraints) {
                  final code = Text(
                    '房间号 ${room.code}',
                    style: Theme.of(context).textTheme.bodySmall
                        ?.copyWith(fontFeatures: AppTokens.tabularFontFeatures),
                  );
                  if (!_canConnect) return code;
                  final button = _connectionButton(room, card: true);
                  if (constraints.maxWidth < 280 ||
                      MediaQuery.textScalerOf(context).scale(14) > 20) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [code, const SizedBox(height: 10), button],
                    );
                  }
                  return Row(
                    children: [
                      Expanded(child: code),
                      const SizedBox(width: 12),
                      button,
                    ],
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  bool get _connectionBusy =>
      _busy || _parallel.busy || widget.statusStore.daemonBusy;

  Widget _connectionBadge(FriendRoom room) {
    final session = _parallel.session(room.id);
    final snapshot = _roomSnapshot(room);
    final tone = session?.phase == RoomConnectionPhase.failed
        ? StatusTone.bad
        : session?.phase == RoomConnectionPhase.unavailable ||
              snapshot != null && _snapshotStale(snapshot)
        ? StatusTone.warn
        : snapshot == null
        ? StatusTone.neutral
        : RoomConnectivitySummary.fromSnapshot(snapshot).dataWarning != null
        ? StatusTone.warn
        : RoomConnectivitySummary.fromSnapshot(snapshot).established > 0
        ? StatusTone.good
        : StatusTone.neutral;
    final primaryStarting =
        session == null &&
        widget.settingsStore.settings.networkId == room.id &&
        widget.statusStore.daemonStarting;
    return StatusBadge(
      label: primaryStarting ? '本机启动' : _connectionLabel(session, snapshot),
      tone: tone,
    );
  }

  Widget _connectionButton(FriendRoom room, {bool card = false}) {
    final connection = _parallel.session(room.id);
    final primaryConnected = connection == null && _roomSnapshot(room) != null;
    final disconnect = connection != null || primaryConnected;
    final primaryStarting =
        connection == null &&
        widget.settingsStore.settings.networkId == room.id &&
        widget.statusStore.daemonStarting;
    final transitioning =
        primaryStarting ||
        connection?.phase == RoomConnectionPhase.starting ||
        connection?.phase == RoomConnectionPhase.stopping;
    final label = primaryStarting
        ? '本机启动'
        : transitioning
        ? _connectionLabel(connection)
        : disconnect
        ? '断开本机'
        : widget.settingsStore.settings.networkId == room.id
        ? '重新连接本机'
        : '连接本机';
    final palette = P2WlanColors.of(context);
    return FilledButton.tonalIcon(
      style: disconnect
          ? FilledButton.styleFrom(
              backgroundColor: palette.surfaceMuted,
              foregroundColor: palette.textPrimary,
              side: BorderSide(color: palette.border),
            )
          : null,
      key: ValueKey(
        '${card ? 'room-card' : 'room-detail'}-connection-${room.id}',
      ),
      onPressed:
          _connectionBusy ||
              transitioning ||
              !disconnect && _authenticationError != null
          ? null
          : () => disconnect ? _disconnectRoom(room) : _connect(room),
      icon: Icon(disconnect ? Icons.link_off_rounded : Icons.lan_outlined),
      label: Text(label),
    );
  }

  String _ownerLatency(FriendRoom room, RoomRoster? roster) {
    if (room.isOwner) return '我是房主';
    final snapshot = _roomSnapshot(room);
    if (snapshot == null) return '连接后测量';
    if (_snapshotStale(snapshot)) return '待更新';
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
    if (roster == null) return '进入房间后查看';
    final latencies =
        snapshot.peers
            .where(
              (p) =>
                  ips.contains(p.virtualIp) &&
                  (roster.devices.any(
                    (device) =>
                        device['user_id'] == room.ownerId &&
                        roomPeerForDevice(device, [p]) != null,
                  )),
            )
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
    if (roomDeviceIsSnapshotLocal(device, snapshot)) return true;
    final peer = roomPeerForDevice(device, peers);
    if (peer != null) return peer.online;
    return device['online'] == true;
  }

  Widget _deviceList(RoomRoster roster) {
    final snapshot = _roomSnapshot(roster.room);
    final peers = snapshot != null && !_snapshotStale(snapshot)
        ? snapshot.peers
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
            roomDeviceNodeId(d) == peer.nodeId ||
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
        !devices.any(
          (d) =>
              roomDeviceNodeId(d) == snapshot.nodeId ||
              d['virtual_ip'] == snapshot.virtualIp,
        )) {
      devices.insert(0, {
        'node_id': snapshot.nodeId,
        'device_name': widget.settingsStore.settings.deviceName,
        'virtual_ip': snapshot.virtualIp,
        'user_id': _api.userId,
        'online': true,
      });
    }
    final users = <String>{
      ...roster.members.map((member) => member['user_id'] as String? ?? ''),
      ...devices.map((device) => device['user_id'] as String? ?? ''),
    };
    bool onlyLocalDevices(String user) {
      final owned = devices.where(
        (device) => (device['user_id'] ?? '') == user,
      );
      return owned.isNotEmpty &&
          owned.every(
            (device) =>
                _isLocalDevice(roster.room, device) ||
                roomDeviceIsSnapshotLocal(device, snapshot),
          );
    }

    final prioritizedUsers = MediaQuery.sizeOf(context).width < 700
        ? [
            ...users.where((user) => !onlyLocalDevices(user)),
            ...users.where(onlyLocalDevices),
          ]
        : users;
    bool hasDevices(String user) =>
        devices.any((device) => (device['user_id'] ?? '') == user);
    final orderedUsers = [
      ...prioritizedUsers.where(hasDevices),
      ...prioritizedUsers.where((user) => !hasDevices(user)),
    ];
    final palette = P2WlanColors.of(context);
    return _surfaceCard(
      child: LayoutBuilder(
        builder: (context, constraints) => Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 18, 18, 14),
              child: Text(
                '设备与连接 · ${devices.length}',
                style: Theme.of(context).textTheme.titleMedium
                    ?.copyWith(fontSize: 15, fontWeight: FontWeight.w700),
              ),
            ),
            if (constraints.maxWidth >= 988 &&
                MediaQuery.textScalerOf(context).scale(14) < 20)
              Padding(
                padding: const EdgeInsets.fromLTRB(14, 0, 14, 10),
                child: DefaultTextStyle(
                  style: Theme.of(context).textTheme.bodySmall!,
                  child: const Row(
                    children: [
                      Expanded(flex: 3, child: Text('设备')),
                      SizedBox(width: 16),
                      SizedBox(width: 180, child: Text('虚拟 IP')),
                      SizedBox(width: 110, child: Text('连接')),
                      Expanded(flex: 2, child: Text('房间数据')),
                      SizedBox(width: 110, child: Text('端到端延迟')),
                      SizedBox(width: 88, child: Text('状态')),
                      SizedBox(width: 66),
                    ],
                  ),
                ),
              ),
            if (devices.isEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(18, 8, 18, 24),
                child: Text(
                  '还没有设备连接。连接房间后，设备 IP 和连接质量会显示在这里。',
                  style: Theme.of(context).textTheme.bodyMedium
                      ?.copyWith(color: palette.textSecondary),
                ),
              ),
            for (final user in orderedUsers) ...[
              Container(
                color: palette.surfaceMuted,
                padding: const EdgeInsets.symmetric(
                  horizontal: 18,
                  vertical: 8,
                ),
                child: DefaultTextStyle.merge(
                  style: Theme.of(context).textTheme.bodySmall
                      ?.copyWith(fontWeight: FontWeight.w600),
                  child: MediaQuery.textScalerOf(context).scale(14) < 20
                      ? Text(
                          '${user.isEmpty ? '成员信息同步中' : _memberLabel(user)} · ${user == roster.room.ownerId ? '房主' : '成员'} · ${devices.where((d) => (d['user_id'] ?? '') == user).length} 台设备',
                        )
                      : Wrap(
                          spacing: 12,
                          runSpacing: 4,
                          children: [
                            Text(user.isEmpty ? '成员信息同步中' : _memberLabel(user)),
                            Text(user == roster.room.ownerId ? '房主' : '成员'),
                            Text(
                              '${devices.where((d) => (d['user_id'] ?? '') == user).length} 台设备',
                            ),
                          ],
                        ),
                ),
              ),
              for (final device in devices.where(
                (d) => (d['user_id'] ?? '') == user,
              ))
                _deviceCard(
                  roster.room,
                  device,
                  snapshot,
                  peers,
                  withinList: true,
                ),
            ],
          ],
        ),
      ),
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
          final peers = snapshot != null && !_snapshotStale(snapshot)
              ? snapshot.peers
              : <PeerSnapshot>[];
          final candidates =
              _rosters[room.id]?.devices ?? <Map<String, dynamic>>[];
          var current = device;
          for (final candidate in candidates) {
            if (device['id'] != null && candidate['id'] == device['id']) {
              current = candidate;
              break;
            }
          }
          final peer = roomPeerForDevice(current, peers);
          final local = roomDeviceIsSnapshotLocal(current, snapshot);
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
                '${room.name} · ${user == room.ownerId ? '房主' : '成员'} · ${_memberLabel(user)}\n房间数据：${_deviceDataLabel(current, snapshot)}\n链路与收包状态不代表系统 ping 一定可达。',
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
              await _copyText(value, success: '已复制');
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
    bool withinList = false,
  }) {
    final ip = device['virtual_ip'] as String? ?? '';
    final local =
        _isLocalDevice(room, device) ||
        roomDeviceIsSnapshotLocal(device, snapshot);
    final peer = roomPeerForDevice(device, peers);
    final mappingMismatch =
        snapshot != null &&
        !_snapshotStale(snapshot) &&
        roomDeviceMappingMismatch(device, peers);
    final access = _accessFor(room, device);
    final state = access?['state'] as String? ?? 'allowed';
    final online = state == 'allowed' && _deviceOnline(device, snapshot, peers);
    final path = local
        ? '本机'
        : !online
        ? '未连接'
        : snapshot == null
        ? '本机未连接'
        : _snapshotStale(snapshot)
        ? '状态待更新'
        : mappingMismatch
        ? '地址待同步'
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
    final green = P2WlanColors.of(context).successText;
    final statusColor = colors.onSurfaceVariant;
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
        : _snapshotStale(snapshot)
        ? '待更新'
        : latency == null
        ? '未测得'
        : '$latency ms';
    final management =
        ((room.isOwner ||
                userId == _api.userId &&
                    state != 'pending' &&
                    (state != 'blocked' ||
                        access?['blocked_by'] == _api.userId)) &&
            (access != null || room.isOwner && device['id'] is String))
        ? PopupMenuButton<String>(
            tooltip: '管理设备',
            enabled: !_serverActionsBusy,
            onSelected: (action) => action == 'ip'
                ? _changeIp(room, device)
                : action == 'delete'
                ? _deleteDevice(room, device)
                : _controlDevice(room, device, access!, action),
            itemBuilder: (_) => [
              if (room.isOwner &&
                  device['id'] is String &&
                  (device['id'] as String).isNotEmpty)
                const PopupMenuItem(value: 'ip', child: Text('分配 IP')),
              if (access != null) ...[
                if (state == 'allowed')
                  const PopupMenuItem(
                    value: 'disconnect',
                    child: Text('断开此设备'),
                  ),
                if (state != 'blocked' && (state != 'pending' || room.isOwner))
                  const PopupMenuItem(
                    value: 'block',
                    child: Text('禁止此设备连接此房间'),
                  ),
                if (state == 'blocked' &&
                    (room.isOwner || access['blocked_by'] == _api.userId))
                  const PopupMenuItem(value: 'unblock', child: Text('解除设备限制')),
                if (state == 'pending' && room.isOwner)
                  const PopupMenuItem(value: 'approve', child: Text('批准此设备')),
              ] else if (room.isOwner)
                const PopupMenuItem(value: 'delete', child: Text('删除设备')),
            ],
          )
        : null;
    final staleRoster = _rosterErrors.containsKey(room.id);
    final status = StatusBadge(
      label: state == 'blocked'
          ? '已禁止'
          : state == 'pending'
          ? '待审批'
          : state == 'paused'
          ? '已断开'
          : staleRoster && peer == null && !local
          ? '状态待更新'
          : online
          ? '在线'
          : '离线',
      tone: state == 'blocked'
          ? StatusTone.bad
          : state == 'pending' || staleRoster && peer == null && !local
          ? StatusTone.warn
          : online
          ? StatusTone.good
          : StatusTone.neutral,
    );
    final ipWidget = Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Flexible(
          child: SelectableText(
            ip.isEmpty ? '待分配' : ip,
            style: const TextStyle(fontWeight: FontWeight.w600),
          ),
        ),
        if (ip.isNotEmpty)
          IconButton(
            tooltip: '复制 IP',
            iconSize: 16,
            style: _desktopLayout(context)
                ? IconButton.styleFrom(
                    minimumSize: const Size(40, 40),
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  )
                : null,
            icon: const Icon(Icons.copy_rounded),
            onPressed: () async {
              await _copyText(ip, success: 'IP 已复制');
            },
          ),
      ],
    );
    final latencyWidget = Text(
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
    );
    final pathLabel = staleRoster && peer == null && !local ? '成员信息待更新' : path;
    final pathWidget = Text(pathLabel);
    final dataLabel = _deviceDataLabel(device, snapshot);
    final dataWidget = Text(dataLabel);
    final content = _RoomActionSurface(
      key: ValueKey(
        'room-device-${device['id'] ?? device['public_key'] ?? ip}',
      ),
      label: interactive ? '查看设备 ${device['device_name'] ?? '设备'}' : null,
      borderRadius: withinList ? BorderRadius.zero : null,
      onTap: interactive ? () => _showRoomDeviceDetails(room, device) : null,
      child: Padding(
        padding: EdgeInsets.symmetric(
          horizontal: 14,
          vertical: _desktopLayout(context) ? 8 : 10,
        ),
        child: LayoutBuilder(
          builder: (context, constraints) {
            final wide =
                constraints.maxWidth >= 960 &&
                MediaQuery.textScalerOf(context).scale(14) < 20;
            final header = Row(
              children: [
                if (MediaQuery.textScalerOf(context).scale(14) < 20) ...[
                  Icon(Icons.computer_rounded, color: statusColor, size: 22),
                  const SizedBox(width: 10),
                ],
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '${device['device_name'] ?? '设备'}${local ? '（本机）' : ''}',
                        style: Theme.of(context).textTheme.titleSmall,
                      ),
                      if (!withinList) ...[
                        const SizedBox(height: 3),
                        Text(
                          identity,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ],
                  ),
                ),
                if (!wide && management != null) management,
                if (!wide && interactive)
                  const Icon(Icons.chevron_right_rounded, size: 18),
              ],
            );
            Widget metric(String label, Widget value) => withinList
                ? value
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(label, style: Theme.of(context).textTheme.bodySmall),
                      const SizedBox(height: 4),
                      value,
                    ],
                  );
            Widget inlineMetric(String label, Widget value) => Wrap(
              spacing: 6,
              runSpacing: 2,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Text(
                  label,
                  style: Theme.of(context).textTheme.bodySmall
                      ?.copyWith(color: P2WlanColors.of(context).textSecondary),
                ),
                value,
              ],
            );
            final connectionMetrics = [
              status,
              inlineMetric(
                dataLabel == pathLabel ? '链路 / 数据' : '链路',
                pathWidget,
              ),
              Tooltip(
                message: '端到端实测延迟',
                child: inlineMetric('延迟', latencyWidget),
              ),
              if (dataLabel != pathLabel) inlineMetric('数据', dataWidget),
            ];
            if (wide) {
              return Row(
                children: [
                  Expanded(flex: 3, child: header),
                  const SizedBox(width: 16),
                  SizedBox(width: 180, child: metric('虚拟 IP', ipWidget)),
                  SizedBox(width: 110, child: metric('连接', pathWidget)),
                  Expanded(flex: 2, child: metric('房间数据', dataWidget)),
                  SizedBox(width: 110, child: metric('端到端延迟', latencyWidget)),
                  SizedBox(
                    width: withinList ? 88 : null,
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: status,
                    ),
                  ),
                  if (withinList)
                    SizedBox(width: 48, child: management)
                  else
                    ?management,
                  if (interactive)
                    const Icon(Icons.chevron_right_rounded, size: 18),
                ],
              );
            }
            if (constraints.maxWidth >= 480 &&
                MediaQuery.textScalerOf(context).scale(14) < 20) {
              return Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  header,
                  Wrap(
                    spacing: 12,
                    runSpacing: 4,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [ipWidget, ...connectionMetrics],
                  ),
                ],
              );
            }
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                header,
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Semantics(label: '虚拟 IP', child: ipWidget),
                ),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [...connectionMetrics],
                ),
              ],
            );
          },
        ),
      ),
    );
    return withinList
        ? DecoratedBox(
            decoration: BoxDecoration(
              border: Border(
                top: BorderSide(color: P2WlanColors.of(context).border),
              ),
            ),
            child: content,
          )
        : _surfaceCard(child: content);
  }

  Widget _roomMetric(String label, String value) => Wrap(
    spacing: 8,
    runSpacing: 4,
    crossAxisAlignment: WrapCrossAlignment.center,
    children: [
      Text(label, style: Theme.of(context).textTheme.bodySmall),
      Text(
        value,
        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
          fontWeight: FontWeight.w600,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
    ],
  );

  Widget _autoConnectToggle(FriendRoom room) => SwitchListTile.adaptive(
    title: const Text('启动时自动连接此房间'),
    subtitle: const Text('仅对本机生效；手动或远程断开后，需重新手动连接'),
    value: _autoConnect[room.id] ?? false,
    onChanged: _busy
        ? null
        : (value) => _run((isCurrent) async {
            await _parallel.setAutoConnect(room, value);
            if (isCurrent()) _autoConnect[room.id] = value;
          }, requiresAuthentication: false),
  );

  Widget _managementList(List<Widget> rows) => _surfaceCard(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        for (var i = 0; i < rows.length; i++) ...[
          if (i > 0) const Divider(height: 1),
          rows[i],
        ],
      ],
    ),
  );

  Widget _managementRow({
    required Widget title,
    Widget? subtitle,
    Widget? action,
    bool actionBesideSubtitle = false,
  }) => Padding(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
    child: LayoutBuilder(
      builder: (context, constraints) {
        final heading = DefaultTextStyle.merge(
          style: Theme.of(context).textTheme.bodyLarge,
          child: title,
        );
        final description = subtitle == null
            ? null
            : DefaultTextStyle.merge(
                style: Theme.of(context).textTheme.bodySmall,
                child: subtitle,
              );
        final information = Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            heading,
            if (description != null) ...[
              const SizedBox(height: 4),
              description,
            ],
          ],
        );
        if (action == null) return information;
        if (constraints.maxWidth < 360 ||
            MediaQuery.textScalerOf(context).scale(14) >= 20) {
          if (actionBesideSubtitle && description != null) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                heading,
                const SizedBox(height: 4),
                Row(
                  children: [
                    Expanded(child: description),
                    action,
                  ],
                ),
              ],
            );
          }
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              information,
              const SizedBox(height: 8),
              Align(alignment: Alignment.centerRight, child: action),
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Expanded(child: information),
            const SizedBox(width: 16),
            action,
          ],
        );
      },
    ),
  );

  Widget _roomDetails(RoomRoster roster) {
    final room = roster.room;
    final compact = MediaQuery.sizeOf(context).width < 700;
    final connection = _parallel.session(room.id);
    final snapshot = _roomSnapshot(room);
    final primaryConnected = connection == null && snapshot != null;
    final active =
        connection != null ||
        widget.settingsStore.settings.networkId == room.id;
    final palette = P2WlanColors.of(context);
    final expansionMotion = AppMotion.expansionStyleOf(context);
    final actions = Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        if (_canConnect) _connectionButton(room),
        if (room.isOwner)
          OutlinedButton.icon(
            onPressed: _serverActionsBusy || room.locked
                ? null
                : () => _issueInvite(room),
            icon: const Icon(Icons.person_add_alt_1_outlined, size: 18),
            label: Text(compact ? '邀请' : '生成邀请'),
          ),
        if (!room.isOwner)
          TextButton(
            onPressed: _serverActionsBusy ? null : () => _leave(room),
            child: const Text('退出房间'),
          ),
      ],
    );
    final identity = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            Text(
              room.name,
              style: Theme.of(context).textTheme.headlineSmall
                  ?.copyWith(fontSize: 22, fontWeight: FontWeight.w700),
            ),
            _connectionBadge(room),
          ],
        ),
        const SizedBox(height: 6),
        Wrap(
          spacing: 16,
          runSpacing: 4,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Flexible(
                  child: SelectableText(
                    '房间号 ${room.code}',
                    style: Theme.of(context).textTheme.bodySmall
                        ?.copyWith(fontFeatures: AppTokens.tabularFontFeatures),
                  ),
                ),
                IconButton(
                  tooltip: '复制房间号',
                  icon: const Icon(Icons.copy_rounded, size: 16),
                  onPressed: _busy
                      ? null
                      : () async {
                          await _copyText(room.code, success: '房间号已复制');
                        },
                ),
              ],
            ),
            if (snapshot != null)
              Text(
                '本机 IP：${snapshot.virtualIp}',
                style: Theme.of(context).textTheme.bodySmall
                    ?.copyWith(fontFeatures: AppTokens.tabularFontFeatures),
              ),
            if (!compact)
              Text(
                room.cidr,
                style: Theme.of(context).textTheme.bodySmall
                    ?.copyWith(fontFeatures: AppTokens.tabularFontFeatures),
              ),
          ],
        ),
      ],
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _surfaceCard(
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                LayoutBuilder(
                  builder: (context, constraints) {
                    if (constraints.maxWidth >= 900 &&
                        MediaQuery.textScalerOf(context).scale(14) < 20) {
                      return Row(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          Expanded(child: identity),
                          const SizedBox(width: 24),
                          actions,
                        ],
                      );
                    }
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [identity, const SizedBox(height: 12), actions],
                    );
                  },
                ),
                if (connection?.message case final message?) ...[
                  const SizedBox(height: 10),
                  Semantics(
                    liveRegion: true,
                    child: Text(
                      message,
                      style: Theme.of(context).textTheme.bodySmall
                          ?.copyWith(color: palette.warningText),
                    ),
                  ),
                ],
                if (connection == null && !primaryConnected) ...[
                  const SizedBox(height: 10),
                  Text(
                    active
                        ? (_parallel.supported ? '重新连接以启用多房间互联。' : '当前房间网络')
                        : '已加入，连接后即可访问房间内的设备。',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
                if (!_canConnect)
                  Padding(
                    padding: const EdgeInsets.only(top: 10),
                    child: Text(
                      '此平台仅支持房间管理，不能创建本地虚拟网卡。',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        _deviceList(roster),
        ExpansionTile(
          key: ValueKey('room-connection-options-${room.id}'),
          expansionAnimationStyle: expansionMotion,
          title: const Text('连接与自动连接'),
          children: [
            ListTile(
              title: const Text('房间网段'),
              subtitle: SelectableText(room.cidr),
            ),
            if (_roomSnapshot(room) case final snapshot?)
              ListTile(
                title: const Text('连接概况'),
                subtitle: Text(
                  _snapshotStale(snapshot)
                      ? '链路信息待更新'
                      : RoomConnectivitySummary.fromSnapshot(snapshot).details,
                ),
              ),
            ListTile(
              title: Text(
                _parallel.supported
                    ? '本机已连接 ${_parallel.activeConnections}/${_parallel.maxConnections} 个房间；各房间独立运行。'
                    : '此平台使用单活动网络，连接本房间将断开当前网络。',
              ),
            ),
            if (_parallel.supported && _canConnect) _autoConnectToggle(room),
          ],
        ),
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
          key: ValueKey('room-members-${room.id}'),
          expansionAnimationStyle: expansionMotion,
          title: Text(
            '${room.isOwner ? '成员管理' : '房间成员'} · ${roster.members.length}',
          ),
          children: [
            _managementList([
              for (final member in roster.members)
                _managementRow(
                  title: Text(_memberLabel(member['user_id'] as String? ?? '')),
                  subtitle: Text(member['role'] == 'owner' ? '房主' : '成员'),
                  actionBesideSubtitle: true,
                  action: room.isOwner && member['role'] != 'owner'
                      ? PopupMenuButton<bool>(
                          tooltip:
                              '管理成员 ${_memberLabel(member['user_id'] as String? ?? '')}',
                          enabled: !_serverActionsBusy,
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
            ]),
          ],
        ),
        if (room.isOwner)
          ExpansionTile(
            key: ValueKey('room-settings-${room.id}'),
            expansionAnimationStyle: expansionMotion,
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
                    onChanged: _serverActionsBusy
                        ? null
                        : (value) => _run((isCurrent) async {
                            await _api.request(
                              'PUT',
                              [room.id, 'device-policy'],
                              {'require_approval': value},
                            );
                          }),
                  ),
                SwitchListTile.adaptive(
                  title: const Text('锁定新成员加入'),
                  subtitle: const Text('锁定后密码和邀请都无法添加新成员'),
                  value: room.locked,
                  onChanged: _serverActionsBusy
                      ? null
                      : (value) => _run((isCurrent) async {
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
                      onPressed: _serverActionsBusy
                          ? null
                          : () => _edit(room, false),
                      child: const Text('重命名'),
                    ),
                    TextButton(
                      onPressed: _serverActionsBusy
                          ? null
                          : () => _edit(room, true),
                      child: const Text('更改密码'),
                    ),
                    TextButton.icon(
                      onPressed: _serverActionsBusy ? null : () => _leave(room),
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
            key: ValueKey('room-invites-${room.id}'),
            expansionAnimationStyle: expansionMotion,
            title: const Text('邀请管理'),
            children: [
              if (_invitesError != null)
                _managementRow(
                  title: const Text('邀请信息更新失败'),
                  subtitle: Text(_invitesError!),
                  action: TextButton(
                    onPressed: _serverActionsBusy || _refreshing
                        ? null
                        : () => _refresh(),
                    child: const Text('重试'),
                  ),
                ),
              if (_invites.isEmpty && _invitesError == null)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 12),
                  child: Text('尚未生成邀请；已生成链接的凭证不会再次返回。'),
                ),
              if (_invites.isNotEmpty)
                _managementList([
                  for (final invite in _invites)
                    _managementRow(
                      title: Text(
                        '已使用 ${invite['uses']} / ${invite['max_uses']} 次',
                      ),
                      subtitle: Text(
                        '有效期至 ${DateTime.fromMillisecondsSinceEpoch((invite['expires_at'] as num).toInt() * 1000).toLocal()}${invite['revoked'] == true ? ' · 已撤销' : ''}',
                      ),
                      action: IconButton(
                        tooltip: '撤销邀请',
                        icon: const Icon(Icons.link_off_rounded),
                        onPressed:
                            _serverActionsBusy || invite['revoked'] == true
                            ? null
                            : () async {
                                if (await _confirm(
                                      '撤销邀请',
                                      '链接将不能再用于加入，已加入成员不受影响。',
                                    ) &&
                                    mounted) {
                                  await _run((isCurrent) async {
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
                ]),
              if (roster.bannedUserIds.isNotEmpty) ...[
                const SizedBox(height: 16),
                Align(
                  alignment: Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                    child: Text(
                      '封禁账号',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                  ),
                ),
                _managementList([
                  for (final user in roster.bannedUserIds)
                    _managementRow(
                      title: const Text('已封禁账号'),
                      subtitle: SelectableText(user),
                      action: Tooltip(
                        message: '解除账号 $user 的封禁',
                        child: TextButton(
                          onPressed: _serverActionsBusy
                              ? null
                              : () async {
                                  if (await _confirm(
                                        '解除封禁',
                                        '解除账号 $user 的封禁后，该账号仍需使用有效密码或邀请重新加入。',
                                      ) &&
                                      mounted) {
                                    await _run((isCurrent) async {
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
                ]),
              ],
            ],
          ),
      ],
    );
  }

  Widget _rosterIssue(FriendRoom room) {
    final cached = _rosters.containsKey(room.id);
    final updated = _rosterUpdatedAt[room.id];
    final time = updated == null
        ? ''
        : '（${TimeOfDay.fromDateTime(updated).format(context)} 更新）';
    return _surfaceCard(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (!cached) ...[
              Text(room.name, style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 8),
              Text('房间号 ${room.code} · ${room.cidr}'),
              const SizedBox(height: 12),
            ],
            Semantics(
              liveRegion: true,
              child: Text(cached ? '房间信息更新失败，当前显示上次数据$time。' : '暂时无法加载房间详情。'),
            ),
            const SizedBox(height: 8),
            Text(
              _rosterErrors[room.id]!,
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const ValueKey('retry-room-roster'),
              onPressed: _serverActionsBusy || _refreshing
                  ? null
                  : () => _selectRoom(room.id),
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('重试加载房间'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _overviewHeader() => LayoutBuilder(
    builder: (context, constraints) {
      final owned = _rooms.where((room) => room.isOwner).firstOrNull;
      final createAction =
          (owned == null ? FilledButton.icon : OutlinedButton.icon)(
            onPressed: _serverActionsBusy || _loading || owned != null
                ? null
                : _create,
            icon: const Icon(Icons.add_rounded),
            label: const Text('创建房间'),
          );
      final joinAction =
          (owned == null ? OutlinedButton.icon : FilledButton.icon)(
            onPressed: _serverActionsBusy ? null : () => _join(),
            icon: const Icon(Icons.meeting_room_outlined),
            label: const Text('加入房间'),
          );
      final actions = Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          if (owned != null) joinAction,
          createAction,
          if (owned == null) joinAction,
        ],
      );
      final title = Text(
        '房间',
        style: Theme.of(context).textTheme.titleLarge
            ?.copyWith(fontSize: 24, fontWeight: FontWeight.w700),
      );
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (!widget.showHeader || !widget.embedded)
            actions
          else if (constraints.maxWidth >= 600 &&
              MediaQuery.textScalerOf(context).scale(14) < 20)
            Row(children: [title, const Spacer(), actions])
          else ...[
            title,
            const SizedBox(height: 8),
            actions,
          ],
          if (owned != null) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Text(
                  '每个账号可创建一个房间，你已创建“${owned.name}”。',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                TextButton(
                  onPressed: _busy ? null : () => _selectRoom(owned.id),
                  child: const Text('管理我的房间'),
                ),
              ],
            ),
          ],
        ],
      );
    },
  );

  Widget _authenticationIssue() => _surfaceCard(
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Semantics(
            liveRegion: true,
            child: Text(
              _authenticationError!.message,
              style: Theme.of(context).textTheme.titleSmall,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _rooms.isEmpty
                ? '自动刷新已暂停。重新登录后可继续使用房间。'
                : '自动刷新已暂停，当前显示上次加载的成员信息。本机连接仍可查看和断开。',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              if (widget.onReauthenticate != null)
                FilledButton.icon(
                  onPressed: _busy ? null : widget.onReauthenticate,
                  icon: const Icon(Icons.login_rounded),
                  label: const Text('重新登录'),
                ),
              if (_apiInstance != null)
                OutlinedButton.icon(
                  onPressed: _busy || _refreshing ? null : () => _refresh(),
                  icon: const Icon(Icons.refresh_rounded),
                  label: Text(_refreshing ? '验证中…' : '重试验证登录'),
                ),
            ],
          ),
          if (widget.onReauthenticate == null) const Text('请在设置中重新登录控制服务器。'),
        ],
      ),
    ),
  );

  bool _desktopLayout(BuildContext context) =>
      switch (Theme.of(context).platform) {
        TargetPlatform.macOS ||
        TargetPlatform.windows ||
        TargetPlatform.linux => true,
        _ => MediaQuery.sizeOf(context).width >= 900,
      };

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: widget.settingsStore,
    builder: (context, _) => Scaffold(
      appBar: widget.embedded
          ? null
          : AppBar(
              title: const Text('房间'),
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
            padding: EdgeInsets.fromLTRB(
              _desktopLayout(context) ? 28 : 20,
              _desktopLayout(context) ? 24 : 16,
              _desktopLayout(context) ? 28 : 20,
              24,
            ),
            children: [
              Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 1440),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      if (_selectedId == null) _overviewHeader(),
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
                                      _loading = false;
                                    });
                                    _generation++;
                                    widget.onRoomSelected?.call(null);
                                  },
                            icon: const Icon(Icons.arrow_back_rounded),
                            label: const Text('返回房间'),
                          ),
                        ),
                      if (_busy || _loading)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          child: LinearProgressIndicator(
                            semanticsLabel: _loading ? '正在加载房间' : '正在处理房间操作',
                          ),
                        ),
                      if (_authenticationError != null) ...[
                        const SizedBox(height: 12),
                        _authenticationIssue(),
                      ],
                      if (_operationError != null || _error != null)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          child: Semantics(
                            liveRegion: true,
                            child: Card(
                              elevation: 0,
                              margin: EdgeInsets.zero,
                              color: P2WlanColors.of(context).dangerSurface,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(
                                  AppTokens.radiusLg,
                                ),
                                side: BorderSide(
                                  color: P2WlanColors.of(context).dangerBorder,
                                ),
                              ),
                              child: Padding(
                                padding: const EdgeInsets.all(16),
                                child: LayoutBuilder(
                                  builder: (context, constraints) {
                                    final message = Row(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Icon(
                                          Icons.error_outline,
                                          color: P2WlanColors.of(context)
                                              .dangerText,
                                        ),
                                        const SizedBox(width: 12),
                                        Expanded(
                                          child: Text(
                                            _operationError ?? _error!,
                                          ),
                                        ),
                                      ],
                                    );
                                    final actions = Wrap(
                                      children: [
                                        if (_error != null)
                                          IconButton(
                                            tooltip: '重试加载房间列表',
                                            onPressed: _busy || _refreshing
                                                ? null
                                                : () => _refresh(),
                                            icon: const Icon(
                                              Icons.refresh_rounded,
                                            ),
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
                                    );
                                    if (constraints.maxWidth < 420 ||
                                        MediaQuery.textScalerOf(context)
                                                .scale(14) >=
                                            20) {
                                      return Column(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.stretch,
                                        children: [
                                          message,
                                          const SizedBox(height: 8),
                                          Align(
                                            alignment: Alignment.centerRight,
                                            child: actions,
                                          ),
                                        ],
                                      );
                                    }
                                    return Row(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Expanded(child: message),
                                        actions,
                                      ],
                                    );
                                  },
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
                      if (_selectedId != null)
                        for (final room in _rooms.where(
                          (room) => room.id == _selectedId,
                        ))
                          if (_rosterErrors.containsKey(room.id))
                            _rosterIssue(room),
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

/// Uses InkWell's focus owner, so nested actions retain their own activation.
class _RoomActionSurface extends StatelessWidget {
  const _RoomActionSurface({
    super.key,
    required this.child,
    required this.onTap,
    this.label,
    this.borderRadius,
  });

  final Widget child;
  final VoidCallback? onTap;
  final String? label;
  final BorderRadius? borderRadius;

  @override
  Widget build(BuildContext context) {
    final palette = P2WlanColors.of(context);
    final radius = borderRadius ?? BorderRadius.circular(AppTokens.radiusLg);
    final reducedMotion = MediaQuery.disableAnimationsOf(context);
    final duration = AppMotion.feedbackDurationOf(context);
    return Semantics(
      button: onTap != null,
      label: label,
      child: InkWell(
        onTap: onTap,
        borderRadius: radius,
        hoverColor: palette.hoverSurface,
        focusColor: palette.selectedSurface,
        hoverDuration: duration,
        splashFactory: reducedMotion ? NoSplash.splashFactory : null,
        child: Builder(
          builder: (context) => AnimatedContainer(
            duration: duration,
            curve: AppMotion.curve,
            foregroundDecoration: BoxDecoration(
              borderRadius: radius,
              border: Border.all(
                color: Focus.of(context).hasPrimaryFocus
                    ? Theme.of(context).colorScheme.primary
                    : Colors.transparent,
                width: 2,
              ),
            ),
            child: child,
          ),
        ),
      ),
    );
  }
}

class _RoomField {
  const _RoomField(
    this.label, {
    this.initial = '',
    this.hint,
    this.secret = false,
    this.number = false,
    this.maxLength = 128,
    this.validate,
  });
  final String label;
  final String initial;
  final String? hint;
  final bool secret;
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
                    maxLines: 1,
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
