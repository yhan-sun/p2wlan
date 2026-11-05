import '../../app/app_strings.dart';
import '../../core/rooms/room_api.dart';
import '../../core/rooms/room_connectivity.dart';

/// Copy for room UI. Domain models and runtime ownership remain language-neutral.
class RoomStrings {
  const RoomStrings(this.isZh);
  factory RoomStrings.fromCode(String code) =>
      RoomStrings(AppStrings.fromCode(code).isZh);
  final bool isZh;

  String text(String source, [List<Object?> values = const []]) {
    final template = isZh ? source : (_english[source] ?? source);
    return template.replaceAllMapped(RegExp(r'\{(\d+)\}'), (match) {
      final index = int.parse(match[1]!);
      return index < values.length ? '${values[index] ?? ''}' : match[0]!;
    });
  }

  /// Known runtime messages are presentation only; they never drive behavior.
  String runtimeText(String message) {
    if (isZh) return message;
    final translated = _english[message];
    if (translated != null) return translated;
    final limit = RegExp(r'^已达到并行房间上限 (\d+)$').firstMatch(message);
    if (limit != null) return text('已达到并行房间上限 {0}', [limit[1]]);
    if (message.endsWith('；无法保存本地自动连接设置')) {
      final reason = message.substring(
        0,
        message.length - '；无法保存本地自动连接设置'.length,
      );
      return '${runtimeText(reason)}; could not save the local startup preference';
    }
    if (message.endsWith('；停止失败，运行时仍被保留，请重试断开')) {
      final reason = message.substring(
        0,
        message.length - '；停止失败，运行时仍被保留，请重试断开'.length,
      );
      return '${runtimeText(reason)}; ${text('停止失败，运行时仍被保留，请重试断开')}';
    }
    return RegExp(r'[\u4e00-\u9fff]').hasMatch(message)
        ? 'Room status needs attention. Refresh to check the current state.'
        : message;
  }

  String error(Object error) {
    if (error is! RoomException) return text('操作未完成，请检查连接后重试');
    // Use the stable server reason before legacy localized messages.
    final source = switch (error.code) {
      'auth_expired' => '登录状态已失效，请重新登录',
      'room_device_blocked' => '此设备已被禁止连接该房间，请解除限制后重试',
      'room_device_pending' => '此设备正在等待房主审批，请批准后在本机重新连接',
      'room_device_paused' => '此设备已被远程断开，请在本机手动连接',
      'room_exists' => '每个账号最多创建一个房间',
      'room_join' => '无法加入：房间号、密码或邀请无效，房间已锁定，或账号已被封禁',
      'room_access' => '无权操作该房间，或你已不再是成员',
      'room_invalid' => '输入无效，请检查名称、密码、IP 或邀请设置',
      'room_ip_conflict' => '该 IP 无法分配，请检查网段或选择未占用的地址',
      'room_device_state_conflict' => '此设备状态已变化，申请可能已被处理，请查看最新状态',
      'room_invite_limit' => '有效邀请已达上限，请先撤销不再使用的邀请',
      'room_conflict' => '操作与当前房间状态冲突，请刷新后重试',
      'room_exhausted' => '服务器没有可用子网或房间 IP，请联系管理员',
      'room_rate_limit' => '加入尝试过于频繁，请一分钟后重试',
      _ => error.message,
    };
    return runtimeText(source);
  }

  String connectivityLabel(RoomConnectivitySummary summary) =>
      runtimeText(summary.label);
  String connectivityDetails(RoomConnectivitySummary summary) =>
      text('在线 {0} · 链路已建立 {1} · 直连 {2} / 中继 {3} / 待建链 {4}', [
        summary.online,
        summary.established,
        summary.direct,
        summary.relay,
        summary.pending,
      ]);

  static const _english = <String, String>{
    '该房间已不可用，请刷新房间列表。':
        'This room is no longer available. Refresh the room list.',
    '设备信息存在冲突，请刷新后重试。': 'Device identities conflict. Refresh before retrying.',
    '另一项房间操作仍在进行，请稍后重试。':
        'Another room operation is still running. Try again shortly.',
    " · 已撤销": " · Revoked",
    "8 位房间号，或 p2wlan://join…": "8-digit room code, or p2wlan://join…",
    "8–72 字节，不会写入分享链接": "8–72 UTF-8 bytes; excluded from share links",
    "IP 不得与其他设备重复。保存后旧连接和凭证将被撤销，该设备需要重新连接房间。": "Choose an unused IP. Saving revokes the old connection and credentials; this device must reconnect to the room.",
    "IP 已分配，请让该设备重新连接房间": "IP assigned. Reconnect that device to the room.",
    "IP 已复制": "IP copied",
    "{0} · {1} · {2} 台设备": "{0} · {1} · {2} devices",
    "{0} · {1} · {2}\n房间数据：{3}\n链路与收包状态不代表系统 ping 一定可达。": "{0} · {1} · {2}\nRoom data: {3}\nLink and receive status do not guarantee system ping connectivity.",
    "{0} 台设备": "{0} devices",
    "{0}（我）": "{0} (me)",
    "{0}：已完成": "{0}: done",
    "上次数据": "Last known data",
    "个人网络": "Personal network",
    "中继": "Relay",
    "仅对本机生效；手动或远程断开后，需重新手动连接": "Applies to this device. After a manual or remote disconnect, connect again manually.",
    "使用邀请加入，无需密码。确认后加入当前服务器上的房间。": "Join by invitation without a password. Confirm to join the room on the current server.",
    "关闭": "Close",
    "关闭提示": "Dismiss notice",
    "分享房间": "Share room",
    "分配 IP": "Assign IP",
    "分配设备 IP": "Assign device IP",
    "创建房间": "Create room",
    "删除房间设备": "Remove room device",
    "删除设备": "Remove device",
    "刷新房间": "Refresh rooms",
    "加入房间": "Join room",
    "加入未完成，请检查连接后重试": "Could not join. Check your connection and try again.",
    "取消": "Cancel",
    "只断开这台设备，并停止其自动恢复连接。账号仍是成员，其他设备保持连接。之后可以在该设备上手动连接。": "Disconnect only this device and stop its automatic recovery. The account remains a member and other devices stay connected. Reconnect manually on that device.",
    "启动时自动连接此房间": "Connect to this room at startup",
    "和好友连接到同一房间": "Connect with friends in one room",
    "在线": "Online",
    "在线 / 总人数": "Online / total members",
    "地址待同步": "Address sync pending",
    "地址未变化，无需重新连接": "Address unchanged; no reconnection needed",
    "复制 IP": "Copy IP",
    "复制失败，请手动选择并复制": "Could not copy. Select and copy the text manually.",
    "复制房间号": "Copy room code",
    "复制邀请链接": "Copy invitation link",
    "密码需为 8–72 字节": "Use 8–72 UTF-8 bytes for the password",
    "封禁成员": "Ban member",
    "封禁账号": "Banned accounts",
    "将启动个人网络，已连接的并行房间保持运行。":
        "Start the personal network. Connected parallel rooms keep running.",
    "将断开该设备。其账号仍是成员，可以重新连接；要阻止重新加入，请封禁账号。": "Disconnect this device. Its account remains a member and can reconnect. Ban the account to prevent rejoining.",
    "将移除所有成员并撤销房间凭证。此操作不可恢复，重新创建会获得新房间号。": "Remove all members and revoke room credentials. This cannot be undone. Creating another room gives it a new code.",
    "尚未生成邀请；已生成链接的凭证不会再次返回。": "No invitations yet. Previously generated invitation credentials cannot be retrieved again.",
    "已使用 {0} / {1} 次": "Used {0} / {1} times",
    "已加入，连接后即可访问房间内的设备。":
        "You have joined. Connect this device to access devices in the room.",
    "已复制": "Copied",
    "已封禁账号": "Banned account",
    "已断开": "Disconnected",
    "已断开本机，其他设备和房间保持运行":
        "This device disconnected; other devices and rooms keep running",
    "已有设备保持当前权限；新设备批准后仍需在本机连接。房主身份属于账号，不绑定创建房间的设备。": "Existing devices keep their permissions. Newly approved devices must connect locally. Ownership belongs to the account, not the device that created the room.",
    "已禁止": "Blocked",
    "已连接房间": "Connected to room",
    "已退出房间": "Left room",
    "已锁定新成员加入": "New members cannot join",
    "延迟": "Latency",
    "建立连接中": "Establishing connection",
    "当前上传速率": "Current upload rate",
    "当前下载速率": "Current download rate",
    "当前合计速率": "Current total rate",
    "当前房间网络": "Current room network",
    "当前控制服务器尚未提供用户名，更新服务器后可同步显示。": "This control server does not provide usernames yet. Update it to show them.",
    "当前没有可用的实时链路信息。设备连接后可查看链路与实测延迟。": "Live link information is unavailable. Connect the device to see its link and measured latency.",
    "当前记录": "Current record",
    "待分配": "Not assigned",
    "待审批": "Pending approval",
    "待更新": "Update pending",
    "成员": "Member",
    "成员信息同步中": "Syncing member information",
    "成员信息待更新": "Member information needs updating",
    "成员信息暂不可用，点击房间可重试":
        "Member information is unavailable. Open this room to retry.",
    "成员信息更新失败，显示上次结果": "Could not update members; showing the last result",
    "成员已封禁": "Member banned",
    "成员已移除": "Member removed",
    "成员管理": "Manage members",
    "我": "Me",
    "我是房主": "You own this room",
    "房主": "Owner",
    "房主 · {0}": "Owner · {0}",
    "房主延迟": "Owner latency",
    "房主离线": "Owner offline",
    "房间": "Rooms",
    "房间信息更新失败，当前显示上次数据{0}。":
        "Could not update room information. Showing the last data{0}.",
    "房间号": "Room code",
    "房间号 {0}": "Room code {0}",
    "房间号 {0} · {1}": "Room code {0} · {1}",
    "房间号已复制": "Room code copied",
    "房间号或邀请链接": "Room code or invitation link",
    "房间名称": "Room name",
    "房间密码": "Room password",
    "房间已创建": "Room created",
    "房间已解散": "Room dissolved",
    "房间成员": "Room members",
    "房间或登录状态已变化，请关闭详情后重试。":
        "The room or account session has changed. Close details and try again.",
    "房间数据": "Room data",
    "房间网段": "Room subnet",
    "房间网段：{0}": "Room subnet: {0}",
    "房间设备已删除": "Room device removed",
    "房间设置": "Room settings",
    "房间设置已保存": "Room settings saved",
    "批准此设备": "Approve device",
    "撤销邀请": "Revoke invitation",
    "操作未完成，请检查连接后重试":
        "The operation did not complete. Check your connection and try again.",
    "数据": "Data",
    "断开中": "Disconnecting",
    "断开本机": "Disconnect this device",
    "断开此设备": "Disconnect device",
    "新设备需要房主审批": "Require owner approval for new devices",
    "无需测量": "Not applicable",
    "旧的单房间运行时未能停止": "Could not stop the previous single-room runtime",
    "旧网络未能停止，未切换网络": "Could not stop the previous network. Network unchanged.",
    "显示房间密码": "Show room password",
    "暂时无法加载房间详情。": "Room details are temporarily unavailable.",
    "更改密码": "Change password",
    "更改密码会同时撤销所有现有邀请链接。已加入成员不受影响；要阻止其再次加入，请封禁账号。": "Changing the password revokes all current invitation links. Existing members are unaffected. Ban an account to prevent it rejoining.",
    "更改房间密码": "Change room password",
    "最多加入账号数": "Maximum accounts",
    "有效小时数": "Valid for (hours)",
    "有效期至 {0}{1}": "Expires {0}{1}",
    "服务运行时长": "Service uptime",
    "未测得": "Not measured",
    "未设置用户名": "Username not set",
    "未连接": "Not connected",
    "本地并行房间未能停止，尚未退出":
        "Could not stop the local parallel room. You have not left.",
    "本地房间网络无法停止，尚未退出房间":
        "Could not stop the local room network. You have not left the room.",
    "本机": "This device",
    "本机 IP：{0}": "This device IP: {0}",
    "本机与当前设备记录的业务流量；服务重启或记录移除后重新累计。": "Business traffic recorded for this device and its current peers. Totals reset after a service restart or record removal.",
    "本机到房主在线设备的实测延迟；多台设备取最低值。": "Measured latency from this device to the owner's online devices; the lowest value is shown.",
    "本机启动": "Starting locally",
    "本机在此房间的流量": "This device's room traffic",
    "本机在此房间的连接信息": "This device's connection in this room",
    "本机已连接 {0}/{1} 个房间；各房间独立运行。": "This device is connected to {0}/{1} rooms. Each room runs independently.",
    "本机未连接": "This device is disconnected",
    "本机未连接此房间或运行信息不可用；远程设备名册不提供设备间流量。": "This device is disconnected from the room or runtime data is unavailable. The remote roster does not report traffic between devices.",
    "查看房间 {0}": "View room {0}",
    "查看设备 {0}": "View device {0}",
    "正在加入…": "Joining…",
    "正在加入房间": "Joining room",
    "正在加载房间": "Loading rooms",
    "正在处理房间操作": "Processing room operation",
    "正在保存…": "Saving…",
    "此平台仅支持房间管理，不能创建本地虚拟网卡。": "This platform supports room management only and cannot create a local virtual adapter.",
    "此平台仍使用单活动网络，将断开当前网络后连接{0}。": "This platform allows one active network. Disconnect the current network and connect to {0}.",
    "此平台使用单活动网络，连接本房间将断开当前网络。": "This platform allows one active network. Connecting to this room disconnects the current network.",
    "此账号的所有设备都会退出该房间。只想让当前设备下线，请使用“断开本机”。个人网络和其他房间不受影响。": "All devices on this account will leave the room. To disconnect only this device, choose “Disconnect this device”. The personal network and other rooms are unaffected.",
    "此链接仅在本次生成后显示。只发送给可信好友；好友可点击链接，或在 P2WLAN 中粘贴加入。": "This link is shown only now. Share it only with trusted friends. They can open it or paste it into P2WLAN to join.",
    "每个账号可以创建一个房间。服务器会分配独立的 10.21.x.0/24 网段，不改变你的个人网络。": "Each account can create one room. The server assigns an independent 10.21.x.0/24 subnet without changing your personal network.",
    "每个账号可创建一个房间，你已创建“{0}”。":
        "Each account can create one room. You already own “{0}”.",
    "版本：{0}": "Version: {0}",
    "状态": "Status",
    "状态待更新": "Status needs updating",
    "生成邀请": "Create invitation",
    "生成邀请链接": "Create invitation link",
    "用户名暂不可用": "Username unavailable",
    "登录账号或服务器已变化，请重新登录。": "The account or server has changed. Sign in again.",
    "直连": "Direct",
    "确认": "Confirm",
    "禁止此设备连接此房间": "Block this device from this room",
    "离线": "Offline",
    "移除成员": "Remove member",
    "端到端实测延迟": "Measured end-to-end latency",
    "端到端延迟": "End-to-end latency",
    "等待发现": "Waiting for discovery",
    "管理成员 {0}": "Manage member {0}",
    "管理我的房间": "Manage my room",
    "管理设备": "Manage device",
    "系统：{0}": "Platform: {0}",
    "网络连接已启动": "Network connection started",
    "自动刷新已暂停。重新登录后可继续使用房间。":
        "Automatic refresh is paused. Sign in again to use rooms.",
    "自动刷新已暂停，当前显示上次加载的成员信息。本机连接仍可查看和断开。": "Automatic refresh is paused. Showing the last loaded members. You can still view and disconnect local connections.",
    "虚拟 IP": "Virtual IP",
    "解散房间": "Dissolve room",
    "解除封禁": "Unban",
    "解除设备限制": "Unblock device",
    "解除账号 {0} 的封禁": "Unban account {0}",
    "解除账号 {0} 的封禁后，该账号仍需使用有效密码或邀请重新加入。": "After unbanning {0}, the account must rejoin with a valid password or invitation.",
    "设备": "Devices",
    "设备与连接 · {0}": "Devices and connections · {0}",
    "设备获得连接资格，但不会自动上线。请在该设备上点击“连接本机”。": "The device will be allowed to connect but will not go online automatically. Choose “Connect this device” on that device.",
    "该账号的所有房间设备将断开，但持有有效密码或邀请时仍可重新加入。": "All room devices on this account will disconnect. The account can rejoin with a valid password or invitation.",
    "该账号的所有房间设备将断开，解除封禁前无法再次加入。": "All room devices on this account will disconnect. The account cannot rejoin until unbanned.",
    "请先登录当前控制服务器后使用房间": "Sign in to the current control server to use rooms",
    "请先登录控制服务器后使用房间": "Sign in to the control server to use rooms",
    "请向房主索取房间密码": "Ask the owner for the room password",
    "请在设置中重新登录控制服务器。": "Sign in to the control server again in Settings.",
    "请输入 1–64 个字符的名称": "Enter a name with 1–64 characters",
    "请输入 8 位房间号或完整的邀请链接":
        "Enter an 8-digit room code or a complete invitation link",
    "请输入 {0} 中的可用主机地址": "Enter an available host address in {0}",
    "请输入 {0}–{1} 的整数": "Enter a whole number from {0} to {1}",
    "账号已加入房间，点击“连接本机”开始互联":
        "Account joined. Choose “Connect this device” to start connecting.",
    "输入好友发来的房间号或邀请链接。也可以创建房间，邀请其他设备加入。": "Enter a room code or invitation link from a friend, or create a room and invite other devices.",
    "输入房间号与密码，或粘贴好友发来的邀请链接。": "Enter the room code and password, or paste an invitation link from a friend.",
    "输入房间号或邀请链接": "Enter room code or invitation link",
    "返回房间": "Back to rooms",
    "还没有设备连接。连接房间后，设备 IP 和连接质量会显示在这里。": "No devices connected yet. Device IPs and connection quality appear after connecting to the room.",
    "这台设备将断开，解除限制前无法连接此房间。同账号其他设备不受影响。": "Disconnect this device and prevent it connecting to this room until unblocked. Other devices on the account are unaffected.",
    "进入房间后查看": "Open room to view",
    "连接": "Connection",
    "连接{0}": "Connect to {0}",
    "连接不可用": "Connection unavailable",
    "连接与自动连接": "Connection and startup",
    "连接中": "Connecting",
    "连接后测量": "Measure after connecting",
    "连接本机": "Connect this device",
    "连接概况": "Connection summary",
    "退出房间": "Leave room",
    "邀请": "Invite",
    "邀请信息更新失败": "Could not update invitations",
    "邀请管理": "Manage invitations",
    "邀请链接格式无效": "Invalid invitation link",
    "重命名": "Rename",
    "重命名房间": "Rename room",
    "重新登录": "Sign in again",
    "重新连接以启用多房间互联。": "Reconnect to enable multiple rooms.",
    "重新连接本机": "Reconnect this device",
    "重试": "Retry",
    "重试加载房间": "Retry loading room",
    "重试加载房间列表": "Retry loading rooms",
    "重试验证登录": "Retry sign-in verification",
    "链接将不能再用于加入，已加入成员不受影响。": "The link will no longer allow joining. Existing members are unaffected.",
    "链接持有者可免密码加入。可以随时撤销；同一账号重复加入不重复消耗次数。": "Anyone with this link can join without a password. Revoke it at any time. An account rejoining does not use another invitation slot.",
    "链路": "Link",
    "链路 / 数据": "Link / data",
    "链路信息待更新": "Link information needs updating",
    "锁定后密码和邀请都无法添加新成员":
        "Passwords and invitations cannot add new members while locked",
    "锁定新成员加入": "Lock new member access",
    "隐藏房间密码": "Hide room password",
    "需处理": "Needs attention",
    "验证中…": "Verifying…",
    "（{0} 更新）": " (updated {0})",
    "（本机）": " (this device)",
    "该设备已不在此房间，请查看最新设备列表。":
        "This device is no longer in the room. Check the latest device list.",
    "上一个登录会话仍有未停止的房间，请先全部断开": "Rooms from the previous account are still running. Disconnect them first.",
    "中继已建立": "Relay established",
    "停止失败，运行时仍被保留，请重试断开":
        "Could not stop the runtime. It is retained; retry disconnecting.",
    "关闭房间失败，尚未确认资源释放":
        "Could not close the room. Resource release is not confirmed.",
    "加入尝试过于频繁，请一分钟后重试": "Too many join attempts. Try again in one minute.",
    "在线 {0} · 链路已建立 {1} · 直连 {2} / 中继 {3} / 待建链 {4}":
        "Online {0} · Established {1} · Direct {2} / Relay {3} / Pending {4}",
    "地址映射异常": "Address mapping error",
    "完成": "Done",
    "尚未验证收包": "Packet reception not verified",
    "已达到并行房间上限 {0}": "Maximum parallel rooms reached: {0}",
    "建立加密会话": "Establishing encrypted session",
    "当前平台尚未接入多房间并行运行时":
        "Parallel room runtimes are unavailable on this platform",
    "当前服务器不支持好友房间，请升级服务器":
        "This server does not support rooms. Update the server.",
    "当前服务器不支持此版本的好友房间":
        "This server does not support this room protocol version",
    "成员授权待同步": "Member authorization sync pending",
    "房间启动失败": "Room failed to start",
    "房间启动失败，需要清理本地运行时": "Room failed to start. Clean up the local runtime.",
    "房间已有运行时，请先断开后重连": "A runtime already exists for this room. Disconnect it before reconnecting.",
    "房间授权已过期": "Room authorization expired",
    "房间授权待同步": "Room authorization sync pending",
    "房间授权有效": "Room authorization valid",
    "房间操作失败，请刷新后确认状态":
        "Room operation failed. Refresh to confirm the current state.",
    "房间操作失败，请检查本地服务和控制服务器":
        "Room operation failed. Check the local service and control server.",
    "房间数据包被拒绝": "Room packet rejected",
    "房间服务响应超过大小限制": "Room service response exceeds the size limit",
    "房间服务请求超时，请刷新后确认操作结果": "Room request timed out. Refresh to confirm the result before retrying.",
    "房间管理器已经关闭": "The room manager is closed",
    "房间网段与已连接房间重叠": "The room subnet overlaps a connected room",
    "房间诊断端口与主网络配置冲突":
        "The room diagnostics port conflicts with the primary network",
    "房间运行时已停止；保留本次实例日志供支持分析": "Room runtime stopped. Logs for this instance are retained for support.",
    "房间运行时资源标识冲突，未修改其他房间": "Room runtime resource identity conflict. Other rooms were not changed.",
    "房间运行时身份不匹配": "Room runtime identity mismatch",
    "房间进程已启动，但地址或路由尚未就绪；可重试状态检查或断开": "The room process started, but its address or routes are not ready. Refresh status or disconnect.",
    "所有并行房间已停止": "All parallel rooms stopped",
    "控制服务器地址无效": "Invalid control server address",
    "操作与当前房间状态冲突，请刷新后重试": "The room state conflicts with this operation. Refresh before retrying.",
    "数据状态未验证": "Data status not verified",
    "无权操作该房间，或你已不再是成员":
        "You cannot manage this room, or you are no longer a member",
    "无法加入：房间号、密码或邀请无效，房间已锁定，或账号已被封禁": "Could not join. Check the room code, password and invitation. The room may be locked or the account banned.",
    "无法恢复房间运行时，请检查登录和控制服务器": "Could not recover the room runtime. Check your sign-in and control server.",
    "无法确认房间运行时已停止": "Could not confirm that the room runtime stopped",
    "无法确认房间进程状态，请重试断开":
        "Could not confirm the room process state. Retry disconnecting.",
    "无法访问房间服务，请检查网络和服务器版本":
        "Cannot reach the room service. Check the network and server version.",
    "有效邀请已达上限，请先撤销不再使用的邀请":
        "Invitation limit reached. Revoke invitations you no longer use.",
    "服务器响应格式无效": "Invalid server response",
    "服务器没有可用子网或房间 IP，请联系管理员":
        "No room subnet or IP is available. Contact the administrator.",
    "服务器返回了无效的房间信息，请升级服务器":
        "The server returned invalid room information. Update the server.",
    "未发现房间运行时；保留本次实例日志供支持分析": "Room runtime not found. Logs for this instance are retained for support.",
    "本机地址待同步": "Local address sync pending",
    "本机已断开，但无法保存停止自动连接设置，请检查本地目录权限": "This device disconnected, but the startup preference could not be saved. Check local directory permissions.",
    "此房间仍被主网络使用，请先切回个人网络": "The primary network still uses this room. Switch back to the personal network first.",
    "此设备已被禁止连接该房间，请解除限制后重试":
        "This device is blocked from this room. Unblock it before retrying.",
    "此设备已被远程断开，请在本机手动连接": "This device was disconnected remotely. Connect it manually on this device.",
    "此设备正在等待房主审批，请批准后在本机重新连接": "This device is waiting for owner approval. Once approved, reconnect it locally.",
    "此设备状态已变化，申请可能已被处理，请查看最新状态": "The device state changed. The request may already be handled. Check the latest state.",
    "每个账号最多创建一个房间": "Each account can create only one room",
    "源地址被拒绝": "Source address rejected",
    "登录状态已变化，已取消连接": "The account session changed. Connection cancelled.",
    "登录状态已变化，连接已取消": "The account session changed. Connection cancelled.",
    "登录状态已失效，请重新登录": "Your session expired. Sign in again.",
    "直连与中继": "Direct and relay",
    "直连已建立": "Direct established",
    "直连探测": "Probing direct path",
    "等待好友": "Waiting for friends",
    "等待房间授权": "Waiting for room authorization",
    "房间数据状态未知": "Room data status unknown",
    "网络正在关闭，未启动房间": "Network shutdown is in progress. Room not started.",
    "访问规则已阻止": "Blocked by access rules",
    "该 IP 无法分配，请检查网段或选择未占用的地址":
        "Cannot assign this IP. Check the subnet or choose an unused address.",
    "请先登录": "Sign in first",
    "请输入完整的 P2WLAN 房间邀请链接": "Enter the complete P2WLAN room invitation link",
    "输入无效，请检查名称、密码、IP 或邀请设置":
        "Invalid input. Check the name, password, IP or invitation settings.",
    "运行时或路由不可用；未显示过期的在线状态":
        "Runtime or routes unavailable. Stale online status is hidden.",
    "近期已收房间数据": "Room data received recently",
    "邀请来自其他控制服务器。请先在设置中确认并登录该服务器，当前登录凭证不会被发送过去。": "This invitation belongs to another control server. Verify it and sign in through Settings. Your current credentials will not be sent to that server.",
    "邀请链接中的房间号或凭证无效": "The invitation room code or credential is invalid",
    "邀请链接过长": "Invitation link is too long",
    "部分房间未能停止，请重试；尚未清除运行时记录":
        "Some rooms did not stop. Retry; their runtime records are retained.",
    "部分链路已建立": "Some links established",
  };
}
