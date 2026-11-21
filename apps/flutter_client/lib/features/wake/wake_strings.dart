import '../../core/api/wake_api.dart';

class WakeStrings {
  const WakeStrings(this.zh);

  final bool zh;

  String get title => zh ? '远程开机' : 'Remote wake';
  String get close => zh ? '关闭' : 'Close';
  String get cancel => zh ? '取消' : 'Cancel';
  String get refresh => zh ? '刷新' : 'Refresh';
  String get confirm => zh ? '发送唤醒请求' : 'Send wake request';
  String get chooseAndWake => zh ? '更换代理并唤醒' : 'Choose another agent and wake';
  String get chooseAgent => zh ? '选择局域网代理' : 'Choose a LAN agent';
  String get sameLan => zh
      ? '代理必须与目标设备位于同一局域网广播域。'
      : 'The agent must share the target’s LAN broadcast domain.';
  String assignedAgent(String name) =>
      zh ? '本次代理：$name' : 'Assigned agent: $name';
  String get existingJob => zh
      ? '近期已有唤醒任务，正在跟踪原任务。'
      : 'A recent wake request already exists. Showing its progress.';
  String get loading => zh ? '正在检查设备状态…' : 'Checking device status…';
  String get submitting => zh ? '正在提交唤醒请求…' : 'Submitting wake request…';
  String get waitingOnline => zh
      ? '已发唤醒包，等待设备上线…'
      : 'Wake packet sent. Waiting for the device to come online…';
  String get timedOut => zh
      ? '120 秒内未确认上线。请检查目标的有线连接、唤醒设置和代理所在局域网。'
      : 'The device did not report online within 120 seconds. Check its wired connection, Wake-on-LAN settings, and the agent’s LAN.';
  String get manualTimedOut => zh
      ? '120 秒内未收到代理发送结果，请检查代理和控制服务器连接。'
      : 'The agent did not report a send result within 120 seconds. Check the agent’s connection to Control.';
  String get manualSent => zh
      ? '唤醒包已发送。此目标没有 P2WLAN 在线状态，请确认设备是否开机。'
      : 'Wake packet sent. Check the device directly to confirm it powered on.';
  String get manualTargets => zh ? '手填唤醒目标' : 'Manual wake targets';
  String get devices => zh ? '已登记设备' : 'Registered devices';
  String get noDevices =>
      zh ? '此网络中没有已登记设备。' : 'No devices are registered on this network.';
  String get noTargets => zh ? '还没有手填唤醒目标。' : 'No manual wake targets yet.';
  String get add => zh ? '添加唤醒目标' : 'Add wake target';
  String get edit => zh ? '编辑唤醒目标' : 'Edit wake target';
  String get remove => zh ? '删除唤醒目标' : 'Remove wake target';
  String get save => zh ? '保存' : 'Save';
  String get name => zh ? '名称' : 'Name';
  String get mac => zh ? '有线网卡的 MAC 地址' : 'Wired adapter MAC address';
  String get keepMac =>
      zh ? '留空以保留当前 MAC 地址' : 'Leave blank to keep the current MAC address';
  String get invalidName =>
      zh ? '请输入 1–64 个字符的名称。' : 'Enter a name of 1–64 characters.';
  String get invalidMac =>
      zh ? '请输入有效的单播 MAC 地址。' : 'Enter a valid unicast MAC address.';
  String get enableTarget => zh ? '启用此唤醒目标' : 'Enable this wake target';
  String get disabled => zh ? '该目标已禁用。' : 'This target is disabled.';

  String removeNamed(String name) => zh ? '删除“$name”？' : 'Remove “$name”?';

  String availability(WakeAvailability value) => switch (value) {
    WakeAvailability.online => zh ? '设备已上线。' : 'The device is online.',
    WakeAvailability.ready => zh ? '可远程唤醒' : 'Ready to wake',
    WakeAvailability.missingMac => zh ? '设备离线，尚未登记有线网卡。请先在目标机上启用远程开机。' : 'The device is offline and has no wired adapter registered. Enable remote wake on the target first.',
    WakeAvailability.missingAgent =>
      zh
          ? '设备离线，当前没有可用的局域网代理。'
          : 'The device is offline and no LAN agent is available.',
  };

  String job(WakeJob value, {required bool manual}) => switch (value.state) {
    WakeJobState.queued => zh ? '等待代理领取…' : 'Waiting for a LAN agent…',
    WakeJobState.claimed =>
      zh ? '代理正在发送唤醒包…' : 'The agent is sending the wake packet…',
    WakeJobState.sent => manual ? manualSent : waitingOnline,
    WakeJobState.expired => error('expired'),
    WakeJobState.failed => error(value.reason),
  };

  String error(String code) => switch (code) {
    'auth_expired' => zh ? '请重新登录后再操作。' : 'Sign in again to continue.',
    'https_required' =>
      zh
          ? '远程开机要求控制服务器使用 HTTPS。'
          : 'Remote wake requires an HTTPS Control server.',
    'unsupported' =>
      zh
          ? '此控制服务器暂不支持远程开机。'
          : 'This Control server does not support remote wake.',
    'wake_not_found' || 'target_blocked' =>
      zh
          ? '该设备已不可用，或当前账号无权操作。'
          : 'This device is unavailable or your account cannot manage it.',
    'wake_agent_unavailable' ||
    'agent_offline' ||
    'no_agent' => availability(WakeAvailability.missingAgent),
    'wake_agent_ambiguous' => chooseAgent,
    'already_online' => availability(WakeAvailability.online),
    'target_no_mac' => availability(WakeAvailability.missingMac),
    'wake_rate_limited' || 'rate_limited' || 'wake_queue_full' =>
      zh
          ? '唤醒请求达到限额，请稍后再试。'
          : 'The wake request limit was reached. Try again shortly.',
    'expired' => zh ? '唤醒任务已过期。请确认代理在线后重试。' : 'The wake request expired. Check that the agent is online and try again.',
    'send_failed' ||
    'no_lan_interface' ||
    'unsupported_platform' => zh ? '代理未能发送唤醒包。请检查代理的局域网接口。' : 'The agent could not send the wake packet. Check the agent’s LAN interface.',
    'unreachable' =>
      zh
          ? '无法访问控制服务器，请检查网络后刷新。'
          : 'Could not reach Control. Check your connection and refresh.',
    _ => zh ? '远程开机操作失败，请刷新后重试。' : 'Remote wake failed. Refresh and try again.',
  };
}
