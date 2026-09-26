type Locale = 'zh-CN' | 'en-US'

// Codes follow validTransitionReasons in database/path_telemetry.go. Keep the
// machine code in the UI tooltip; the visible label follows the chosen locale.
export const transitionReasonLabels: Record<string, Record<Locale, string>> = {
  initial: { 'zh-CN': '初始观测', 'en-US': 'Initial observation' },
  peer_online: { 'zh-CN': '对端上线', 'en-US': 'Peer online' },
  direct_first_started: { 'zh-CN': '开始优先直连', 'en-US': 'Direct-first attempt started' },
  direct_first_satisfied: { 'zh-CN': '优先直连已建立', 'en-US': 'Direct-first attempt succeeded' },
  direct_first_deadline: { 'zh-CN': '优先直连超时', 'en-US': 'Direct-first deadline reached' },
  peer_left: { 'zh-CN': '对端离开', 'en-US': 'Peer left' },
  identity_reset: { 'zh-CN': '连接身份已重置', 'en-US': 'Connection identity reset' },
  network_generation_advanced: { 'zh-CN': '网络代次已更新', 'en-US': 'Network generation advanced' },
  remote_candidate_epoch_advanced: { 'zh-CN': '对端候选地址已更新', 'en-US': 'Remote candidate epoch advanced' },
  relay_transport_ready: { 'zh-CN': '中继传输已就绪', 'en-US': 'Relay transport ready' },
  relay_peer_confirmed: { 'zh-CN': '中继对端已确认', 'en-US': 'Relay peer confirmed' },
  relay_business_usable: { 'zh-CN': '中继业务路径可用', 'en-US': 'Relay business path usable' },
  relay_health_observed: { 'zh-CN': '已观测中继健康状态', 'en-US': 'Relay health observed' },
  relay_transport_lost: { 'zh-CN': '中继传输已断开', 'en-US': 'Relay transport lost' },
  relay_path_failed: { 'zh-CN': '中继路径失败', 'en-US': 'Relay path failed' },
  direct_probe_started: { 'zh-CN': '已开始直连探测', 'en-US': 'Direct probe started' },
  direct_validation_started: { 'zh-CN': '已开始直连验证', 'en-US': 'Direct validation started' },
  direct_committed: { 'zh-CN': '直连已确认', 'en-US': 'Direct committed' },
  direct_probe_failed: { 'zh-CN': '直连探测失败', 'en-US': 'Direct probe failed' },
  direct_path_failed: { 'zh-CN': '直连路径失败', 'en-US': 'Direct path failed' },
  direct_attempt_cancelled: { 'zh-CN': '直连尝试已取消', 'en-US': 'Direct attempt cancelled' },
  direct_retry_scheduled: { 'zh-CN': '已安排直连重试', 'en-US': 'Direct retry scheduled' },
  compatibility_state_requested: { 'zh-CN': '已请求兼容状态', 'en-US': 'Compatibility state requested' },
  unknown: { 'zh-CN': '未知原因', 'en-US': 'Unknown reason' },
}

export function transitionReasonLabel(reason: string, locale: Locale): string {
  if (!reason) return '—'
  return (transitionReasonLabels[reason] ?? transitionReasonLabels.unknown)[locale]
}

export function lifecycleLabel(lifecycle: string, locale: Locale): string {
  const labels: Record<string, Record<Locale, string>> = {
    online: { 'zh-CN': '在线', 'en-US': 'Online' },
    offline: { 'zh-CN': '离线', 'en-US': 'Offline' },
    unbound: { 'zh-CN': '未绑定', 'en-US': 'Unbound' },
  }
  return labels[lifecycle]?.[locale] ?? (locale === 'zh-CN' ? '未知' : 'Unknown')
}
