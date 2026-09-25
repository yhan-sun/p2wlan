import { useMemo, useState } from 'react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  Gauge,
  RadioTower,
  RefreshCw,
  Route,
} from 'lucide-react'
import { adminApi } from '../../api'
import { MetricCard, PageHeader, Panel, SegmentedControl, StatusPill } from '../../components/ui/console'
import { ErrorBlock, LoadingBlock, formatAgo } from '../../shared/console'
import { ConnectionDrawer } from '../connections/ConnectionsPage'
import type { AdminConnectionHealthAlert } from '../../types'

const HEALTH_ALERT_LIMIT = 100

const WINDOW_OPTIONS = [
  { label: '1h', value: 3600 },
  { label: '6h', value: 21600 },
  { label: '24h', value: 86400 },
] as const

function pathLabel(path?: string | null): string {
  if (!path) return 'None'
  if (path === 'direct') return 'Direct'
  if (path === 'relay') return 'Relay'
  return path.replaceAll('_', ' ')
}

function signalLabel(signal: string): string {
  const labels: Record<string, string> = {
    reporter_offline: '上报端离线',
    stale_observation: '观测过期',
    no_active_path: '在线但无活动路径',
    frequent_path_switching: '路径频繁切换',
    repeated_path_failures: '路径失败重复发生',
  }
  return labels[signal] ?? signal.replaceAll('_', ' ')
}

function HealthAlertRow({
  alert,
  onSelect,
}: {
  alert: AdminConnectionHealthAlert
  onSelect: (alert: AdminConnectionHealthAlert) => void
}) {
  const lastEvent = Math.max(alert.received_at, alert.last_transition_at ?? 0)
  const failureCount = alert.recent_direct_failures + alert.recent_relay_failures
  return <button className={`health-alert-row ${alert.severity === 'warning' ? 'warning' : 'info'}`} onClick={() => onSelect(alert)}>
    <span className="health-alert-severity" aria-hidden>
      {alert.severity === 'warning' ? <AlertTriangle size={16} /> : <CircleAlert size={16} />}
    </span>
    <span className="health-alert-direction">
      <span><strong>{alert.reporting_device_name}</strong><small>{alert.reporting_username}</small></span>
      <ArrowDownRight size={15} aria-hidden />
      <span><strong>{alert.remote_device_name}</strong><small>{alert.remote_username}</small></span>
    </span>
    <span className="health-alert-signals">
      {alert.signals.map((signal) => <span className={`health-signal-chip ${alert.severity === 'warning' ? 'warning' : ''}`} key={signal}>{signalLabel(signal)}</span>)}
    </span>
    <span className="health-alert-facts">
      <span><strong>{pathLabel(alert.current_path)}</strong><small>{alert.freshness}</small></span>
      <span><strong>{alert.recent_path_switches}</strong><small>切换</small></span>
      <span><strong>{failureCount}</strong><small>失败</small></span>
      <span><strong>{alert.last_validation_rtt_ms === undefined ? '—' : `${alert.last_validation_rtt_ms} ms`}</strong><small>验证 RTT</small></span>
    </span>
    <span className="health-alert-tail">
      <strong>{alert.network_name}</strong>
      <small>{formatAgo(lastEvent)}</small>
    </span>
  </button>
}

export function ConnectionHealthPage() {
  const [networkId, setNetworkId] = useState('')
  const [windowSeconds, setWindowSeconds] = useState<number>(3600)
  const [selectedAlert, setSelectedAlert] = useState<AdminConnectionHealthAlert | null>(null)

  const networks = useInfiniteQuery({
    queryKey: ['health', 'networks'],
    queryFn: ({ pageParam }) => adminApi.networks(100, pageParam),
    initialPageParam: 0,
    getNextPageParam: (lastPage) => {
      const nextOffset = lastPage.offset + lastPage.items.length
      return nextOffset < lastPage.total ? nextOffset : undefined
    },
    staleTime: 60_000,
  })
  const networkItems = useMemo(
    () => networks.data?.pages.flatMap((page) => page.items) ?? [],
    [networks.data?.pages],
  )

  const health = useQuery({
    queryKey: ['connection-health', networkId, windowSeconds],
    queryFn: () => adminApi.connectionHealth({ networkId, windowSeconds }, HEALTH_ALERT_LIMIT),
    refetchInterval: 15_000,
  })

  const selectedConnection = useQuery({
    queryKey: [
      'health-selected-connection',
      selectedAlert?.network_id,
      selectedAlert?.reporting_device_id,
      selectedAlert?.remote_device_id,
    ],
    queryFn: () => adminApi.connections({
      networkId: selectedAlert!.network_id,
      reportingDeviceId: selectedAlert!.reporting_device_id,
      remoteDeviceId: selectedAlert!.remote_device_id,
    }, 1, 0),
    enabled: Boolean(selectedAlert),
    refetchInterval: 10_000,
  })

  const summary = health.data?.summary
  const thresholds = health.data?.thresholds
  const selected = selectedConnection.data?.items[0]

  return <div className="page-stack connection-health-page">
    <PageHeader
      eyebrow="OBSERVABILITY"
      title="连接健康"
      description="只读聚合 daemon 权威路径观测与受限迁移历史。这里没有综合健康分，稳定 Relay 也不会被自动判定为故障。"
      actions={<SegmentedControl
        label="健康窗口"
        value={windowSeconds}
        onChange={setWindowSeconds}
        options={WINDOW_OPTIONS}
      />}
    />

    <div className="connections-toolbar health-toolbar">
      <select className="select-field" value={networkId} onChange={(event) => setNetworkId(event.target.value)} aria-label="按网络过滤健康信号">
        <option value="">全部网络</option>
        {networkItems.map((network) => <option key={network.id} value={network.id}>{network.name}</option>)}
      </select>
      {networks.hasNextPage && <button className="button secondary compact" onClick={() => networks.fetchNextPage()} disabled={networks.isFetchingNextPage}>
        {networks.isFetchingNextPage ? '加载中…' : '加载更多网络'}
      </button>}
      <span className="health-toolbar-note"><Clock3 size={14} />窗口内切换/失败统计来自每方向最多 50 条保留历史。</span>
    </div>

    {health.isPending ? <LoadingBlock label="正在聚合连接健康…" /> : health.error ? <ErrorBlock error={health.error} /> : health.data && summary ? <>
      <section className="connection-health-metrics">
        <MetricCard
          icon={<AlertTriangle size={17} />}
          label="Needs attention"
          value={health.data.alerts_total}
          meta={health.data.alerts_total > health.data.alerts.length ? `仅展示前 ${health.data.alerts.length} 条` : '当前派生信号'}
        />
        <MetricCard
          icon={<Activity size={17} />}
          label="Fresh observations"
          value={<>{summary.fresh_observations}/{summary.total_observations}</>}
          meta={<>{summary.stale_observations} stale · {summary.reporter_offline_observations} reporter offline</>}
        />
        <MetricCard
          icon={<Route size={17} />}
          label="Fresh paths"
          value={<>{summary.fresh_direct} / {summary.fresh_relay}</>}
          meta={<>Direct / Relay · {summary.fresh_online_no_path} online no-path</>}
        />
        <MetricCard
          icon={<RefreshCw size={17} />}
          label="Recent transitions"
          value={summary.recent_path_switches}
          meta={<>{summary.recent_direct_failures + summary.recent_relay_failures} explicit path failures</>}
        />
        <MetricCard
          icon={<Gauge size={17} />}
          label="Validation RTT"
          value={summary.average_validation_rtt_ms === undefined ? '—' : `${summary.average_validation_rtt_ms} ms`}
          meta={summary.validation_rtt_samples ? `${summary.validation_rtt_samples} samples · max ${summary.max_validation_rtt_ms ?? '—'} ms` : '没有 fresh validation sample'}
        />
      </section>

      <section className="health-threshold-strip">
        <div><RadioTower size={15} /><strong>显式阈值</strong></div>
        <span>频繁切换 ≥ {thresholds?.frequent_path_switches ?? '—'}</span>
        <span>重复路径失败 ≥ {thresholds?.repeated_path_failures ?? '—'}</span>
        <span>history cap {health.data.history_limit_per_direction}/方向</span>
        <span>生成于 {formatAgo(health.data.generated_at)}</span>
      </section>

      <Panel
        className="health-attention-panel"
        title="Needs attention"
        subtitle="每一项都来自固定 signal；点击查看对应方向的当前 Connection 与切换历史。"
        action={<StatusPill tone={health.data.alerts_total ? 'warning' : 'success'} dot>{health.data.alerts_total} 条</StatusPill>}
      >
        {health.data.alerts.length === 0
          ? <div className="health-empty"><CircleCheck size={19} /><div><strong>当前窗口没有 attention signal</strong><span>稳定 Relay 不会被当成异常；此结果也不等于目标业务端口已经验证可达。</span></div></div>
          : <div className="health-alert-list">{health.data.alerts.map((alert) => <HealthAlertRow
            key={`${alert.network_id}:${alert.reporting_device_id}:${alert.remote_device_id}`}
            alert={alert}
            onSelect={setSelectedAlert}
          />)}</div>}
        {health.data.alerts_total > health.data.alerts.length && <div className="connection-partial-warning">
          <CircleAlert size={15} />当前共有 {health.data.alerts_total} 条 attention connection，页面按 API 上界展示前 {health.data.alerts.length} 条；请使用 Network scope 收窄范围。
        </div>}
      </Panel>

      <div className="truth-notice health-truth-notice">
        <CircleAlert size={15} />
        <span>Connection Health 是请求时派生视图，不会反写 daemon，也不是长期 SLA。验证 RTT 是已有 observation 的最近验证样本；最终业务可达性仍需虚拟 IP 流量验证。</span>
      </div>
    </> : <ErrorBlock error={new Error('Control 未返回 Connection Health。')} />}

    {selectedAlert && selectedConnection.isPending && <div className="health-selection-loading"><div className="spinner" />正在打开 directional connection…</div>}
    {selectedAlert && selectedConnection.error && <div className="health-selection-error"><CircleAlert size={15} />无法读取该连接的最新快照；它可能已被移除。</div>}
    {selectedAlert && selectedConnection.data && selectedConnection.data.items.length === 0 && <div className="health-selection-error"><CircleAlert size={15} />该 directional observation 已不存在；刷新 Health 后会移除这条旧 attention item。</div>}
    {selected && <ConnectionDrawer connection={selected} onClose={() => setSelectedAlert(null)} />}
  </div>
}
