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
  if (!path) return '无路径'
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

function freshnessLabel(value: string): string {
  if (value === 'fresh') return '新鲜'
  if (value === 'reporter_offline') return '上报端离线'
  if (value === 'stale') return '过期'
  return value.replaceAll('_', ' ')
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
      <span><strong>{pathLabel(alert.current_path)}</strong><small>{freshnessLabel(alert.freshness)}</small></span>
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
      eyebrow="可观测性"
      title="连接健康"
      description="基于 daemon 权威路径观测与受限迁移历史。没有综合健康分，稳定 Relay 不会被判为故障。"
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
      <span className="health-toolbar-note"><Clock3 size={14} />切换与失败统计基于每方向最近 50 条历史。</span>
    </div>

    {health.isPending ? <LoadingBlock label="正在聚合连接健康…" /> : health.error ? <ErrorBlock error={health.error} /> : health.data && summary ? <>
      <section className="connection-health-metrics">
        <MetricCard
          icon={<AlertTriangle size={17} />}
          label="需要关注"
          value={health.data.alerts_total}
          meta={health.data.alerts_total > health.data.alerts.length ? `仅展示前 ${health.data.alerts.length} 条` : '当前派生信号'}
        />
        <MetricCard
          icon={<Activity size={17} />}
          label="新鲜观测"
          value={<>{summary.fresh_observations}/{summary.total_observations}</>}
          meta={<>{summary.stale_observations} 过期 · {summary.reporter_offline_observations} 上报端离线</>}
        />
        <MetricCard
          icon={<Route size={17} />}
          label="新鲜路径"
          value={<>{summary.fresh_direct} / {summary.fresh_relay}</>}
          meta={<>Direct / Relay · {summary.fresh_online_no_path} 在线无路径</>}
        />
        <MetricCard
          icon={<RefreshCw size={17} />}
          label="最近切换"
          value={summary.recent_path_switches}
          meta={<>{summary.recent_direct_failures + summary.recent_relay_failures} 次显式路径失败</>}
        />
        <MetricCard
          icon={<Gauge size={17} />}
          label="验证 RTT"
          value={summary.average_validation_rtt_ms === undefined ? '—' : `${summary.average_validation_rtt_ms} ms`}
          meta={summary.validation_rtt_samples ? `${summary.validation_rtt_samples} 个样本 · 最大 ${summary.max_validation_rtt_ms ?? '—'} ms` : '没有新鲜验证样本'}
        />
      </section>

      <section className="health-threshold-strip">
        <div><RadioTower size={15} /><strong>显式阈值</strong></div>
        <span>频繁切换 ≥ {thresholds?.frequent_path_switches ?? '—'}</span>
        <span>重复路径失败 ≥ {thresholds?.repeated_path_failures ?? '—'}</span>
        <span>历史上限 {health.data.history_limit_per_direction}/方向</span>
        <span>生成于 {formatAgo(health.data.generated_at)}</span>
      </section>

      <Panel
        className="health-attention-panel"
        title="需要关注"
        subtitle="每一项都来自固定信号；点击查看对应方向的当前连接与切换历史。"
        action={<StatusPill tone={health.data.alerts_total ? 'warning' : 'success'} dot>{health.data.alerts_total} 条</StatusPill>}
      >
        {health.data.alerts.length === 0
          ? <div className="health-empty"><CircleCheck size={19} /><div><strong>当前窗口没有关注信号</strong><span>稳定 Relay 不会被当成异常；此结果也不等于目标业务端口已经验证可达。</span></div></div>
          : <div className="health-alert-list">{health.data.alerts.map((alert) => <HealthAlertRow
            key={`${alert.network_id}:${alert.reporting_device_id}:${alert.remote_device_id}`}
            alert={alert}
            onSelect={setSelectedAlert}
          />)}</div>}
        {health.data.alerts_total > health.data.alerts.length && <div className="connection-partial-warning">
          <CircleAlert size={15} />当前共有 {health.data.alerts_total} 条关注连接，页面按 API 上界展示前 {health.data.alerts.length} 条；请使用网络范围收窄范围。
        </div>}
      </Panel>

      <div className="truth-notice health-truth-notice">
        <CircleAlert size={15} />
        <span>连接健康是请求时派生视图，不反写 daemon，也不代表业务可达性；最终仍需虚拟 IP 流量验证。</span>
      </div>
    </> : <ErrorBlock error={new Error('Control 未返回连接健康。')} />}

    {selectedAlert && selectedConnection.isPending && <div className="health-selection-loading"><div className="spinner" />正在打开单向连接…</div>}
    {selectedAlert && selectedConnection.error && <div className="health-selection-error"><CircleAlert size={15} />无法读取该连接的最新快照；它可能已被移除。</div>}
    {selectedAlert && selectedConnection.data && selectedConnection.data.items.length === 0 && <div className="health-selection-error"><CircleAlert size={15} />该单向观测已不存在；刷新连接健康后会移除这条旧关注项。</div>}
    {selected && <ConnectionDrawer connection={selected} onClose={() => setSelectedAlert(null)} />}
  </div>
}
