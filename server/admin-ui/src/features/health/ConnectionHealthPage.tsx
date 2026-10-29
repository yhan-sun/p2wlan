import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Gauge,
  MonitorSmartphone,
  RadioTower,
  RefreshCw,
  Route,
  X,
} from 'lucide-react'
import { useEffect, useMemo, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { SnapshotExport } from '../../SnapshotExport'
import { adminApi } from '../../api'
import { getLocale, tr } from '../../i18n'
import { resourceOriginState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import type { AdminConnectionHealthAlert } from '../../types'
import { ConnectionDrawer } from '../connections/ConnectionDrawer'
import { healthSignalLabel } from '../connections/connectionLabels'
import { closeConnectionDetailSearch, connectionDetailIsOpen, connectionWorkspaceSearch } from '../connections/connectionNavigation'
import { HEALTH_PAGE_SIZE, HEALTH_SIGNALS, clearHealthScope, readHealthSearch, selectHealthDirection, type HealthDirection } from '../connections/trends'
import { useConnectionSearchParams } from '../connections/useConnectionSearch'

const HEALTH_ALERT_LIMIT = HEALTH_PAGE_SIZE

const WINDOW_OPTIONS = [
  { label: '1h', value: 3600 },
  { label: '6h', value: 21600 },
  { label: '24h', value: 86400 },
] as const

function formatAgo(unix?: number): string {
  if (!unix) return '—'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  const locale = getLocale()
  if (seconds < 45) return tr('刚刚')
  if (seconds < 3600) {
    const count = Math.max(1, Math.floor(seconds / 60))
    return locale === 'zh-CN' ? `${count} 分钟前` : `${count} min ago`
  }
  if (seconds < 86400) {
    const count = Math.floor(seconds / 3600)
    return locale === 'zh-CN' ? `${count} 小时前` : `${count} hr ago`
  }
  const count = Math.floor(seconds / 86400)
  return locale === 'zh-CN' ? `${count} 天前` : `${count} days ago`
}

function pathLabel(path?: string | null): string {
  if (!path) return tr('None')
  if (path === 'direct') return tr('Direct')
  if (path === 'relay') return tr('Relay')
  return tr(path.replaceAll('_', ' '))
}

function signalLabel(signal: string): string {
  return healthSignalLabel(signal, getLocale())
}

function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block" role="status"><div className="spinner" />{tr(label)}</div>
}

function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>{tr("无法加载数据")}</strong><span>{tr(message)}</span></div></div>
}

function HealthMetric({
  icon,
  label,
  value,
  meta,
}: {
  icon: ReactNode
  label: string
  value: ReactNode
  meta: ReactNode
}) {
  return <article className="connection-health-metric">
    <span className="connection-health-metric-icon">{icon}</span>
    <div><span>{label}</span><strong>{value}</strong><small>{meta}</small></div>
  </article>
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
      <span><strong>{pathLabel(alert.current_path)}</strong><small>{tr(alert.freshness)}</small></span>
      <span><strong>{alert.recent_path_switches}</strong><small>{tr("切换")}</small></span>
      <span><strong>{failureCount}</strong><small>{tr("失败")}</small></span>
      <span><strong>{alert.last_validation_rtt_ms === undefined ? '—' : `${alert.last_validation_rtt_ms} ms`}</strong><small>{tr("验证 RTT")}</small></span>
    </span>
    <span className="health-alert-tail">
      <strong>{alert.network_name}</strong>
      <small>{formatAgo(lastEvent)}</small>
    </span>
  </button>
}

export function ConnectionHealthPage() {
  const [searchParams, setSearchParams] = useConnectionSearchParams()
  const location = useLocation()
  const resourceOrigin = location.state
  const { networkId, accountId, deviceId, windowSeconds, alertSignal, alertPage, direction: selectedAlert } = readHealthSearch(searchParams)
  const offset = (alertPage - 1) * HEALTH_ALERT_LIMIT
  const hasNarrowScope = Boolean(accountId || deviceId)
  const refreshInterval = useAutoRefresh()
  const setSelectedAlert = (direction: HealthDirection | null) => setSearchParams((current) => selectHealthDirection(current, direction))
  const clearScope = (scope: 'account_id' | 'device_id' | 'all' = 'all') => setSearchParams((current) => clearHealthScope(current, scope))
  const updateFilter = (name: string, value: string, clearSelection = false) => setSearchParams((current) => {
    const next = clearSelection ? selectHealthDirection(current, null) : new URLSearchParams(current)
    if (value) next.set(name, value)
    else next.delete(name)
    if (name !== 'alert_page') next.delete('alert_page')
    if (name === 'network_id') next.delete('page')
    return next
  })

  const networks = useInfiniteQuery({
    queryKey: ['health', 'networks'],
    queryFn: ({ pageParam, signal }) => adminApi.networks(100, pageParam, signal),
    initialPageParam: 0,
    getNextPageParam: (lastPage) => {
      const nextOffset = lastPage.offset + lastPage.items.length
      return lastPage.items.length > 0 && nextOffset < lastPage.total ? nextOffset : undefined
    },
    staleTime: 60_000,
  })
  const networkItems = useMemo(
    () => networks.data?.pages.flatMap((page) => page.items) ?? [],
    [networks.data?.pages],
  )

  const health = useQuery({
    queryKey: ['connection-health', networkId, windowSeconds, accountId, deviceId, alertSignal, offset],
    queryFn: ({ signal }) => adminApi.connectionHealth({ networkId, accountId, deviceId, windowSeconds, alertSignal, offset }, HEALTH_ALERT_LIMIT, signal),
    refetchInterval: refreshInterval,
  })

  const summary = health.data?.summary
  const thresholds = health.data?.thresholds
  // Retained transition alerts can exist without a current observation. A signal
  // filter or an empty page must not hide that historical evidence.
  const noConnectionEvidence = summary?.total_observations === 0
    && health.data?.alerts_unfiltered_total === 0
    && health.data?.alerts_total === 0
    && health.data?.alerts.length === 0
  const healthSnapshot = !refreshInterval || health.isError || health.fetchStatus !== 'idle'
  const devicesSearch = new URLSearchParams()
  if (accountId) devicesSearch.set('account_id', accountId)
  const availablePage = health.data ? Math.max(1, Math.ceil(health.data.alerts_total / HEALTH_ALERT_LIMIT)) : alertPage
  const correctingPage = health.isSuccess && alertPage > availablePage
  useEffect(() => {
    if (correctingPage) setSearchParams((current) => {
      const next = new URLSearchParams(current)
      next.set('alert_page', String(availablePage))
      return next
    }, { replace: true })
  }, [correctingPage, availablePage, setSearchParams])

  return <div className="page-stack connection-health-page">
    <div className="connection-view-heading connection-health-intro">
      <div>
        <h3>{tr('待关注')}</h3>
        <p>{tr('先查看异常信号，再打开对应方向的连接详情。')}</p>
      </div>
    </div>

    <div className="connections-toolbar health-toolbar">
      <label className="connection-filter"><span>{tr('Network')}</span><select className="select-field" value={networkId} onChange={(event) => updateFilter('network_id', event.target.value, true)} aria-label={tr("按网络过滤健康信号")}>
        <option value="">{tr("全部网络")}</option>
        {networkId && !networkItems.some((network) => network.id === networkId) && <option value={networkId}>{networkId}</option>}
        {networkItems.map((network) => <option key={network.id} value={network.id}>{network.name}</option>)}
      </select></label>
      <label className="connection-filter"><span>{tr('健康信号')}</span><select className="select-field" value={alertSignal} aria-label={tr('按健康信号过滤')} onChange={(event) => updateFilter('signal', event.target.value, true)}>
        <option value="">{tr('全部健康信号')}</option>
        {HEALTH_SIGNALS.map((signal) => <option key={signal} value={signal}>{signalLabel(signal)}</option>)}
      </select></label>
      <div className="health-window-control"><span>{tr('健康窗口')}</span><div className="health-window-switch" role="group" aria-label={tr("健康窗口")}>
        {WINDOW_OPTIONS.map((option) => <button key={option.value} className={windowSeconds === option.value ? 'active' : ''} aria-pressed={windowSeconds === option.value} onClick={() => updateFilter('window_seconds', String(option.value), true)}>{option.label}</button>)}
      </div></div>
      {networks.hasNextPage && <button className="button secondary compact" onClick={() => networks.fetchNextPage()} disabled={networks.isFetchingNextPage}>
        {networks.isFetchingNextPage ? tr('加载中…') : tr('加载更多网络')}
      </button>}
      <SnapshotExport items={correctingPage ? [] : health.data?.alerts ?? []} filename="connection-health" total={health.data?.alerts_total} generatedAt={health.data?.generated_at} scope={{ network_id: networkId, account_id: accountId, device_id: deviceId, window_seconds: windowSeconds, signal: alertSignal, offset }} />
    </div>
    {hasNarrowScope && <div className="health-scope-filters" aria-label={tr('当前筛选范围')}>
      {accountId && <span className="health-scope-chip"><span>{tr('账号')}：<code>{accountId}</code></span><button type="button" aria-label={`${tr('清除账号范围')}: ${accountId}`} onClick={() => clearScope('account_id')}><X size={14} aria-hidden /></button></span>}
      {deviceId && <span className="health-scope-chip"><span>{tr('设备')}：<code>{deviceId}</code></span><button type="button" aria-label={`${tr('清除设备范围')}: ${deviceId}`} onClick={() => clearScope('device_id')}><X size={14} aria-hidden /></button></span>}
    </div>}
    {(networks.error || networks.fetchStatus === 'paused') && <QueryStatus queries={[networks]} />}
    <QueryStatus queries={[health]} />

    {!health.data && health.fetchStatus === 'paused' ? <ErrorBlock error={new Error('浏览器当前离线，无法访问控制面。网络恢复后会自动重新请求。')} /> : !health.data && health.isPending ? <LoadingBlock label={tr("正在聚合连接健康…")} /> : !health.data && health.error ? <ErrorBlock error={health.error} /> : health.data && summary ? noConnectionEvidence ? <section className="connections-empty-state" role="status">
      <MonitorSmartphone size={28} aria-hidden />
      <h3>{tr(healthSnapshot ? '上次快照中没有连接观测' : '尚无连接观测')}</h3>
      <p>{tr('端点上报连接后，才会在这里生成提醒。可先查看已注册设备。')}</p>
      <Link className="button secondary" to={`/devices${devicesSearch.size ? `?${devicesSearch}` : ''}`} state={resourceOriginState(location)}>{tr('查看设备')}</Link>
    </section> : <>
      <section className="panel-v2 health-attention-panel">
        <header className="panel-v2-header">
          <div><h4>{tr('待处理信号')}</h4><p>{tr('选择一条信号，查看连接详情与切换历史。')}</p></div>
          <span className={`badge ${health.data.alerts_total ? 'warning' : 'success'}`}><span />{health.data.alerts_total} {tr("条")}</span>
        </header>
        {correctingPage ? <LoadingBlock label={tr('正在调整分页…')} /> : health.data.alerts.length === 0
          ? <div className="health-empty"><CircleCheck size={19} /><div><strong>{tr(alertSignal ? '当前筛选条件下没有待关注信号' : '当前时间窗口没有待关注信号')}</strong><span>{tr("稳定的 Relay 路径不会被视为异常；此结果也不能证明目标业务端口已验证可达。")}</span></div></div>
          : <div className="health-alert-list">{health.data.alerts.map((alert) => <HealthAlertRow
            key={`${alert.network_id}:${alert.reporting_device_id}:${alert.remote_device_id}`}
            alert={alert}
            onSelect={setSelectedAlert}
          />)}</div>}
        <div className="pagination-v2"><span>{health.data.alerts.length ? offset + 1 : 0}–{health.data.alerts.length ? Math.min(offset + health.data.alerts.length, health.data.alerts_total) : 0} / {health.data.alerts_total} · {tr('按所选信号筛选')}</span><div>
          <button className="button secondary compact" disabled={correctingPage || offset === 0} onClick={() => updateFilter('alert_page', String(alertPage - 1))}><ChevronLeft size={15} />{tr('上一页')}</button>
          <button className="button secondary compact" disabled={correctingPage || offset + health.data.alerts.length >= health.data.alerts_total} onClick={() => updateFilter('alert_page', String(alertPage + 1))}>{tr('下一页')}<ChevronRight size={15} /></button>
        </div></div>
      </section>

      <section className="connection-health-metrics">
        <HealthMetric
          icon={<AlertTriangle size={17} />}
          label={tr("Needs attention")}
          value={health.data.alerts_unfiltered_total}
          meta={tr('当前范围内全部健康信号')}
        />
        <HealthMetric
          icon={<Activity size={17} />}
          label={tr("Fresh observations")}
          value={<>{summary.fresh_observations}{tr("/")}{summary.total_observations}</>}
          meta={getLocale() === 'zh-CN'
            ? <>{summary.stale_observations} 过期 · {summary.reporter_offline_observations} 上报端离线</>
            : <>{summary.stale_observations} stale · {summary.reporter_offline_observations} reporter offline</>}
        />
        <HealthMetric
          icon={<Route size={17} />}
          label={tr("Fresh paths")}
          value={<>{summary.fresh_direct} {tr("/ ")}{summary.fresh_relay}</>}
          meta={<>{tr("Direct / Relay · ")}{summary.fresh_online_no_path} {tr("在线但暂无路径")}</>}
        />
        <HealthMetric
          icon={<RefreshCw size={17} />}
          label={tr("Recent transitions")}
          value={summary.recent_path_switches}
          meta={<>{summary.recent_direct_failures + summary.recent_relay_failures} {tr("explicit path failures")}</>}
        />
        <HealthMetric
          icon={<Gauge size={17} />}
          label={tr("Validation RTT")}
          value={summary.average_validation_rtt_ms === undefined ? '—' : `${summary.average_validation_rtt_ms} ms`}
          meta={summary.validation_rtt_samples
            ? getLocale() === 'zh-CN'
              ? `${summary.validation_rtt_samples} 个样本 · 最大 ${summary.max_validation_rtt_ms ?? '—'} ms`
              : `${summary.validation_rtt_samples} samples · max ${summary.max_validation_rtt_ms ?? '—'} ms`
            : tr('没有有效的 RTT 验证样本')}
        />
      </section>

      <details className="health-methodology"><summary>{tr('信号与统计说明')}</summary>
        <div className="health-threshold-strip"><div><RadioTower size={15} /><strong>{tr("显式阈值")}</strong></div><span>{tr("频繁切换 ≥ ")}{thresholds?.frequent_path_switches ?? '—'}</span><span>{tr("重复路径失败 ≥ ")}{thresholds?.repeated_path_failures ?? '—'}</span><span>{tr("每个方向最多保留 ")}{health.data.history_limit_per_direction}{tr(" 条切换记录")}</span><span>{tr("生成于 ")}{formatAgo(health.data.generated_at)}</span></div>
        <p>{tr("只读汇总由守护进程权威报告的路径观测和有上限的切换历史。这里不生成综合健康分，也不会把 Relay 路径本身判定为故障。")}</p>
        <p>{tr("连接健康是请求时生成的派生视图，不会回写守护进程，也不代表长期服务等级。验证 RTT 使用已有观测中的最近样本；仍需通过虚拟 IP 流量确认业务可达性。")}</p>
      </details>
    </> : <ErrorBlock error={new Error('控制面未返回连接健康数据。')} />}

    <div className="connection-context-note"><span>{tr('趋势按网络汇总，保留当前排障上下文。')}</span><Link className="button secondary compact" to={`/connections?${connectionWorkspaceSearch(searchParams, 'trends')}`} state={resourceOrigin}>{tr('查看历史趋势')}</Link></div>
    {selectedAlert && connectionDetailIsOpen(searchParams) && <ConnectionDrawer key={`${selectedAlert.network_id}:${selectedAlert.reporting_device_id}:${selectedAlert.remote_device_id}`} connection={selectedAlert} onClose={() => setSearchParams(closeConnectionDetailSearch, { replace: true })} />}
  </div>
}
