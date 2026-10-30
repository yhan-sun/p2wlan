import { useQuery } from '@tanstack/react-query'
import { ArrowRight, ChevronDown, ChevronRight, CircleAlert, CircleCheck, MonitorSmartphone, UsersRound } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { getLocale, tr } from '../../i18n'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { AccountMark, ErrorBlock, Panel, PendingBlock, formatAgo } from '../../shared/console'
import type { AdminAccount, AdminConnectionHealthAlert } from '../../types'
import { healthSignalLabel } from '../connections/connectionLabels'
import { selectConnectionSearch } from '../connections/connectionNavigation'

function Metric({ label, value, meta, to, pending }: {
  label: string; value: ReactNode; meta: ReactNode; to: string; pending: boolean
}) {
  return <Link className="overview-metric" to={to}>
    <span className="overview-metric-heading">{label}</span>
    <span className="overview-metric-value">{pending ? <span className="overview-metric-placeholder" aria-label={tr('加载中…')} /> : value}</span>
    <span className="overview-metric-meta">{meta}</span>
  </Link>
}

type OverviewQuery = { dataUpdatedAt: number; fetchStatus: string; error: unknown; refetch: () => unknown }

function snapshotNeedsNotice(query: OverviewQuery, automatic: number | false) {
  return !automatic || Boolean(query.error) || query.fetchStatus === 'paused'
}

function SnapshotNotice({ query, label, automatic }: { query: OverviewQuery; label: string; automatic: number | false }) {
  return snapshotNeedsNotice(query, automatic) ? <div className="overview-snapshot-notice"><QueryStatus queries={[query]} label={label} /></div> : null
}

function SnapshotDetails({ query, label, automatic, summary, children }: {
  query: OverviewQuery; label: string; automatic: number | false; summary: string; children?: ReactNode
}) {
  return <details className="overview-details">
    <summary><span>{summary}</span><ChevronDown size={14} aria-hidden /></summary>
    <div className="overview-details-body">
      {!snapshotNeedsNotice(query, automatic) && <QueryStatus queries={[query]} label={label} />}
      {children}
    </div>
  </details>
}

function AttentionRow({ alert }: { alert: AdminConnectionHealthAlert }) {
  const search = selectConnectionSearch(new URLSearchParams('tab=health'), alert)
  const reporter = alert.reporting_device_name || alert.reporting_device_id
  const remote = alert.remote_device_name || alert.remote_device_id
  return <li><Link className="overview-attention-row" to={`/connections?${search}`} title={tr('查看连接详情')}>
    <span className={`overview-attention-icon${alert.severity === 'warning' ? ' warning' : ''}`}><CircleAlert size={18} aria-hidden /></span>
    <span className="overview-attention-main">
      <span className="overview-direction"><strong title={reporter}>{reporter}</strong><ArrowRight size={14} aria-label={tr('当前方向')} /><strong title={remote}>{remote}</strong></span>
      <span className="overview-attention-reasons">{alert.signals.map((signal) => healthSignalLabel(signal, getLocale())).join(' · ')}</span>
    </span>
    <span className="overview-attention-context"><strong>{alert.network_name || alert.network_id}</strong><span>{formatAgo(Math.max(alert.received_at, alert.last_transition_at || 0))}</span></span>
    <ChevronRight size={16} className="overview-row-arrow" aria-hidden />
  </Link></li>
}

function RecentAccount({ account }: { account: AdminAccount }) {
  return <li><Link className="overview-account-row" to={`/accounts/${encodeURIComponent(account.id)}`}>
    <AccountMark account={account} size="small" />
    <span className="overview-account-main"><strong title={account.username}>{account.username}</strong><span title={account.email}>{account.email}</span></span>
    <span className="overview-account-devices"><strong><span className="sr-only">{tr('设备在线 / 总数')} </span>{account.online_devices}<span> / {account.device_count}</span></strong><small>{formatAgo(account.last_seen)}</small></span>
    <ChevronRight size={15} className="overview-row-arrow" aria-hidden />
  </Link></li>
}

export function Dashboard() {
  const refetchInterval = useAutoRefresh()
  const overview = useQuery({ queryKey: ['overview'], queryFn: ({ signal }) => adminApi.overview(signal), refetchInterval })
  const accounts = useQuery({ queryKey: ['accounts', 'recent'], queryFn: () => adminApi.accounts('', 6, 0), refetchInterval })
  const health = useQuery({ queryKey: ['connection-health', 'dashboard', 3600], queryFn: ({ signal }) => adminApi.connectionHealth({ windowSeconds: 3600 }, 5, signal), refetchInterval })
  const offlineDevices = overview.data ? Math.max(0, overview.data.devices - overview.data.online_devices) : 0
  const healthSnapshot = snapshotNeedsNotice(health, refetchInterval)
  const overviewSnapshot = snapshotNeedsNotice(overview, refetchInterval)
  const accountsSnapshot = snapshotNeedsNotice(accounts, refetchInterval)
  const number = (value: number | undefined) => value === undefined ? '—' : new Intl.NumberFormat(getLocale()).format(value)

  return <div className="page-stack overview-page">
    <PageHeader title={tr('运维概览')} actions={<Link className="overview-workspace-link" to="/connections?tab=all">{tr('打开连接工作区')}<ArrowRight size={15} aria-hidden /></Link>} />
    <section className="overview-resources" aria-label={tr('资源快照')}>
      <div className="overview-metrics" aria-busy={overview.isPending}>
        <Metric label={tr('账号')} to="/accounts" pending={overview.isPending} value={number(overview.data?.users)} meta={tr('已注册账号')} />
        <Metric label={tr('在线设备')} to="/devices" pending={overview.isPending} value={<>{number(overview.data?.online_devices)}<small> / {number(overview.data?.devices)}</small></>} meta={tr('设备在线 / 总数')} />
        <Metric label={tr('网络')} to="/networks" pending={overview.isPending} value={number(overview.data?.networks)} meta={<>{number(overview.data?.rooms)} {tr('个房间网络')}</>} />
        <Metric label={tr('待处理信令')} to="/system" pending={overview.isPending} value={number(overview.data?.pending_signals)} meta={tr('控制面协调消息')} />
      </div>
      <SnapshotNotice query={overview} label="资源快照" automatic={refetchInterval} />
      {overview.isPending ? <PendingBlock queries={[overview]} label="正在读取控制面状态…" /> : overview.error && !overview.data ? <ErrorBlock error={overview.error} onRetry={() => { void overview.refetch() }} /> : null}
      <SnapshotDetails query={overview} label="资源快照" automatic={refetchInterval} summary={tr('资源快照')}>
        {overview.data && (overview.data.devices === 0 ? <div className="overview-resource-note"><MonitorSmartphone size={16} aria-hidden /><span>{tr(overviewSnapshot ? '上次资源快照中没有设备，请刷新后确认。' : '尚未注册设备。注册并连接客户端后，这里会显示资源与在线状态。')}</span><Link to="/devices" className="text-link">{tr('查看设备')}<ArrowRight size={14} aria-hidden /></Link></div> : offlineDevices > 0 && <div className="overview-resource-note"><MonitorSmartphone size={16} aria-hidden /><span>{offlineDevices} {tr('台设备在当前快照中离线；离线本身不等同于故障。')}</span><Link to="/devices?status=offline" className="text-link">{tr('查看离线设备')}<ArrowRight size={14} aria-hidden /></Link></div>)}
      </SnapshotDetails>
    </section>
    <div className="overview-workspace">
      <Panel className="overview-attention-panel" title={tr('需要关注')} action={<Link className="text-link overview-section-link" to="/connections?tab=health">{health.data && <span className="overview-count">{number(health.data.alerts_total)}</span>}{tr('查看全部提醒')}<ArrowRight size={14} aria-hidden /></Link>}>
        <SnapshotNotice query={health} label="连接观测" automatic={refetchInterval} />
        {health.isPending ? <PendingBlock queries={[health]} label="正在读取连接提醒…" /> : health.error && !health.data ? <ErrorBlock error={health.error} onRetry={() => { void health.refetch() }} /> : health.data && <>
          {health.data.alerts.length ? <>
            <div className="overview-attention-columns" aria-hidden><span>{tr('最近 1 小时')}</span><span>{tr('网络')} / {tr('最近证据')}</span></div>
            <ul className="overview-attention-list">{health.data.alerts.map((alert) => <AttentionRow key={`${alert.network_id}:${alert.reporting_device_id}:${alert.remote_device_id}`} alert={alert} />)}</ul>
          </> : <div className="overview-empty">
            <span className="overview-empty-icon">{health.data.summary.total_observations === 0 ? <MonitorSmartphone size={24} aria-hidden /> : <CircleCheck size={24} aria-hidden />}</span>
            <strong>{tr(healthSnapshot ? health.data.summary.total_observations === 0 ? '上次快照中没有连接观测' : '上次快照中没有待关注提醒' : health.data.summary.total_observations === 0 ? '尚无连接观测' : '当前范围没有待关注提醒')}</strong>
            <p>{tr(health.data.summary.total_observations === 0 ? '端点上报连接后，才会在这里生成提醒。可先查看已注册设备。' : '这表示当前记录未触发提醒，不代表所有业务已经验证可达。')}</p>
            <Link className="button secondary" to={health.data.summary.total_observations === 0 ? '/devices' : '/connections?tab=all'}>{tr(health.data.summary.total_observations === 0 ? '查看设备' : '查看全部观测')}<ArrowRight size={14} aria-hidden /></Link>
          </div>}
        </>}
        {health.data && <dl className="overview-evidence">
          <div><dt>{tr('Fresh Direct')}</dt><dd>{number(health.data.summary.fresh_direct)}</dd></div>
          <div><dt>{tr('Fresh Relay')}</dt><dd>{number(health.data.summary.fresh_relay)}</dd></div>
          <div><dt>{tr('Path switches')}</dt><dd>{number(health.data.summary.recent_path_switches)}</dd></div>
        </dl>}
        <SnapshotDetails query={health} label="连接观测" automatic={refetchInterval} summary={tr('观测说明')}>
          <p>{tr('最近 1 小时 · 依据端点上报与路径迁移记录')}</p>
          {health.data && health.data.alerts_total > health.data.alerts.length && <p>{tr('这里只显示优先级最高的前 5 条提醒；完整列表请查看全部提醒。')}</p>}
          <p>{tr('提醒保持方向性，不推断双向业务可达。')}</p>
        </SnapshotDetails>
      </Panel>
      <Panel className="overview-accounts-panel" title={tr('最近账号')} action={<Link className="text-link overview-section-link" to="/accounts">{tr('全部账号')}<ArrowRight size={14} aria-hidden /></Link>}>
        <SnapshotNotice query={accounts} label="最近账号" automatic={refetchInterval} />
        {accounts.isPending ? <PendingBlock queries={[accounts]} /> : accounts.error && !accounts.data ? <ErrorBlock error={accounts.error} onRetry={() => { void accounts.refetch() }} /> : accounts.data?.items.length ? <>
          <div className="overview-account-columns" aria-hidden><span>{tr('账号')}</span><span>{tr('在线设备')}</span></div>
          <ul className="overview-account-list">{accounts.data.items.map((account) => <RecentAccount key={account.id} account={account} />)}</ul>
        </> : <div className="overview-accounts-empty"><UsersRound size={24} aria-hidden /><strong>{tr(accountsSnapshot ? '上次快照中没有账号' : '暂无账号')}</strong><Link className="text-link" to="/accounts">{tr('全部账号')}<ArrowRight size={14} aria-hidden /></Link></div>}
        <SnapshotDetails query={accounts} label="最近账号" automatic={refetchInterval} summary={tr('按设备最后活动时间排序')} />
      </Panel>
    </div>
  </div>
}
