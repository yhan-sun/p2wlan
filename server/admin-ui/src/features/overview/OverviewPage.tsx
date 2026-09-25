import { useQuery } from '@tanstack/react-query'
import {
  ArrowRight,
  CircleAlert,
  ChevronRight,
  CircleCheck,
  Gauge,
  RadioTower,
  Waypoints,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { adminApi } from '../../api'
import { PageHeader, Panel, StatusPill } from '../../components/ui/console'
import { AccountMark, ErrorBlock, PendingBlock, formatAgo, formatDate, formatDuration } from '../../shared/console'

export function Dashboard() {
  const overview = useQuery({ queryKey: ['overview'], queryFn: adminApi.overview, refetchInterval: 30_000 })
  const accounts = useQuery({ queryKey: ['accounts', 'recent'], queryFn: () => adminApi.accounts('', 6, 0), refetchInterval: 30_000 })
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: adminApi.runtime, refetchInterval: 30_000 })
  const connectionHealth = useQuery({
    queryKey: ['connection-health', 'dashboard', 3600],
    queryFn: () => adminApi.connectionHealth({ windowSeconds: 3600 }, 5),
    refetchInterval: 60_000,
  })
  if (overview.isPending || accounts.isPending || runtime.isPending) return <PendingBlock queries={[overview, accounts, runtime]} label="正在读取 Control 状态…" />
  const error = overview.error || accounts.error || runtime.error
  if (error) return <ErrorBlock error={error} />
  if (!overview.data || !accounts.data || !runtime.data) return <ErrorBlock error={new Error('Control 未返回完整快照，请刷新重试。')} />

  const offlineDevices = Math.max(0, overview.data.devices - overview.data.online_devices)
  const health = connectionHealth.data

  return <div className="page-stack overview-page">
    <PageHeader
      title="概览"
      description="Control、路径与最近活动。这里只展示可确认事实，不合成健康分。"
      actions={<div className="overview-page-actions">
        <StatusPill tone="success" dot>Control 在线</StatusPill>
        <span className="overview-build mono">{runtime.data.build_version}</span>
      </div>}
    />

    <section className="overview-stat-strip" aria-label="Control 摘要">
      <div>
        <span>设备</span>
        <strong>{overview.data.online_devices}<small> / {overview.data.devices}</small></strong>
        <p>{offlineDevices ? `${offlineDevices} 台离线` : '全部在线'}</p>
      </div>
      <div>
        <span>账号</span>
        <strong>{overview.data.users}</strong>
        <p>{overview.data.networks} 个网络</p>
      </div>
      <div>
        <span>新鲜直连</span>
        <strong>{health?.summary.fresh_direct ?? '—'}</strong>
        <p>最近 1 小时</p>
      </div>
      <div>
        <span>新鲜中继</span>
        <strong>{health?.summary.fresh_relay ?? '—'}</strong>
        <p>最近 1 小时</p>
      </div>
      <div>
        <span>待处理信令</span>
        <strong>{overview.data.pending_signals}</strong>
        <p>{overview.data.active_tunnels} 个活动隧道</p>
      </div>
    </section>

    <section className="overview-primary-grid">
      <Panel
        title="连接状态"
        subtitle="最近 1 小时 daemon 权威观测"
        action={<Link className="text-link" to="/health">连接健康<ArrowRight size={13} /></Link>}
      >
        {connectionHealth.isPending
          ? <div className="overview-inline-state"><div className="spinner" />正在聚合路径信号…</div>
          : connectionHealth.error
            ? <div className="overview-inline-state warning"><CircleAlert size={15} />连接健康暂不可用</div>
            : health && <div className="overview-health-list">
              <div><span>新鲜观测</span><strong>{health.summary.fresh_observations}<small> / {health.summary.total_observations}</small></strong></div>
              <div><span>路径切换</span><strong>{health.summary.recent_path_switches}</strong></div>
              <div><span>显式路径失败</span><strong>{health.summary.recent_direct_failures + health.summary.recent_relay_failures}</strong></div>
              <div><span>需要关注</span><strong className={health.alerts_total ? 'warning-text' : ''}>{health.alerts_total}</strong></div>
              <div><span>平均验证 RTT</span><strong>{health.summary.average_validation_rtt_ms === undefined ? '—' : `${health.summary.average_validation_rtt_ms} ms`}</strong></div>
            </div>}
      </Panel>

      <Panel title="需要关注" subtitle="仅显示当前快照中需要处理的事实">
        <div className="attention-list minimal">
          {connectionHealth.isPending && <div className="attention-item neutral"><Gauge size={15} /><div><strong>正在读取连接关注信号</strong><span>设备与信令状态仍可独立确认。</span></div></div>}
          {connectionHealth.error && <div className="attention-item warning"><CircleAlert size={15} /><div><strong>连接健康暂不可用</strong><span>无法读取最近 1 小时的派生关注信号。</span></div><Link to="/health">连接健康</Link></div>}
          {health && health.alerts_total > 0 && <div className="attention-item warning"><CircleAlert size={15} /><div><strong>{health.alerts_total} 条连接需要关注</strong><span>来自 daemon 路径观测与受限迁移历史。</span></div><Link to="/health">连接健康</Link></div>}
          {offlineDevices > 0 && <div className="attention-item warning"><CircleAlert size={15} /><div><strong>{offlineDevices} 台设备离线</strong><span>结合最后活动时间确认是否为预期离线。</span></div><Link to="/devices">设备</Link></div>}
          {overview.data.pending_signals > 0 && <div className="attention-item warning"><RadioTower size={15} /><div><strong>{overview.data.pending_signals} 条待处理信令</strong><span>这是控制面协调状态，不等于数据路径故障。</span></div><Link to="/relationships">资源关系</Link></div>}
          {!connectionHealth.isPending && !connectionHealth.error && (health?.alerts_total ?? 0) === 0 && offlineDevices === 0 && overview.data.pending_signals === 0 &&
            <div className="attention-item success"><CircleCheck size={15} /><div><strong>暂无需要处理的关注项</strong><span>当前快照未发现离线设备、信令积压或连接关注信号。</span></div></div>}
        </div>
      </Panel>
    </section>

    <section className="overview-secondary-grid">
      <Panel title="最近账号" action={<Link className="text-link" to="/accounts">全部<ArrowRight size={13} /></Link>}>
        <div className="recent-account-list compact">{accounts.data.items.map((account) => <Link className="recent-account-row" to={'/accounts/' + encodeURIComponent(account.id)} key={account.id}>
          <AccountMark account={account} size="small" />
          <div className="recent-account-main"><strong>{account.username}</strong><span>{account.email}</span></div>
          <div className="recent-account-stat"><strong>{account.online_devices}/{account.device_count}</strong><span>在线</span></div>
          <div className="recent-account-time">{formatAgo(account.last_seen)}</div>
          <ChevronRight size={14} />
        </Link>)}</div>
      </Panel>

      <Panel title="Control" action={<Link className="text-link" to="/system">详情<ArrowRight size={13} /></Link>}>
        <dl className="overview-runtime-list">
          <div><dt>状态</dt><dd><StatusPill tone="success" dot>可响应</StatusPill></dd></div>
          <div><dt>运行时间</dt><dd>{formatDuration(runtime.data.uptime_seconds)}</dd></div>
          <div><dt>版本</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>提交</dt><dd className="mono">{runtime.data.build_commit.slice(0, 10)}</dd></div>
          <div><dt>启动时间</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>快照</dt><dd>{formatAgo(overview.data.generated_at)}</dd></div>
        </dl>
      </Panel>
    </section>

    <div className="overview-footnote">
      <Gauge size={14} />
      <span>Control 在线、Relay RTT、路径状态均不单独证明业务端口端到端可达。</span>
      <Link to="/connections">查看连接路径</Link>
    </div>
  </div>
}
