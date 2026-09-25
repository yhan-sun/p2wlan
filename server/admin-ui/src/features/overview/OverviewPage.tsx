import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  ArrowRight,
  CircleAlert,
  ChevronRight,
  CircleCheck,
  Clock3,
  Gauge,
  MonitorSmartphone,
  Network,
  RadioTower,
  Server,
  Users,
  Waypoints,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { adminApi } from '../../api'
import { MetricCard, Panel } from '../../components/ui/console'
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

  return <div className="page-stack">
    <section className="overview-hero">
      <div className="overview-hero-copy">
        <div className="overview-kicker">
          <span className="live-label">控制平面在线</span>
          <span className="mono">{runtime.data.build_version}</span>
        </div>
        <h2>从控制面到真实路径，<br />一眼看清。</h2>
        <p>集中查看设备、连接路径、信令与运行事实。资源关系与 daemon 权威路径继续分层呈现，不用一个“健康分”掩盖真实状态。</p>
        <div className="overview-hero-actions">
          <Link className="button primary" to="/connections">查看连接路径<ArrowRight size={15} /></Link>
          <Link className="button secondary" to="/relationships">打开资源拓扑</Link>
        </div>
      </div>
      <div className="overview-snapshot">
        <div><span>在线设备</span><strong>{overview.data.online_devices}/{overview.data.devices}</strong><small>{offlineDevices ? `${offlineDevices} 台离线` : '当前全部在线'}</small></div>
        <div><span>新鲜直连</span><strong>{connectionHealth.data?.summary.fresh_direct ?? '—'}</strong><small>最近 1 小时观测</small></div>
        <div><span>新鲜中继</span><strong>{connectionHealth.data?.summary.fresh_relay ?? '—'}</strong><small>最近 1 小时观测</small></div>
        <div><span>快照</span><strong>{formatAgo(overview.data.generated_at)}</strong><small>Control 快照</small></div>
      </div>
    </section>

    <section className="metrics-grid-v2">
      <MetricCard icon={<Users size={18} />} label="账号" value={overview.data.users} meta="Control 中的非系统账号" />
      <MetricCard icon={<MonitorSmartphone size={18} />} label="设备在线" value={<>{overview.data.online_devices}/{overview.data.devices}</>} meta={offlineDevices ? <>{offlineDevices} 台离线</> : '全部设备在线'} />
      <MetricCard icon={<Network size={18} />} label="网络" value={overview.data.networks} meta={<>{overview.data.rooms} 个房间网络</>} />
      <MetricCard icon={<Activity size={18} />} label="待处理信令" value={overview.data.pending_signals} meta={<>{overview.data.active_tunnels} 个 Control 活动隧道</>} />
    </section>

    {connectionHealth.isPending
      ? <section className="dashboard-health-strip"><div className="dashboard-health-title"><span><Gauge size={16} /></span><div><strong>连接健康</strong><small>正在聚合最近 1 小时的路径信号…</small></div></div></section>
      : connectionHealth.error
        ? <section className="dashboard-health-strip"><div className="dashboard-health-title"><span><CircleAlert size={16} /></span><div><strong>连接健康暂不可用</strong><small>{connectionHealth.error instanceof Error ? connectionHealth.error.message : '读取失败'}</small></div></div><Link to="/health">打开工作区<ArrowRight size={14} /></Link></section>
        : connectionHealth.data && <section className="dashboard-health-strip">
          <div className="dashboard-health-title"><span><Gauge size={16} /></span><div><strong>连接健康 · 1h</strong><small>派生信号，不是综合健康分</small></div></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.alerts_total}</strong><span>需要关注</span></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.summary.fresh_direct}</strong><span>新鲜直连</span></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.summary.fresh_relay}</strong><span>新鲜中继</span></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.summary.recent_path_switches}</strong><span>路径切换</span></div>
          <Link to="/health">查看连接健康<ArrowRight size={14} /></Link>
        </section>}

    <section className="dashboard-grid operations-grid">
      <Panel className="health-card" title="Control 运行健康" subtitle="这里只展示 Control 能直接确认的事实" action={<span className="badge success"><span />可响应</span>}>
        <div className="health-runtime-big"><div className="health-runtime-icon"><Server size={22} /></div><div><span>运行时间</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list compact">
          <div><dt>版本</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>提交</dt><dd className="mono">{runtime.data.build_commit.slice(0, 10)}</dd></div>
          <div><dt>启动时间</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>管理权限</dt><dd>只读</dd></div>
        </dl>
        <Link className="text-link panel-footer-link" to="/system">查看运行健康<ArrowRight size={14} /></Link>
      </Panel>

      <Panel title="需要关注" subtitle="按当前 Control 快照生成，不推断真实数据面故障">
        <div className="attention-list">
          {offlineDevices > 0
            ? <div className="attention-item warning"><CircleAlert size={17} /><div><strong>{offlineDevices} 台设备当前离线</strong><span>可到设备页按在线状态筛选，结合最后活动时间排查。</span></div><Link to="/devices">查看</Link></div>
            : <div className="attention-item success"><CircleCheck size={17} /><div><strong>设备在线状态正常</strong><span>当前快照中没有离线设备。</span></div></div>}
          {overview.data.pending_signals > 0
            ? <div className="attention-item warning"><RadioTower size={17} /><div><strong>{overview.data.pending_signals} 条待处理信令</strong><span>这是控制面协调状态，不代表 Relay 或 Direct 数据路径。</span></div><Link to="/relationships">查看关系</Link></div>
            : <div className="attention-item success"><CircleCheck size={17} /><div><strong>没有待处理信令</strong><span>Control 当前未记录积压的协调消息。</span></div></div>}
          <div className="attention-item neutral"><Waypoints size={17} /><div><strong>权威路径与资源关系已分离</strong><span>连接路径只读取 daemon 已提交的权威观测；资源关系仍只表达成员关系与设备挂载。</span></div><Link to="/connections">查看连接</Link></div>
        </div>
      </Panel>
    </section>

    <section className="dashboard-lower-grid">
      <Panel title="最近账号" subtitle="按设备最后活动时间排序" action={<Link className="text-link" to="/accounts">全部账号<ArrowRight size={14} /></Link>}>
        <div className="recent-account-list">{accounts.data.items.map((account) => <Link className="recent-account-row" to={'/accounts/' + encodeURIComponent(account.id)} key={account.id}>
          <AccountMark account={account} />
          <div className="recent-account-main"><strong>{account.username}</strong><span>{account.email}</span></div>
          <div className="recent-account-stat"><strong>{account.online_devices}/{account.device_count}</strong><span>在线设备</span></div>
          <div className="recent-account-stat"><strong>{account.network_count}</strong><span>网络</span></div>
          <div className="recent-account-time">{formatAgo(account.last_seen)}</div>
          <ChevronRight size={15} />
        </Link>)}</div>
      </Panel>
      <Panel title="控制面摘要" subtitle="计数不等于端到端业务可达">
        <div className="control-summary-grid">
          <div><span className="summary-icon"><Activity size={17} /></span><strong>{overview.data.pending_signals}</strong><small>待处理信令</small></div>
          <div><span className="summary-icon"><Waypoints size={17} /></span><strong>{overview.data.active_tunnels}</strong><small>活动隧道</small></div>
          <div><span className="summary-icon"><RadioTower size={17} /></span><strong>{overview.data.rooms}</strong><small>房间</small></div>
          <div><span className="summary-icon"><Clock3 size={17} /></span><strong>{formatAgo(overview.data.generated_at)}</strong><small>快照时间</small></div>
        </div>
      </Panel>
    </section>
  </div>
}
