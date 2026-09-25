import { useQuery } from '@tanstack/react-query'
import { CircleAlert, Server } from 'lucide-react'
import { adminApi } from '../../api'
import { PageHeader, Panel, StatusPill } from '../../components/ui/console'
import { ErrorBlock, PendingBlock, formatDate, formatDuration } from '../../shared/console'

export function SystemPage() {
  const runtime = useQuery({ queryKey: ['runtime-system'], queryFn: adminApi.runtime, refetchInterval: 15_000 })
  const overview = useQuery({ queryKey: ['overview-system'], queryFn: adminApi.overview, refetchInterval: 15_000 })
  if (runtime.isPending || overview.isPending) return <PendingBlock queries={[runtime, overview]} />
  const error = runtime.error || overview.error
  if (error) return <ErrorBlock error={error} />
  if (!runtime.data || !overview.data) return <ErrorBlock error={new Error('Control 未返回完整的运行状态快照。')} />
  return <div className="page-stack">
    <PageHeader
      eyebrow="RUNTIME"
      title="Control 运行健康"
      description={<>这里只展示 Control 进程与数据库能直接确认的事实；Relay TLS、systemd、SQLite 完整性和备份请在部署主机运行 <code>p2wlan-server doctor</code>。</>}
      actions={<StatusPill tone="success" dot>运行中</StatusPill>}
    />
    <section className="system-grid">
      <Panel title="进程" subtitle="构建与启动信息">
        <div className="system-hero"><div className="system-hero-icon"><Server size={26} /></div><div><span>UPTIME</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list">
          <div><dt>构建版本</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>源码提交</dt><dd className="mono">{runtime.data.build_commit}</dd></div>
          <div><dt>启动时间</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>管理权限</dt><dd>read-only</dd></div>
        </dl>
      </Panel>
      <Panel title="控制面状态" subtitle="不是业务数据面吞吐">
        <div className="system-metrics"><div><span>待处理信令</span><strong>{overview.data.pending_signals}</strong></div><div><span>活动隧道</span><strong>{overview.data.active_tunnels}</strong></div><div><span>在线设备</span><strong>{overview.data.online_devices}</strong></div><div><span>账号</span><strong>{overview.data.users}</strong></div></div>
        <div className="truth-notice system-notice"><CircleAlert size={15} /><span>Control healthy、设备 online、Relay RTT 都不能单独证明真实 TUN 或应用流量已经端到端可达。主机级部署问题使用 p2wlan-server doctor 分层检查。</span></div>
      </Panel>
    </section>
  </div>
}
