import { useQuery } from '@tanstack/react-query'
import { CircleAlert, Server } from 'lucide-react'
import { adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { tr } from '../../i18n'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { ErrorBlock, Panel, PendingBlock, formatDate, formatDuration } from '../../shared/console'
export function SystemPage() {
  const refreshInterval = useAutoRefresh()
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const overview = useQuery({ queryKey: ['overview'], queryFn: ({ signal }) => adminApi.overview(signal), refetchInterval: refreshInterval })
  if (runtime.isPending || overview.isPending) return <PendingBlock queries={[runtime, overview]} />
  const error = runtime.error || overview.error
  if (error && (!overview.data || !runtime.data)) return <ErrorBlock error={error} />
  if (!runtime.data || !overview.data) return <ErrorBlock error={new Error('控制面未返回完整的运行状态快照。')} />
  return <div className="page-stack">
    <PageHeader title={tr("控制面运行健康")} description={<> {tr("这里只展示控制面进程与数据库能直接确认的事实；Relay TLS、systemd、SQLite 完整性和备份请在部署主机运行 ")}<code>{tr("p2wlan-server doctor")}</code>{tr("。")} </>} actions={<><span className={`badge ${!refreshInterval || runtime.fetchStatus === 'paused' || runtime.error ? 'warning' : 'success'} large`}><span />{tr(!refreshInterval || runtime.fetchStatus === 'paused' || runtime.error ? '缓存快照' : '运行中')}</span></>} />
    <QueryStatus queries={[runtime, overview]} />
    <section className="system-grid">
      <Panel title={tr("进程")} subtitle={tr("构建与启动信息")}>
        <div className="system-hero"><div className="system-hero-icon"><Server size={26} /></div><div><span>{tr("UPTIME")}</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list">
          <div><dt>{tr("构建版本")}</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>{tr("源码提交")}</dt><dd className="mono">{runtime.data.build_commit}</dd></div>
          <div><dt>{tr("启动时间")}</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>{tr("管理权限")}</dt><dd>{tr("read-only")}</dd></div>
        </dl>
      </Panel>
      <Panel title={tr("控制面状态")} subtitle={tr("不是业务数据面吞吐")}>
        <div className="system-metrics"><div><span>{tr("待处理信令")}</span><strong>{overview.data.pending_signals}</strong></div><div><span>{tr("活动隧道")}</span><strong>{overview.data.active_tunnels}</strong></div><div><span>{tr("在线设备")}</span><strong>{overview.data.online_devices}</strong></div><div><span>{tr("账号")}</span><strong>{overview.data.users}</strong></div></div>
        <div className="truth-notice system-notice"><CircleAlert size={15} /><span>{tr("控制面正常、设备在线和 Relay RTT 都不能单独证明真实 TUN 或应用流量已端到端可达。主机级部署问题请使用 p2wlan-server doctor 分层检查。")}</span></div>
      </Panel>
    </section>
  </div>
}
