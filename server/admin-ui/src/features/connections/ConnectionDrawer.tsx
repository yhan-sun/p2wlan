import { useQuery } from '@tanstack/react-query'
import { Clock3, X } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Link, useLocation } from 'react-router-dom'
import { CopyValue } from '../../CopyValue'
import { adminApi } from '../../api'
import { getLocale, tr } from '../../i18n'
import { resourceOriginState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import type { AdminConnectionTransition } from '../../types'
import { useOverlay } from '../../useOverlay'
import { lifecycleLabel } from './connectionLabels'
import { connectionWorkspaceSearch, selectConnectionSearch, type ConnectionIdentity } from './connectionNavigation'
import { ErrorBlock, FreshnessBadge, LoadingBlock, PathBadge, formatAgo, formatDate, formatMilliseconds, pathLabel, reasonLabel } from './connectionPresentation'
import { trendWindowForTimestamp } from './trends'
import { useConnectionSearchParams } from './useConnectionSearch'

const HISTORY_LIMIT = 50

function TransitionRow({ transition }: { transition: AdminConnectionTransition }) {
  const [params] = useConnectionSearchParams()
  const { state: resourceOrigin } = useLocation()
  const trendScope = connectionWorkspaceSearch(params, 'trends')
  trendScope.set('network_id', transition.network_id)
  trendScope.set('trend_hour', String(Math.floor(transition.created_at / 3600) * 3600))
  trendScope.set('window_hours', String(trendWindowForTimestamp(transition.created_at)))
  return <div className="connection-transition-row">
    <span className="connection-transition-dot" />
    <div className="connection-transition-main">
      <strong>{pathLabel(transition.previous_path)} {tr("→ ")}{pathLabel(transition.current_path)}</strong>
      <span title={transition.transition_reason}>{reasonLabel(transition.transition_reason)}</span>
    </div>
    <div className="connection-transition-meta">
      <Link to={`/connections?${trendScope}`} state={resourceOrigin} title={tr('在网络趋势中查看此时段')}>{formatDate(transition.created_at)}</Link>
      {transition.selected_path_mtu !== undefined && <small>{tr("MTU ")}{transition.selected_path_mtu}</small>}
    </div>
  </div>
}

export function ConnectionDrawer({
  connection,
  onClose,
}: {
  connection: ConnectionIdentity
  onClose: () => void
}) {
  const [drawerParams, setDrawerParams] = useConnectionSearchParams()
  const location = useLocation()
  const resourceOrigin = location.state
  const nextOrigin = resourceOriginState(location)
  const deviceConnectionsHref = (deviceId: string) => {
    const next = selectConnectionSearch(drawerParams, null)
    next.set('device_id', deviceId)
    next.delete('page')
    next.delete('alert_page')
    return `${location.pathname}?${next}`
  }
  const refetchInterval = useAutoRefresh(10_000)
  const exact = useQuery({
    queryKey: ['connection', connection.network_id, connection.reporting_device_id, connection.remote_device_id],
    queryFn: ({ signal }) => adminApi.connections({
      networkId: connection.network_id,
      reportingDeviceId: connection.reporting_device_id,
      remoteDeviceId: connection.remote_device_id,
    }, 1, 0, signal),
    refetchInterval,
    refetchOnMount: 'always',
    staleTime: 0,
    gcTime: 0,
  })
  // Only this exact-direction query supplies path data. During an outage its
  // retained response is explicitly labelled as a cached snapshot by QueryStatus.
  const current = exact.data?.items[0]
  const reverse = useQuery({
    queryKey: ['connection', connection.network_id, connection.remote_device_id, connection.reporting_device_id],
    queryFn: ({ signal }) => adminApi.connections({
      networkId: connection.network_id,
      reportingDeviceId: connection.remote_device_id,
      remoteDeviceId: connection.reporting_device_id,
    }, 1, 0, signal),
    refetchInterval,
    refetchOnMount: 'always', staleTime: 0, gcTime: 0,
  })
  const reverseConnection = reverse.data?.items[0]
  const reverseDirection = () => setDrawerParams((params) => selectConnectionSearch(params, {
    network_id: connection.network_id,
    reporting_device_id: connection.remote_device_id,
    remote_device_id: connection.reporting_device_id,
  }))
  const graphScope = connectionWorkspaceSearch(drawerParams, 'topology')
  graphScope.set('network_id', connection.network_id)
  graphScope.set('detail', 'closed')
  const identity = current ?? connection
  const history = useQuery({
    queryKey: ['connection-transitions', connection.network_id, connection.reporting_device_id, connection.remote_device_id],
    queryFn: ({ signal }) => adminApi.connectionTransitions(
      connection.reporting_device_id,
      connection.remote_device_id,
      connection.network_id,
      HISTORY_LIMIT,
      '',
      signal,
    ),
    refetchInterval,
    staleTime: 0,
    gcTime: 0,
  })
  const previousRevision = useRef(current?.observation_revision)
  const refreshHistory = history.refetch
  useEffect(() => {
    const revision = current?.observation_revision
    if (revision !== undefined && previousRevision.current !== undefined && revision !== previousRevision.current) {
      void refreshHistory()
    }
    previousRevision.current = revision
  }, [current?.observation_revision, refreshHistory])
  const dialogRef = useRef<HTMLDialogElement>(null)
  useOverlay(true, onClose)

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    // The native modal owns focus containment, background inertness and restore.
    // useOverlay remains the sole Escape-stack and scroll-lock owner.
    dialog.showModal()
    return () => dialog.close()
  }, [])

  const transitions = history.data?.items ?? []

  return createPortal(<dialog
      ref={dialogRef}
      className="connection-drawer"
      aria-labelledby="connection-drawer-title"
      onCancel={(event) => { event.preventDefault(); onClose() }}
      onClick={(event) => {
        if (event.target !== event.currentTarget) return
        const bounds = event.currentTarget.getBoundingClientRect()
        if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) onClose()
      }}
    >
    <header className="connection-drawer-head">
      <div>
        <span>{tr("Directional connection")}</span>
        <h2 id="connection-drawer-title">{identity.reporting_device_name || identity.reporting_device_id} → {identity.remote_device_name || identity.remote_device_id}</h2>
        <p>{identity.network_name || identity.network_id}</p>
      </div>
      <button autoFocus className="icon-button-v2" onClick={onClose} aria-label={tr("关闭连接详情")}><X size={17} /></button>
    </header>

    <QueryStatus queries={[exact]} />
    <section className="connection-drawer-section">
      {!current ? exact.isPending
        ? exact.fetchStatus === 'paused' ? null : <LoadingBlock label={tr('正在读取连接的最新状态…')} />
        : exact.isError ? <ErrorBlock error={exact.error} />
          : <div className="connection-empty-inline" role="status">{tr('该连接观测已不存在，请关闭详情并刷新列表。')}</div>
        : <><div className="connection-state-hero">
        <div><PathBadge connection={current} /><FreshnessBadge connection={current} /></div>
        <Link className="button secondary compact" to={`/connections?${graphScope}`} state={resourceOrigin}>{tr('在拓扑中定位')}</Link>
      </div>
      <dl className="connection-detail-metrics">
        <div><dt>{tr('验证 RTT')}</dt><dd>{current.last_validation_rtt_ms === undefined ? '—' : `${current.last_validation_rtt_ms} ms`}</dd></div>
        <div><dt>{tr('Path age')}</dt><dd>{formatMilliseconds(current.path_age_ms)}</dd></div>
        <div><dt>{tr('Last observed')}</dt><dd>{formatAgo(current.received_at)}</dd></div>
      </dl>
      {!current.fresh && <div className="connection-stale-note">
        {tr("这是守护进程最后一次权威上报的路径，不代表当前仍处于活动连接。")}</div>}
      <h3 className="connection-detail-heading">{tr('双向观测对照')}</h3>
      <section className="connection-direction-comparison" aria-label={tr('双向观测对照')}>
        <div><strong>{tr('当前方向')}</strong><span>{current.reporting_device_name} → {current.remote_device_name}</span><span><PathBadge connection={current} /> <FreshnessBadge connection={current} /></span><small>{tr('恢复状态')}：{current.recovery_state || tr('未上报')}</small><small>{tr('服务端接收于')} {formatDate(current.received_at)}</small></div>
        <div><strong>{tr('反向观测')}</strong><span>{current.remote_device_name} → {current.reporting_device_name}</span>
          {reverseConnection ? <><span><PathBadge connection={reverseConnection} /> <FreshnessBadge connection={reverseConnection} /></span><small>{tr('恢复状态')}：{reverseConnection.recovery_state || tr('未上报')}</small><small>{tr('服务端接收于')} {formatDate(reverseConnection.received_at)}</small><button type="button" className="button secondary compact" onClick={reverseDirection}>{tr('查看反向详情')}</button></>
            : <span>{tr(reverse.fetchStatus === 'paused' ? '反向观测更新已暂停' : reverse.isPending ? '正在读取反向观测…' : reverse.error ? '无法读取反向观测' : '没有反向观测；不等同于路径断开。')}</span>}
        </div>
      </section>
      {(reverse.error || reverse.fetchStatus === 'paused') && <QueryStatus queries={[reverse]} />}
      <h3 className="connection-detail-heading">{tr('连接信息')}</h3>
      <dl className="connection-detail-list">
        <div><dt>{tr("From")}</dt><dd><Link to={deviceConnectionsHref(current.reporting_device_id)} state={nextOrigin}>{current.reporting_device_name}</Link><small><Link to={`/accounts/${encodeURIComponent(current.reporting_user_id)}`} state={nextOrigin}>{current.reporting_username}</Link></small></dd></div>
        <div><dt>{tr("To")}</dt><dd><Link to={deviceConnectionsHref(current.remote_device_id)} state={nextOrigin}>{current.remote_device_name}</Link><small><Link to={`/accounts/${encodeURIComponent(current.remote_user_id)}`} state={nextOrigin}>{current.remote_username}</Link></small></dd></div>
        <div><dt>{tr("Network")}</dt><dd><Link to={`/relationships?${new URLSearchParams({ network_id: current.network_id === 'default' ? `personal:${current.reporting_user_id}` : current.network_id, account_id: current.reporting_user_id })}`} state={nextOrigin}>{current.network_name}</Link></dd></div>
        <div><dt>{tr("Lifecycle")}</dt><dd title={current.lifecycle}>{lifecycleLabel(current.lifecycle, getLocale())}</dd></div>
        <div><dt>{tr("Previous path")}</dt><dd>{pathLabel(current.previous_path)}</dd></div>
        <div><dt>{tr("Reason")}</dt><dd title={current.transition_reason}>{reasonLabel(current.transition_reason)}</dd></div>
        {current.selected_path_mtu !== undefined && <div><dt>{tr("Path MTU")}</dt><dd>{current.selected_path_mtu}</dd></div>}
        {current.last_handshake_age_ms !== undefined && <div><dt>{tr("Handshake age")}</dt><dd>{formatMilliseconds(current.last_handshake_age_ms)}</dd></div>}
      </dl>
      <details className="connection-evidence"><summary>{tr('高级诊断证据')}</summary><dl className="connection-detail-list">
        <div><dt>{tr('Direct 状态')}</dt><dd>{current.direct_state || tr('未上报')}</dd></div>
        <div><dt>{tr('Relay 状态')}</dt><dd>{current.relay_state || tr('未上报')}</dd></div>
        <div><dt>{tr('恢复状态')}</dt><dd>{current.recovery_state || tr('未上报')}</dd></div>
        <div><dt>{tr('Relay 服务')}</dt><dd>{current.relay_server || tr('未上报')}</dd></div>
        <div><dt>{tr('UDP 数据报大小')}</dt><dd>{current.selected_udp_datagram_size ?? '—'}</dd></div>
        <div><dt>{tr('客户端观测时间')}</dt><dd>{formatDate(current.observed_at)}</dd></div>
        <div><dt>{tr('服务端接收时间')}</dt><dd>{formatDate(current.received_at)}</dd></div>
        <div><dt>{tr('观测版本')}</dt><dd>{current.observation_revision}</dd></div>
        <div><dt>{tr('上报设备 ID')}</dt><dd><code>{current.reporting_device_id}</code><CopyValue value={current.reporting_device_id} label="复制设备 ID" /></dd></div>
        <div><dt>{tr('远端设备 ID')}</dt><dd><code>{current.remote_device_id}</code><CopyValue value={current.remote_device_id} label="复制设备 ID" /></dd></div>
        <div><dt>{tr('原始原因')}</dt><dd><code>{current.transition_reason}</code></dd></div>
      </dl><p>{tr('两端时钟可能不同；这些时间不能直接相减作为网络延迟。')}</p></details>
      </>}
      {!exact.isPending && !current && exact.fetchStatus !== 'paused' && <button type="button" className="button secondary compact" onClick={() => void exact.refetch()} disabled={exact.isFetching}>{tr('重试')}</button>}
    </section>

    <section className="connection-drawer-section timeline-section">
      <div className="connection-section-title"><div><Clock3 size={15} /><strong>{tr("切换历史")}</strong></div><span>{tr("仅当前方向")}</span></div>
      <QueryStatus queries={[history]} />
      {!history.data && history.isPending ? history.fetchStatus === 'paused' ? null : <LoadingBlock label={tr("正在读取迁移历史…")} /> : !history.data && history.error ? <ErrorBlock error={history.error} /> : transitions.length === 0
        ? <div className="connection-empty-inline">{tr("暂无迁移记录。")}</div>
        : <div className="connection-timeline">{transitions.map((transition) => <TransitionRow key={transition.id} transition={transition} />)}</div>}
      <p className="connection-empty-inline">{tr('仅展示此方向最近保留的最多 50 条切换记录。')}</p>
    </section>
  </dialog>, document.body)
}
