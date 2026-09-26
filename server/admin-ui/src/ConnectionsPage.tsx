import { getLocale, tr } from './i18n'
import { createPortal } from 'react-dom'
import { lazy, useEffect, useMemo, useRef, useState } from 'react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowDownRight,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Clock3,
  Network,
  Search,
  Table2,
  Waypoints,
  X,
} from 'lucide-react'
import { Link, useSearchParams } from 'react-router-dom'
import { adminApi } from './api'
import { AsyncView } from './AsyncView'
import { lifecycleLabel, transitionReasonLabel } from './connectionLabels'
import { CONNECTION_PAGE_SIZE, lastAvailableConnectionPage, readConnectionSearch, selectConnectionSearch, updateConnectionSearch, type ConnectionIdentity } from './connectionNavigation'
import { QueryStatus, useAutoRefresh } from './refresh'
import { useOverlay } from './useOverlay'
import type { AdminConnection, AdminConnectionTransition } from './types'

const PAGE_SIZE = CONNECTION_PAGE_SIZE
const TOPOLOGY_LIMIT = 100
const HISTORY_LIMIT = 50
const ConnectionTopology = lazy(() => import('./ConnectionTopology').then((module) => ({ default: module.ConnectionTopology })))

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
  if (seconds < 86400 * 30) {
    const count = Math.floor(seconds / 86400)
    return locale === 'zh-CN' ? `${count} 天前` : `${count} days ago`
  }
  return new Intl.DateTimeFormat(locale, { year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(unix * 1000))
}

function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat(getLocale(), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(unix * 1000))
}

function formatMilliseconds(value?: number): string {
  if (value === undefined) return '—'
  if (value < 1000) return `${value} ms`
  const seconds = Math.round(value / 100) / 10
  if (seconds < 60) return getLocale() === 'zh-CN' ? `${seconds} 秒` : `${seconds} s`
  const minutes = Math.round(seconds / 6) / 10
  return getLocale() === 'zh-CN' ? `${minutes} 分钟` : `${minutes} min`
}

function pathLabel(path?: string | null): string {
  if (!path) return tr('None')
  if (path === 'direct') return tr('Direct')
  if (path === 'relay') return tr('Relay')
  return tr(path.replaceAll('_', ' '))
}

function reasonLabel(reason: string): string {
  return transitionReasonLabel(reason, getLocale())
}

function PathBadge({ connection }: { connection: AdminConnection }) {
  const path = connection.current_path || 'none'
  return <span className={`connection-path-badge ${path} ${connection.fresh ? '' : 'stale'}`}>
    <span />{pathLabel(connection.current_path)}
  </span>
}

function FreshnessBadge({ connection }: { connection: AdminConnection }) {
  const label = connection.fresh ? tr('Fresh') : connection.freshness === 'reporter_offline' ? tr('Reporter offline') : tr('Stale')
  return <span className={`connection-freshness ${connection.fresh ? 'fresh' : 'stale'}`}>{label}</span>
}

function ConnectionDirection({ connection }: { connection: AdminConnection }) {
  return <div className="connection-direction-cell">
    <div>
      <strong title={connection.reporting_device_name}>{connection.reporting_device_name}</strong>
      <span>{connection.reporting_username}</span>
    </div>
    <ArrowDownRight size={15} aria-hidden />
    <div>
      <strong title={connection.remote_device_name}>{connection.remote_device_name}</strong>
      <span>{connection.remote_username}</span>
    </div>
  </div>
}

function ConnectionMobileCard({ connection, onSelect }: {
  connection: AdminConnection
  onSelect: (connection: AdminConnection) => void
}) {
  return <button
    type="button"
    className="connection-mobile-card"
    aria-label={getLocale() === 'zh-CN'
      ? `查看 ${connection.reporting_device_name} 到 ${connection.remote_device_name} 的连接详情`
      : `View connection details from ${connection.reporting_device_name} to ${connection.remote_device_name}`}
    onClick={() => onSelect(connection)}
  >
    <span className="connection-mobile-direction">
      <span><strong>{connection.reporting_device_name}</strong><small>{connection.reporting_username}</small></span>
      <ArrowDownRight size={16} aria-hidden />
      <span><strong>{connection.remote_device_name}</strong><small>{connection.remote_username}</small></span>
    </span>
    <span className="connection-mobile-context">
      <strong>{connection.network_name}</strong>
      <span><PathBadge connection={connection} /><FreshnessBadge connection={connection} /></span>
    </span>
    <span className="connection-mobile-facts">
      <span><small>{tr("验证 RTT")}</small><strong>{connection.last_validation_rtt_ms === undefined ? '—' : `${connection.last_validation_rtt_ms} ms`}</strong></span>
      <span><small>{tr("Path age")}</small><strong>{formatMilliseconds(connection.path_age_ms)}</strong></span>
      <span><small>{tr("最后观测")}</small><strong>{formatAgo(connection.received_at)}</strong></span>
      <span><small>{tr("最近原因")}</small><strong title={connection.transition_reason}>{reasonLabel(connection.transition_reason)}</strong></span>
    </span>
    <ChevronRight className="connection-mobile-chevron" size={16} aria-hidden />
  </button>
}

function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block"><div className="spinner" />{tr(label)}</div>
}

function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>{tr("无法加载数据")}</strong><span>{tr(message)}</span></div></div>
}

function TransitionRow({ transition }: { transition: AdminConnectionTransition }) {
  return <div className="connection-transition-row">
    <span className="connection-transition-dot" />
    <div className="connection-transition-main">
      <strong>{pathLabel(transition.previous_path)} {tr("→ ")}{pathLabel(transition.current_path)}</strong>
      <span title={transition.transition_reason}>{reasonLabel(transition.transition_reason)}</span>
    </div>
    <div className="connection-transition-meta">
      <span>{formatDate(transition.created_at)}</span>
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
  const dialogRef = useRef<HTMLElement>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  useOverlay(true, onClose)

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement || document.activeElement instanceof SVGElement ? document.activeElement : null
    const focusFrame = window.requestAnimationFrame(() => closeButtonRef.current?.focus())
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
      )
      if (!focusable?.length) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      window.cancelAnimationFrame(focusFrame)
      window.removeEventListener('keydown', handleKeyDown)
      if (previousFocus?.isConnected) previousFocus.focus()
    }
  }, [])

  const transitions = history.data?.items ?? []

  return createPortal(<div className="connection-drawer-layer">
    <button type="button" className="connection-drawer-backdrop" onClick={onClose} aria-label={tr('关闭连接详情')} />
    <aside
      ref={dialogRef}
      className="connection-drawer"
      role="dialog"
      aria-modal="true"
      aria-labelledby="connection-drawer-title"
    >
    <header className="connection-drawer-head">
      <div>
        <span>{tr("Directional connection")}</span>
        <h2 id="connection-drawer-title">{identity.reporting_device_name || identity.reporting_device_id} → {identity.remote_device_name || identity.remote_device_id}</h2>
        <p>{identity.network_name || identity.network_id}</p>
      </div>
      <button ref={closeButtonRef} className="icon-button-v2" onClick={onClose} aria-label={tr("关闭连接详情")}><X size={17} /></button>
    </header>

    <QueryStatus queries={[exact, history]} />
    <section className="connection-drawer-section">
      {!current ? exact.isPending
        ? exact.fetchStatus === 'paused' ? null : <LoadingBlock label={tr('正在读取连接的最新状态…')} />
        : exact.isError ? <ErrorBlock error={exact.error} />
          : <div className="connection-empty-inline" role="status">{tr('该连接观测已不存在，请关闭详情并刷新列表。')}</div>
        : <><div className="connection-state-hero">
        <PathBadge connection={current} />
        <FreshnessBadge connection={current} />
      </div>
      {!current.fresh && <div className="connection-stale-note">
        {tr("这是守护进程最后一次权威上报的路径，不代表当前仍处于活动连接。")}</div>}
      <dl className="connection-detail-list">
        <div><dt>{tr("From")}</dt><dd><Link to={`/connections?${new URLSearchParams({ device_id: current.reporting_device_id })}`} onClick={onClose}>{current.reporting_device_name}</Link><small><Link to={`/accounts/${encodeURIComponent(current.reporting_user_id)}`} onClick={onClose}>{current.reporting_username}</Link></small></dd></div>
        <div><dt>{tr("To")}</dt><dd><Link to={`/connections?${new URLSearchParams({ device_id: current.remote_device_id })}`} onClick={onClose}>{current.remote_device_name}</Link><small><Link to={`/accounts/${encodeURIComponent(current.remote_user_id)}`} onClick={onClose}>{current.remote_username}</Link></small></dd></div>
        <div><dt>{tr("Network")}</dt><dd><Link to={`/relationships?${new URLSearchParams({ network_id: current.network_id === 'default' ? `personal:${current.reporting_user_id}` : current.network_id, account_id: current.reporting_user_id })}`} onClick={onClose}>{current.network_name}</Link></dd></div>
        <div><dt>{tr("验证 RTT")}</dt><dd>{current.last_validation_rtt_ms === undefined ? '—' : `${current.last_validation_rtt_ms} ms`}</dd></div>
        <div><dt>{tr("Path age")}</dt><dd>{formatMilliseconds(current.path_age_ms)}</dd></div>
        <div><dt>{tr("Last observed")}</dt><dd>{formatAgo(current.received_at)}</dd></div>
        <div><dt>{tr("Lifecycle")}</dt><dd title={current.lifecycle}>{lifecycleLabel(current.lifecycle, getLocale())}</dd></div>
        <div><dt>{tr("Previous path")}</dt><dd>{pathLabel(current.previous_path)}</dd></div>
        <div><dt>{tr("Reason")}</dt><dd title={current.transition_reason}>{reasonLabel(current.transition_reason)}</dd></div>
        {current.selected_path_mtu !== undefined && <div><dt>{tr("Path MTU")}</dt><dd>{current.selected_path_mtu}</dd></div>}
        {current.last_handshake_age_ms !== undefined && <div><dt>{tr("Handshake age")}</dt><dd>{formatMilliseconds(current.last_handshake_age_ms)}</dd></div>}
      </dl>
      </>}
      {!exact.isPending && !current && exact.fetchStatus !== 'paused' && <button type="button" className="button secondary compact" onClick={() => void exact.refetch()} disabled={exact.isFetching}>{tr('重试')}</button>}
    </section>

    <section className="connection-drawer-section timeline-section">
      <div className="connection-section-title"><div><Clock3 size={15} /><strong>{tr("切换历史")}</strong></div><span>{tr("仅当前方向")}</span></div>
      {!history.data && history.isPending ? history.fetchStatus === 'paused' ? null : <LoadingBlock label={tr("正在读取迁移历史…")} /> : !history.data && history.error ? <ErrorBlock error={history.error} /> : transitions.length === 0
        ? <div className="connection-empty-inline">{tr("暂无迁移记录。")}</div>
        : <div className="connection-timeline">{transitions.map((transition) => <TransitionRow key={transition.id} transition={transition} />)}</div>}
      <p className="connection-empty-inline">{tr('仅展示此方向最近保留的最多 50 条切换记录。')}</p>
    </section>
    </aside>
  </div>, document.body)
}

export function ConnectionsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { view, query: committedQuery, networkId, accountId, deviceId, path, freshness, page, showStale: showStaleTopology, selected } = readConnectionSearch(searchParams)
  const [query, setQuery] = useState(committedQuery)
  const offset = (page - 1) * PAGE_SIZE
  const tableRefreshInterval = useAutoRefresh()
  const topologyRefreshInterval = useAutoRefresh(10_000)

  // The URL owns committed filters; local text is only the debounce draft.
  // Back/forward navigation replaces the draft before it can overwrite the URL.
  useEffect(() => setQuery(committedQuery), [committedQuery, searchParams])

  useEffect(() => {
    if (query.trim() === committedQuery) return
    const timer = window.setTimeout(() => {
      setSearchParams((current) => selectConnectionSearch(updateConnectionSearch(current, { q: query.trim(), page: null }), null), { replace: true })
    }, 250)
    return () => window.clearTimeout(timer)
  }, [query, committedQuery, setSearchParams])

  const changeFilter = (changes: Record<string, string | null>) => {
    setSearchParams((current) => selectConnectionSearch(updateConnectionSearch(current, { q: query.trim(), page: null, ...changes }), null))
  }
  const selectConnection = (connection: ConnectionIdentity | null) => {
    setSearchParams((current) => selectConnectionSearch(current, connection), { replace: !connection })
  }

  const networks = useInfiniteQuery({
    queryKey: ['connections', 'networks'],
    queryFn: ({ pageParam, signal }) => adminApi.networks(100, pageParam, signal),
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

  const result = useQuery({
    queryKey: ['connections', 'table', committedQuery, networkId, accountId, deviceId, path, freshness, offset],
    queryFn: ({ signal }) => adminApi.connections({
      query: committedQuery,
      networkId,
      accountId,
      deviceId,
      path,
      freshness,
    }, PAGE_SIZE, offset, signal),
    enabled: view === 'table',
    refetchInterval: tableRefreshInterval,
  })

  const topology = useQuery({
    queryKey: ['connections', 'topology', committedQuery, networkId, accountId, deviceId, path, showStaleTopology],
    queryFn: ({ signal }) => adminApi.connections({
      query: committedQuery,
      networkId,
      accountId,
      deviceId,
      path,
      freshness: showStaleTopology ? '' : 'fresh',
    }, TOPOLOGY_LIMIT, 0, signal),
    enabled: view === 'topology' && Boolean(networkId),
    refetchInterval: topologyRefreshInterval,
  })

  const availablePage = result.data ? lastAvailableConnectionPage(page, result.data.total) : page
  const correctingPage = view === 'table' && result.isSuccess && availablePage !== page
  useEffect(() => {
    if (correctingPage) setSearchParams((current) => updateConnectionSearch(current, { page: String(availablePage) }), { replace: true })
  }, [correctingPage, availablePage, setSearchParams])

  const selectedNetwork = networkItems.find((network) => network.id === networkId)
  const activeItems = (view === 'table' ? result.data?.items : topology.data?.items) ?? []
  const accountConnection = activeItems.find((connection) => connection.reporting_user_id === accountId || connection.remote_user_id === accountId)
  const accountName = accountConnection?.reporting_user_id === accountId ? accountConnection.reporting_username : accountConnection?.remote_username
  const deviceConnection = activeItems.find((connection) => connection.reporting_device_id === deviceId || connection.remote_device_id === deviceId)
  const deviceName = deviceConnection?.reporting_device_id === deviceId ? deviceConnection.reporting_device_name : deviceConnection?.remote_device_name

  const columns = useMemo<ColumnDef<AdminConnection, unknown>[]>(() => [
    { id: 'direction', header: '方向', cell: ({ row }) => <ConnectionDirection connection={row.original} /> },
    { id: 'network', header: 'Network', cell: ({ row }) => <div className="primary-secondary"><strong title={row.original.network_name}>{row.original.network_name}</strong><span className="mono" title={row.original.network_id}>{row.original.network_id}</span></div> },
    { id: 'path', header: '路径', cell: ({ row }) => <PathBadge connection={row.original} /> },
    { id: 'fresh', header: 'Status', cell: ({ row }) => <FreshnessBadge connection={row.original} /> },
    { id: 'rtt', header: 'RTT', cell: ({ row }) => row.original.last_validation_rtt_ms === undefined ? '—' : `${row.original.last_validation_rtt_ms} ms` },
    { id: 'age', header: 'Age', cell: ({ row }) => <span title={formatMilliseconds(row.original.path_age_ms)}>{formatMilliseconds(row.original.path_age_ms)}</span> },
    { id: 'reason', header: '原因', cell: ({ row }) => <span className="connection-reason" title={reasonLabel(row.original.transition_reason)}>{reasonLabel(row.original.transition_reason)}</span> },
    { id: 'observed', header: 'Observed', cell: ({ row }) => formatAgo(row.original.received_at) },
  ], [])

  const table = useReactTable({
    data: result.data?.items ?? [],
    columns,
    getRowId: (connection) => `${connection.network_id}:${connection.reporting_device_id}:${connection.remote_device_id}`,
    getCoreRowModel: getCoreRowModel(),
  })

  return <div className="page-stack connections-page">
    <div className="page-intro connections-intro">
      <div><h2>{tr("Connections")}</h2><p>{tr("路径只来自守护进程已提交的权威单向观测。“新鲜”表示观测仍在有效租约内，不代表目标应用一定可达。")}</p></div>
      <div className="connections-intro-actions">
        <Link className="button secondary compact" to={`/health?${new URLSearchParams({ network_id: networkId, account_id: accountId, device_id: deviceId })}`}><AlertTriangle size={15} />{tr("Needs attention")}</Link>
        <div className="connections-view-switch" role="group" aria-label={tr("连接视图")}>
          <button className={view === 'table' ? 'active' : ''} aria-pressed={view === 'table'} onClick={() => setSearchParams((current) => updateConnectionSearch(current, { view: 'table' }))}><Table2 size={15} />{tr("列表")}</button>
          <button className={view === 'topology' ? 'active' : ''} aria-pressed={view === 'topology'} onClick={() => setSearchParams((current) => updateConnectionSearch(current, { view: 'topology' }))}><Waypoints size={15} />{tr("Live topology")}</button>
        </div>
      </div>
    </div>

    <div className="connections-toolbar">
      <label className="search-field connections-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={tr("搜索设备、账号或网络")} aria-label={tr("搜索连接")} /></label>
      <select className="select-field" value={networkId} onChange={(event) => changeFilter({ network_id: event.target.value })} aria-label={tr("按网络过滤")}>
        <option value="">{tr("全部网络")}</option>
        {networkId && !selectedNetwork && <option value={networkId}>{networkId}</option>}
        {networkItems.map((network) => <option key={network.id} value={network.id}>{network.name}</option>)}
      </select>
      <select className="select-field" value={path} onChange={(event) => changeFilter({ path: event.target.value })} aria-label={tr("按路径过滤")}>
        <option value="">{tr("全部路径")}</option>
        <option value="direct">{tr("Direct")}</option>
        <option value="relay">{tr("Relay")}</option>
        <option value="none">{tr("None")}</option>
      </select>
      {view === 'table' && <select className="select-field" value={freshness} onChange={(event) => changeFilter({ freshness: event.target.value })} aria-label={tr("按观测新鲜度过滤")}>
        <option value="">{tr("全部观测")}</option>
        <option value="fresh">{tr("Fresh")}</option>
        <option value="stale">{tr("Stale / reporter offline")}</option>
      </select>}
      {networks.hasNextPage && <button
        className="button secondary compact"
        onClick={() => networks.fetchNextPage()}
        disabled={networks.isFetchingNextPage}
      >{networks.isFetchingNextPage ? tr('加载中…') : tr('加载更多网络')}</button>}
    </div>

    {(accountId || deviceId) && <div className="connection-scope-chips" aria-label={tr('连接筛选范围')}>
      {accountId && <button type="button" className="connection-scope-chip" onClick={() => changeFilter({ account_id: null, user_id: null })} aria-label={`${tr('清除账号范围')}: ${accountName || accountId}`}><span>{tr('账号')} · {accountName || accountId}</span><X size={13} aria-hidden /></button>}
      {deviceId && <button type="button" className="connection-scope-chip" onClick={() => changeFilter({ device_id: null })} aria-label={`${tr('清除设备范围')}: ${deviceName || deviceId}`}><span>{tr('设备')} · {deviceName || deviceId}</span><X size={13} aria-hidden /></button>}
    </div>}
    <QueryStatus queries={view === 'table' ? [result, networks] : networkId ? [topology, networks] : [networks]} />

    {view === 'table' ? <section className="panel-v2 connections-panel">
      {correctingPage ? <LoadingBlock label={tr('正在调整分页…')} /> : result.data ? <>
        <div className="data-table-wrap"><table className="data-table connections-table">
          <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
            const heading = header.column.columnDef.header
            return <th key={header.id}>{header.isPlaceholder ? null : typeof heading === 'string' ? tr(heading) : flexRender(heading, header.getContext())}</th>
          })}</tr>)}</thead>
          <tbody>
            {table.getRowModel().rows.map((row) => <tr key={row.id} className="clickable" tabIndex={0} aria-label={`${tr('连接详情')}: ${row.original.reporting_device_name} → ${row.original.remote_device_name}`} onClick={() => selectConnection(row.original)} onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault()
                selectConnection(row.original)
              }
            }}>
              {row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}
            </tr>)}
            {table.getRowModel().rows.length === 0 && <tr><td className="table-empty" colSpan={columns.length}>{tr("当前筛选条件下没有符合条件的权威路径观测。")}</td></tr>}
          </tbody>
        </table></div>
        <div className="connection-mobile-list">
          {result.data.items.map((connection) => <ConnectionMobileCard
            key={`${connection.network_id}:${connection.reporting_device_id}:${connection.remote_device_id}`}
            connection={connection}
            onSelect={selectConnection}
          />)}
          {result.data.items.length === 0 && <div className="connection-mobile-empty">{tr("当前筛选条件下没有符合条件的权威路径观测。")}</div>}
        </div>
        <div className="pagination-v2"><span>{result.data.items.length === 0 ? 0 : offset + 1}{tr("–")}{result.data.items.length === 0 ? 0 : Math.min(result.data.total, offset + result.data.items.length)} {tr("/ ")}{result.data.total}</span><div>
          <button className="button secondary compact" disabled={offset === 0 || query.trim() !== committedQuery} onClick={() => setSearchParams((current) => updateConnectionSearch(current, { page: String(page - 1) }))}><ChevronLeft size={15} />{tr("上一页")}</button>
          <button className="button secondary compact" disabled={offset + PAGE_SIZE >= result.data.total || query.trim() !== committedQuery} onClick={() => setSearchParams((current) => updateConnectionSearch(current, { page: String(page + 1) }))}>{tr("下一页")}<ChevronRight size={15} /></button>
        </div></div>
      </> : result.fetchStatus === 'paused' ? null : result.isPending ? <LoadingBlock label={tr("正在读取连接观测…")} /> : result.error ? <ErrorBlock error={result.error} /> : <ErrorBlock error={new Error('控制面未返回连接列表。')} />}
    </section> : <section className="panel-v2 connections-panel topology-mode">
      {!networkId ? <div className="connection-topology-empty choose-network">
        <Network size={20} />
        <div><strong>{tr("选择一个网络查看实时拓扑")}</strong><span>{tr("拓扑不会跨网络拼接，也不会根据成员关系、信令或 RTT 推断连接。")}</span></div>
      </div> : topology.data ? <>
        {topology.data.total > topology.data.items.length && <div className="connection-partial-warning"><CircleAlert size={15} />{tr("当前网络共有 ")}{topology.data.total} {tr("条匹配观测，拓扑仅展示前 ")}{topology.data.items.length} {tr("条；请收紧搜索或路径过滤。")}</div>}
        <AsyncView><ConnectionTopology
          connections={topology.data.items}
          networkName={selectedNetwork?.name ?? networkId}
          showStale={showStaleTopology}
          partial={topology.data.total > topology.data.items.length}
          onShowStaleChange={(value) => setSearchParams((current) => updateConnectionSearch(current, { show_stale: value ? '1' : null }))}
          onSelect={selectConnection}
        /></AsyncView>
      </> : topology.fetchStatus === 'paused' ? null : topology.isPending ? <LoadingBlock label={tr("正在读取权威连接拓扑…")} /> : topology.error ? <ErrorBlock error={topology.error} /> : <ErrorBlock error={new Error('控制面未返回连接拓扑。')} />}
    </section>}

    {selected && <ConnectionDrawer key={`${selected.network_id}:${selected.reporting_device_id}:${selected.remote_device_id}`} connection={selected} onClose={() => selectConnection(null)} />}
  </div>
}
