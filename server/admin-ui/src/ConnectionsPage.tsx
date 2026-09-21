import { useEffect, useMemo, useState } from 'react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
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
import { adminApi } from './api'
import { ConnectionTopology } from './ConnectionTopology'
import type { AdminConnection, AdminConnectionTransition } from './types'

const PAGE_SIZE = 25
const TOPOLOGY_LIMIT = 100

function formatAgo(unix?: number): string {
  if (!unix) return '—'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  if (seconds < 45) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} 天前`
  return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(unix * 1000))
}

function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
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
  if (seconds < 60) return `${seconds} s`
  return `${Math.round(seconds / 6) / 10} min`
}

function pathLabel(path?: string | null): string {
  if (!path) return 'None'
  if (path === 'direct') return 'Direct'
  if (path === 'relay') return 'Relay'
  return path.replaceAll('_', ' ')
}

function reasonLabel(reason: string): string {
  if (!reason) return '—'
  const known: Record<string, string> = {
    initial: 'Initial observation',
    direct_committed: 'Direct committed',
    relay_peer_confirmed: 'Relay confirmed',
    direct_path_failed: 'Direct path failed',
    relay_path_failed: 'Relay path failed',
    network_generation_advanced: 'Network generation advanced',
  }
  return known[reason] ?? reason.replaceAll('_', ' ')
}

function PathBadge({ connection }: { connection: AdminConnection }) {
  const path = connection.current_path || 'none'
  return <span className={`connection-path-badge ${path} ${connection.fresh ? '' : 'stale'}`}>
    <span />{pathLabel(connection.current_path)}
  </span>
}

function FreshnessBadge({ connection }: { connection: AdminConnection }) {
  const label = connection.fresh ? 'Fresh' : connection.freshness === 'reporter_offline' ? 'Reporter offline' : 'Stale'
  return <span className={`connection-freshness ${connection.fresh ? 'fresh' : 'stale'}`}>{label}</span>
}

function ConnectionDirection({ connection }: { connection: AdminConnection }) {
  return <div className="connection-direction-cell">
    <div>
      <strong>{connection.reporting_device_name}</strong>
      <span>{connection.reporting_username}</span>
    </div>
    <ArrowDownRight size={15} aria-hidden />
    <div>
      <strong>{connection.remote_device_name}</strong>
      <span>{connection.remote_username}</span>
    </div>
  </div>
}

function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block"><div className="spinner" />{label}</div>
}

function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>无法加载数据</strong><span>{message}</span></div></div>
}

function TransitionRow({ transition }: { transition: AdminConnectionTransition }) {
  return <div className="connection-transition-row">
    <span className="connection-transition-dot" />
    <div className="connection-transition-main">
      <strong>{pathLabel(transition.previous_path)} → {pathLabel(transition.current_path)}</strong>
      <span title={transition.transition_reason}>{reasonLabel(transition.transition_reason)}</span>
    </div>
    <div className="connection-transition-meta">
      <span>{formatDate(transition.created_at)}</span>
      {transition.selected_path_mtu !== undefined && <small>MTU {transition.selected_path_mtu}</small>}
    </div>
  </div>
}

export function ConnectionDrawer({
  connection,
  onClose,
}: {
  connection: AdminConnection
  onClose: () => void
}) {
  const exact = useQuery({
    queryKey: ['connection', connection.network_id, connection.reporting_device_id, connection.remote_device_id],
    queryFn: () => adminApi.connections({
      networkId: connection.network_id,
      reportingDeviceId: connection.reporting_device_id,
      remoteDeviceId: connection.remote_device_id,
    }, 1, 0),
    refetchInterval: 10_000,
  })
  const current = exact.data?.items[0] ?? connection
  const history = useInfiniteQuery({
    queryKey: ['connection-transitions', current.network_id, current.reporting_device_id, current.remote_device_id],
    queryFn: ({ pageParam }) => adminApi.connectionTransitions(
      current.reporting_device_id,
      current.remote_device_id,
      current.network_id,
      20,
      pageParam,
    ),
    initialPageParam: '',
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
  })

  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [onClose])

  const transitions = history.data?.pages.flatMap((page) => page.items) ?? []

  return <aside className="connection-drawer" aria-label="连接详情">
    <header className="connection-drawer-head">
      <div>
        <span>Directional connection</span>
        <h2>{current.reporting_device_name} → {current.remote_device_name}</h2>
        <p>{current.network_name}</p>
      </div>
      <button className="icon-button-v2" onClick={onClose} aria-label="关闭连接详情"><X size={17} /></button>
    </header>

    <section className="connection-drawer-section">
      <div className="connection-state-hero">
        <PathBadge connection={current} />
        <FreshnessBadge connection={current} />
      </div>
      {!current.fresh && <div className="connection-stale-note">
        这是 daemon 最后一次权威上报的路径，不表示当前仍处于活动连接。
      </div>}
      <dl className="connection-detail-list">
        <div><dt>From</dt><dd>{current.reporting_device_name}<small>{current.reporting_username}</small></dd></div>
        <div><dt>To</dt><dd>{current.remote_device_name}<small>{current.remote_username}</small></dd></div>
        <div><dt>验证 RTT</dt><dd>{current.last_validation_rtt_ms === undefined ? '—' : `${current.last_validation_rtt_ms} ms`}</dd></div>
        <div><dt>Path age</dt><dd>{formatMilliseconds(current.path_age_ms)}</dd></div>
        <div><dt>Last observed</dt><dd>{formatAgo(current.received_at)}</dd></div>
        <div><dt>Lifecycle</dt><dd>{current.lifecycle || '—'}</dd></div>
        <div><dt>Previous path</dt><dd>{pathLabel(current.previous_path)}</dd></div>
        <div><dt>Reason</dt><dd title={current.transition_reason}>{reasonLabel(current.transition_reason)}</dd></div>
        {current.selected_path_mtu !== undefined && <div><dt>Path MTU</dt><dd>{current.selected_path_mtu}</dd></div>}
        {current.last_handshake_age_ms !== undefined && <div><dt>Handshake age</dt><dd>{formatMilliseconds(current.last_handshake_age_ms)}</dd></div>}
      </dl>
    </section>

    <section className="connection-drawer-section timeline-section">
      <div className="connection-section-title"><div><Clock3 size={15} /><strong>切换历史</strong></div><span>仅当前方向</span></div>
      {history.isPending ? <LoadingBlock label="正在读取迁移历史…" /> : history.error ? <ErrorBlock error={history.error} /> : transitions.length === 0
        ? <div className="connection-empty-inline">暂无迁移记录。</div>
        : <div className="connection-timeline">{transitions.map((transition) => <TransitionRow key={transition.id} transition={transition} />)}</div>}
      {history.hasNextPage && <button className="button secondary compact connection-load-more" onClick={() => history.fetchNextPage()} disabled={history.isFetchingNextPage}>
        {history.isFetchingNextPage ? '加载中…' : '加载更早记录'}
      </button>}
    </section>
  </aside>
}

export function ConnectionsPage() {
  const [view, setView] = useState<'table' | 'topology'>('table')
  const [query, setQuery] = useState('')
  const [networkId, setNetworkId] = useState('')
  const [path, setPath] = useState('')
  const [freshness, setFreshness] = useState<'fresh' | 'stale' | ''>('')
  const [offset, setOffset] = useState(0)
  const [showStaleTopology, setShowStaleTopology] = useState(false)
  const [selected, setSelected] = useState<AdminConnection | null>(null)
  const [debouncedQuery, setDebouncedQuery] = useState(query)

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [query])

  useEffect(() => {
    setOffset(0)
  }, [debouncedQuery, networkId, path, freshness])

  const networks = useInfiniteQuery({
    queryKey: ['connections', 'networks'],
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

  const result = useQuery({
    queryKey: ['connections', 'table', debouncedQuery, networkId, path, freshness, offset],
    queryFn: () => adminApi.connections({
      query: debouncedQuery,
      networkId,
      path,
      freshness,
    }, PAGE_SIZE, offset),
    refetchInterval: 15_000,
  })

  const topology = useQuery({
    queryKey: ['connections', 'topology', debouncedQuery, networkId, path, showStaleTopology],
    queryFn: () => adminApi.connections({
      query: debouncedQuery,
      networkId,
      path,
      freshness: showStaleTopology ? '' : 'fresh',
    }, TOPOLOGY_LIMIT, 0),
    enabled: view === 'topology' && Boolean(networkId),
    refetchInterval: 10_000,
  })

  const selectedNetwork = networkItems.find((network) => network.id === networkId)

  const columns = useMemo<ColumnDef<AdminConnection, unknown>[]>(() => [
    { id: 'direction', header: '方向', cell: ({ row }) => <ConnectionDirection connection={row.original} /> },
    { id: 'network', header: '网络', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.network_name}</strong><span className="mono">{row.original.network_id}</span></div> },
    { id: 'path', header: '路径', cell: ({ row }) => <PathBadge connection={row.original} /> },
    { id: 'fresh', header: '观测', cell: ({ row }) => <FreshnessBadge connection={row.original} /> },
    { id: 'rtt', header: '验证 RTT', cell: ({ row }) => row.original.last_validation_rtt_ms === undefined ? '—' : `${row.original.last_validation_rtt_ms} ms` },
    { id: 'age', header: 'Path age', cell: ({ row }) => formatMilliseconds(row.original.path_age_ms) },
    { id: 'reason', header: '原因', cell: ({ row }) => <span className="connection-reason" title={row.original.transition_reason}>{reasonLabel(row.original.transition_reason)}</span> },
    { id: 'observed', header: '最后观测', cell: ({ row }) => formatAgo(row.original.received_at) },
    { id: 'action', header: '', cell: () => <ChevronRight className="row-chevron" size={16} /> },
  ], [])

  const table = useReactTable({
    data: result.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  return <div className="page-stack connections-page">
    <div className="page-intro connections-intro">
      <div><h2>Connections</h2><p>路径只来自 daemon 已提交的权威单向观测；Fresh 表示观测仍在有效 lease 内，不代表目标应用本身一定可达。</p></div>
      <div className="connections-view-switch" role="group" aria-label="连接视图">
        <button className={view === 'table' ? 'active' : ''} onClick={() => setView('table')}><Table2 size={15} />列表</button>
        <button className={view === 'topology' ? 'active' : ''} onClick={() => setView('topology')}><Waypoints size={15} />Live topology</button>
      </div>
    </div>

    <div className="connections-toolbar">
      <label className="search-field connections-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索设备、账号或网络" aria-label="搜索连接" /></label>
      <select className="select-field" value={networkId} onChange={(event) => setNetworkId(event.target.value)} aria-label="按网络过滤">
        <option value="">全部网络</option>
        {networkItems.map((network) => <option key={network.id} value={network.id}>{network.name}</option>)}
      </select>
      <select className="select-field" value={path} onChange={(event) => setPath(event.target.value)} aria-label="按路径过滤">
        <option value="">全部路径</option>
        <option value="direct">Direct</option>
        <option value="relay">Relay</option>
        <option value="none">None</option>
      </select>
      {view === 'table' && <select className="select-field" value={freshness} onChange={(event) => setFreshness(event.target.value as 'fresh' | 'stale' | '')} aria-label="按观测新鲜度过滤">
        <option value="">全部观测</option>
        <option value="fresh">Fresh</option>
        <option value="stale">Stale / reporter offline</option>
      </select>}
      {networks.hasNextPage && <button
        className="button secondary compact"
        onClick={() => networks.fetchNextPage()}
        disabled={networks.isFetchingNextPage}
      >{networks.isFetchingNextPage ? '加载中…' : '加载更多网络'}</button>}
    </div>

    {view === 'table' ? <section className="panel-v2 connections-panel">
      {result.isPending ? <LoadingBlock label="正在读取连接观测…" /> : result.error ? <ErrorBlock error={result.error} /> : result.data ? <>
        <div className="data-table-wrap"><table className="data-table connections-table">
          <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => <th key={header.id}>{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}</th>)}</tr>)}</thead>
          <tbody>
            {table.getRowModel().rows.map((row) => <tr key={row.id} className="clickable" onClick={() => setSelected(row.original)}>
              {row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}
            </tr>)}
            {table.getRowModel().rows.length === 0 && <tr><td className="table-empty" colSpan={columns.length}>尚无符合条件的 daemon 路径观测。</td></tr>}
          </tbody>
        </table></div>
        <div className="pagination-v2"><span>{result.data.total === 0 ? 0 : offset + 1}–{Math.min(result.data.total, offset + result.data.items.length)} / {result.data.total}</span><div>
          <button className="button secondary compact" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft size={15} />上一页</button>
          <button className="button secondary compact" disabled={offset + PAGE_SIZE >= result.data.total} onClick={() => setOffset(offset + PAGE_SIZE)}>下一页<ChevronRight size={15} /></button>
        </div></div>
      </> : <ErrorBlock error={new Error('Control 未返回连接列表。')} />}
    </section> : <section className="panel-v2 connections-panel topology-mode">
      {!networkId ? <div className="connection-topology-empty choose-network">
        <Network size={20} />
        <div><strong>选择一个网络查看 Live Topology</strong><span>拓扑不会跨网络拼接，也不会从 membership、signaling 或 RTT 推断连接。</span></div>
      </div> : topology.isPending ? <LoadingBlock label="正在读取权威连接拓扑…" /> : topology.error ? <ErrorBlock error={topology.error} /> : topology.data ? <>
        {topology.data.total > topology.data.items.length && <div className="connection-partial-warning"><CircleAlert size={15} />当前网络共有 {topology.data.total} 条匹配观测，拓扑仅展示前 {topology.data.items.length} 条；请收紧搜索或路径过滤。</div>}
        <ConnectionTopology
          connections={topology.data.items}
          networkName={selectedNetwork?.name ?? networkId}
          showStale={showStaleTopology}
          partial={topology.data.total > topology.data.items.length}
          onShowStaleChange={setShowStaleTopology}
          onSelect={setSelected}
        />
      </> : <ErrorBlock error={new Error('Control 未返回连接拓扑。')} />}
    </section>}

    {selected && <ConnectionDrawer connection={selected} onClose={() => setSelected(null)} />}
  </div>
}
