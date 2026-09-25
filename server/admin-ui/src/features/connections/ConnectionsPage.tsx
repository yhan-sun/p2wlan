import { useEffect, useMemo, useState } from 'react'
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
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { adminApi } from '../../api'
import { EmptyState, PageHeader, SegmentedControl, Sheet, StatusPill } from '../../components/ui/console'
import { ErrorBlock, LoadingBlock, formatAgo, formatDate } from '../../shared/console'
import { ConnectionTopology } from './ConnectionTopology'
import type { AdminConnection, AdminConnectionTransition } from '../../types'

const PAGE_SIZE = 25
const TOPOLOGY_LIMIT = 100

function formatMilliseconds(value?: number): string {
  if (value === undefined) return '—'
  if (value < 1000) return `${value} ms`
  const seconds = Math.round(value / 100) / 10
  if (seconds < 60) return `${seconds} s`
  return `${Math.round(seconds / 6) / 10} min`
}

function pathLabel(path?: string | null): string {
  if (!path) return '无路径'
  if (path === 'direct') return 'Direct'
  if (path === 'relay') return 'Relay'
  return path.replaceAll('_', ' ')
}

function reasonLabel(reason: string): string {
  if (!reason) return '—'
  const known: Record<string, string> = {
    initial: '初始观测',
    direct_committed: '直连已提交',
    relay_peer_confirmed: '中继已确认',
    direct_path_failed: '直连路径失败',
    relay_path_failed: '中继路径失败',
    network_generation_advanced: '网络代际已推进',
  }
  return known[reason] ?? reason.replaceAll('_', ' ')
}

function PathBadge({ connection }: { connection: AdminConnection }) {
  const path = connection.current_path || 'none'
  const tone = !connection.fresh ? 'neutral' : path === 'direct' ? 'success' : path === 'relay' ? 'accent' : 'neutral'
  return <StatusPill tone={tone} dot>{pathLabel(connection.current_path)}</StatusPill>
}

function FreshnessBadge({ connection }: { connection: AdminConnection }) {
  const label = connection.fresh ? '新鲜' : connection.freshness === 'reporter_offline' ? '上报端离线' : '过期'
  return <StatusPill tone={connection.fresh ? 'success' : connection.freshness === 'reporter_offline' ? 'warning' : 'neutral'}>{label}</StatusPill>
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

  const transitions = history.data?.pages.flatMap((page) => page.items) ?? []

  return <Sheet
    title={<>{current.reporting_device_name} → {current.remote_device_name}</>}
    description={<>单向连接 · {current.network_name}</>}
    onClose={onClose}
  >

    <section className="connection-drawer-section">
      <div className="connection-state-hero">
        <PathBadge connection={current} />
        <FreshnessBadge connection={current} />
      </div>
      {!current.fresh && <div className="connection-stale-note">
        这是 daemon 最后一次权威上报的路径，不表示当前仍处于活动连接。
      </div>}
      <dl className="connection-detail-list">
        <div><dt>来源</dt><dd>{current.reporting_device_name}<small>{current.reporting_username}</small></dd></div>
        <div><dt>目标</dt><dd>{current.remote_device_name}<small>{current.remote_username}</small></dd></div>
        <div><dt>验证 RTT</dt><dd>{current.last_validation_rtt_ms === undefined ? '—' : `${current.last_validation_rtt_ms} ms`}</dd></div>
        <div><dt>路径存续</dt><dd>{formatMilliseconds(current.path_age_ms)}</dd></div>
        <div><dt>最后观测</dt><dd>{formatAgo(current.received_at)}</dd></div>
        <div><dt>生命周期</dt><dd>{current.lifecycle || '—'}</dd></div>
        <div><dt>上一路径</dt><dd>{pathLabel(current.previous_path)}</dd></div>
        <div><dt>原因</dt><dd title={current.transition_reason}>{reasonLabel(current.transition_reason)}</dd></div>
        {current.selected_path_mtu !== undefined && <div><dt>Path MTU</dt><dd>{current.selected_path_mtu}</dd></div>}
        {current.last_handshake_age_ms !== undefined && <div><dt>握手距今</dt><dd>{formatMilliseconds(current.last_handshake_age_ms)}</dd></div>}
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
  </Sheet>
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
    { id: 'age', header: '路径存续', cell: ({ row }) => formatMilliseconds(row.original.path_age_ms) },
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
    <PageHeader
      eyebrow="网络"
      title="连接路径"
      description="路径只来自 daemon 已提交的权威单向观测。新鲜 表示观测仍在有效 lease 内，不等于目标应用端口已经可达。"
      actions={<div className="connections-intro-actions">
        <Link className="button secondary compact" to="/health"><AlertTriangle size={15} />需要关注</Link>
        <SegmentedControl
          label="连接视图"
          value={view}
          onChange={setView}
          options={[
            { label: '列表', value: 'table', icon: <Table2 size={15} /> },
            { label: '实时拓扑', value: 'topology', icon: <Waypoints size={15} /> },
          ]}
        />
      </div>}
    />

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
        <option value="none">无路径</option>
      </select>
      {view === 'table' && <select className="select-field" value={freshness} onChange={(event) => setFreshness(event.target.value as 'fresh' | 'stale' | '')} aria-label="按观测新鲜度过滤">
        <option value="">全部观测</option>
        <option value="fresh">新鲜</option>
        <option value="stale">过期 / 上报端离线</option>
      </select>}
      {networks.hasNextPage && <button
        className="button secondary compact"
        onClick={() => networks.fetchNextPage()}
        disabled={networks.isFetchingNextPage}
      >{networks.isFetchingNextPage ? '加载中…' : '加载更多网络'}</button>}
    </div>

    {view === 'table' ? <section className="panel-v2 connections-panel">
      {result.isPending ? <LoadingBlock label="正在读取连接观测…" /> : result.error ? <ErrorBlock error={result.error} /> : result.data ? <>
        <div className="connections-mobile-list">
          {result.data.items.map((connection) => <button
            type="button"
            className="connection-mobile-row"
            key={`${connection.network_id}:${connection.reporting_device_id}:${connection.remote_device_id}`}
            onClick={() => setSelected(connection)}
          >
            <div className="connection-mobile-head">
              <div className="connection-mobile-direction">
                <span><strong>{connection.reporting_device_name}</strong><small>{connection.reporting_username}</small></span>
                <ArrowDownRight size={14} aria-hidden />
                <span><strong>{connection.remote_device_name}</strong><small>{connection.remote_username}</small></span>
              </div>
              <PathBadge connection={connection} />
            </div>
            <div className="connection-mobile-facts">
              <span>{connection.network_name}</span>
              <FreshnessBadge connection={connection} />
              <span>{connection.last_validation_rtt_ms === undefined ? '—' : `${connection.last_validation_rtt_ms} ms`}</span>
              <span>{formatAgo(connection.received_at)}</span>
              <ChevronRight size={14} aria-hidden />
            </div>
          </button>)}
          {result.data.items.length === 0 && <div className="connection-mobile-empty">尚无符合条件的 daemon 路径观测。</div>}
        </div>
        <div className="data-table-wrap connections-desktop-table"><table className="data-table connections-table">
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
      {!networkId ? <EmptyState
        icon={<Network size={20} />}
        title="选择一个网络查看 Live Topology"
        description="拓扑不会跨网络拼接，也不会从成员关系、信令或 RTT 推断连接。"
      /> : topology.isPending ? <LoadingBlock label="正在读取权威连接拓扑…" /> : topology.error ? <ErrorBlock error={topology.error} /> : topology.data ? <>
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
