import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table'
import { ChevronLeft, ChevronRight, CircleAlert, Network, Search, X } from 'lucide-react'
import { lazy, useEffect, useMemo, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { AsyncView } from '../../AsyncView'
import { SnapshotExport } from '../../SnapshotExport'
import { adminApi } from '../../api'
import { tr } from '../../i18n'
import { resourceOriginState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import type { AdminConnection } from '../../types'
import { ConnectionDrawer } from './ConnectionDrawer'
import { CONNECTION_PAGE_SIZE, closeConnectionDetailSearch, connectionDetailIsOpen, isolateConnectionSearch, lastAvailableConnectionPage, readConnectionSearch, readDirectionOnlySearch, selectConnectionSearch, updateConnectionSearch, type ConnectionIdentity } from './connectionNavigation'
import { ConnectionDirection, ConnectionMobileCard, ErrorBlock, FreshnessBadge, LoadingBlock, PathBadge, formatAgo, formatMilliseconds, reasonLabel } from './connectionPresentation'
import { useConnectionSearchParams } from './useConnectionSearch'

const PAGE_SIZE = CONNECTION_PAGE_SIZE
const TOPOLOGY_LIMIT = 100
const ConnectionTopology = lazy(() => import('./ConnectionTopology').then((module) => ({ default: module.ConnectionTopology })))

export function ConnectionsPage() {
  const [searchParams, setSearchParams] = useConnectionSearchParams()
  const location = useLocation()
  const { view, query: committedQuery, networkId, accountId, deviceId, path, freshness, page, showStale: showStaleTopology, selected } = readConnectionSearch(searchParams)
  const directionOnly = readDirectionOnlySearch(searchParams)
  const directionQueryKey = directionOnly ? ['direction', directionOnly.reporting_device_id, directionOnly.remote_device_id] : []
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
    const scopeChanged = ['network_id', 'account_id', 'user_id', 'device_id'].some((key) => key in changes)
    setSearchParams((current) => selectConnectionSearch(updateConnectionSearch(current, { q: query.trim(), page: null, ...(scopeChanged ? { alert_page: null } : {}), ...changes }), null))
  }
  const selectConnection = (connection: ConnectionIdentity | null) => {
    setSearchParams((current) => selectConnectionSearch(current, connection), { replace: !connection })
  }
  const clearConnectionFilters = () => {
    setQuery('')
    changeFilter({
      q: null, network_id: null, account_id: null, user_id: null, device_id: null,
      path: null, freshness: null, page: null, show_stale: null, view: null, tab: 'all',
    })
  }

  const networks = useInfiniteQuery({
    queryKey: ['connections', 'networks'],
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

  const result = useQuery({
    queryKey: ['connections', 'table', committedQuery, networkId, accountId, deviceId, path, freshness, offset, ...directionQueryKey],
    queryFn: ({ signal }) => adminApi.connections({
      query: committedQuery,
      networkId,
      accountId,
      deviceId,
      path,
      freshness,
      reportingDeviceId: directionOnly?.reporting_device_id,
      remoteDeviceId: directionOnly?.remote_device_id,
    }, directionOnly ? 1 : PAGE_SIZE, offset, signal),
    enabled: view === 'table',
    refetchInterval: tableRefreshInterval,
  })

  const topology = useQuery({
    queryKey: ['connections', 'topology', committedQuery, networkId, accountId, deviceId, path, freshness, ...directionQueryKey],
    queryFn: ({ signal }) => adminApi.connections({
      query: committedQuery,
      networkId,
      accountId,
      deviceId,
      path,
      freshness,
      reportingDeviceId: directionOnly?.reporting_device_id,
      remoteDeviceId: directionOnly?.remote_device_id,
    }, directionOnly ? 1 : TOPOLOGY_LIMIT, 0, signal),
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
  const hasConnectionFilters = Boolean(committedQuery || networkId || accountId || deviceId || path || freshness || directionOnly)
  const emptySnapshot = tableRefreshInterval === false || result.fetchStatus === 'paused' || result.isFetching || Boolean(result.error) || query.trim() !== committedQuery
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
      <div>
        <h2>{tr(view === 'topology' ? '连接拓扑' : '全部观测')}</h2>
        <p>{tr('查看设备之间的连接路径、延迟与最近变化。')}</p>
        <details className="connection-observation-help">
          <summary>{tr('观测说明')}</summary>
          <p>{tr("路径只来自守护进程已提交的权威单向观测。“新鲜”表示观测仍在有效租约内，不代表目标应用一定可达。")}</p>
        </details>
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
      <select className="select-field" value={freshness} onChange={(event) => changeFilter({ freshness: event.target.value, show_stale: null, view: null, tab: view === 'topology' ? 'topology' : 'all' })} aria-label={tr("按观测新鲜度过滤")}>
        <option value="">{tr("全部观测")}</option>
        <option value="fresh">{tr("Fresh")}</option>
        <option value="stale">{tr("Stale / reporter offline")}</option>
      </select>
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
    {directionOnly && <div className="connection-focus-note"><span>{tr('仅显示所选方向')}：{directionOnly.reporting_device_id} → {directionOnly.remote_device_id}</span><button type="button" className="button secondary compact" onClick={() => selectConnection(null)}>{tr('清除方向范围')}</button></div>}
    {(networks.error || networks.fetchStatus === 'paused') && <div className="connection-context-note"><span>{tr('网络目录')}</span><QueryStatus queries={[networks]} /></div>}
    {(view === 'table' || networkId) && <div className="connections-result-bar">
      <QueryStatus queries={[view === 'table' ? result : topology]} />
      {activeItems.length > 0 && <SnapshotExport items={query.trim() === committedQuery ? activeItems : []} filename="connections" total={view === 'table' ? result.data?.total : topology.data?.total} scope={{ network_id: networkId, account_id: accountId, device_id: deviceId, q: committedQuery, path, freshness, view, page: view === 'table' ? page : 1, ...(directionOnly ? { reporting_device_id: directionOnly.reporting_device_id, remote_device_id: directionOnly.remote_device_id } : {}) }} />}
    </div>}

    {view === 'table' ? <section className="panel-v2 connections-panel">
      {correctingPage ? <LoadingBlock label={tr('正在调整分页…')} /> : result.data ? result.data.items.length === 0 ? <div className="connections-empty-state">
        <Network size={24} aria-hidden />
        <h3>{tr(emptySnapshot ? '上次快照中没有连接观测' : hasConnectionFilters ? '没有匹配的连接观测' : '尚无连接观测')}</h3>
        <p>{tr(emptySnapshot ? '以下为缓存快照，不能确认当前状态。' : hasConnectionFilters ? '请调整筛选条件，或清除筛选查看全部连接观测。' : '设备上报连接后，这里会显示路径、延迟与最近变化。')}</p>
        {hasConnectionFilters
          ? <button type="button" className="button secondary" onClick={clearConnectionFilters}>{tr('清除筛选')}</button>
          : <Link className="button secondary" to="/devices" state={resourceOriginState(location)}>{tr('查看设备')}</Link>}
      </div> : <>
        <div className="data-table-wrap"><table className="data-table connections-table">
          <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
            const heading = header.column.columnDef.header
            return <th key={header.id}>{header.isPlaceholder ? null : typeof heading === 'string' ? tr(heading) : flexRender(heading, header.getContext())}</th>
          })}</tr>)}</thead>
          <tbody>
            {table.getRowModel().rows.map((row) => <tr key={row.id} className={`clickable ${selected && row.original.network_id === selected.network_id && row.original.reporting_device_id === selected.reporting_device_id && row.original.remote_device_id === selected.remote_device_id ? 'connection-selected-row' : ''}`} tabIndex={0} aria-label={`${tr('连接详情')}: ${row.original.reporting_device_name} → ${row.original.remote_device_name}`} onClick={() => selectConnection(row.original)} onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault()
                selectConnection(row.original)
              }
            }}>
              {row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}
            </tr>)}
          </tbody>
        </table></div>
        <div className="connection-mobile-list">
          {result.data.items.map((connection) => <ConnectionMobileCard
            key={`${connection.network_id}:${connection.reporting_device_id}:${connection.remote_device_id}`}
            connection={connection}
            onSelect={selectConnection}
          />)}
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
      </div> : <>
        {topology.data && topology.data.total > topology.data.items.length && <div className="connection-partial-warning"><CircleAlert size={15} />{tr("当前网络共有 ")}{topology.data.total} {tr("条匹配观测，拓扑仅展示前 ")}{topology.data.items.length} {tr("条；请收紧搜索或路径过滤。")}</div>}
        <AsyncView><ConnectionTopology
          connections={topology.data?.items ?? []}
          networkName={selectedNetwork?.name ?? networkId}
          showStale={showStaleTopology}
          partial={Boolean(topology.data && topology.data.total > topology.data.items.length)}
          loading={!topology.data && topology.isPending}
          offline={!topology.data && topology.fetchStatus === 'paused'}
          error={!topology.data ? topology.error : undefined}
          onRetry={() => { void topology.refetch() }}
          fullscreenStatus={<QueryStatus queries={[topology]} />}
          selected={selected}
          directionOnly={Boolean(directionOnly)}
          onClearSelection={() => selectConnection(null)}
          onIsolateSelected={selected && !directionOnly ? () => setSearchParams((current) => isolateConnectionSearch(current, selected)) : undefined}
          onShowStaleChange={(value) => changeFilter({ freshness: value ? '' : 'fresh', tab: 'topology', view: null, show_stale: null })}
          onSelect={selectConnection}
        /></AsyncView>
      </>}
    </section>}

    {selected && connectionDetailIsOpen(searchParams) && <ConnectionDrawer key={`${selected.network_id}:${selected.reporting_device_id}:${selected.remote_device_id}`} connection={selected} onClose={() => setSearchParams(closeConnectionDetailSearch, { replace: true })} />}
  </div>
}
