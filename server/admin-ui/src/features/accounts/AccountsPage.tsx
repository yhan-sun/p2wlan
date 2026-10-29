import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Search } from 'lucide-react'
import { useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { tr } from '../../i18n'
import { accountReturnState, useCursorPage, usePageState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { AccountMark, CursorPagination, DataTable, ErrorBlock, Panel, PendingBlock, ResourceEmptyState, formatAgo, formatDate, useDebouncedValue } from '../../shared/console'
import type { AdminAccount } from '../../types'
const PAGE_SIZE = 25

export function AccountsPage() {
  const refreshInterval = useAutoRefresh()
  const location = useLocation()
  const { params, update } = usePageState()
  const paging = useCursorPage()
  const query = params.get('q') || ''
  const debounced = useDebouncedValue(query)
  const result = useQuery({
    queryKey: ['accounts', 'cursor', debounced, paging.cursor],
    queryFn: ({ signal }) => adminApi.accountsSnapshot(debounced, paging.cursor, PAGE_SIZE, signal),
    refetchInterval: refreshInterval,
    enabled: debounced === query,
  })

  const columns = useMemo<ColumnDef<AdminAccount, unknown>[]>(() => [
    { id: 'account', header: '账号', cell: ({ row }) => <div className="identity-cell"><AccountMark account={row.original} /><div><Link className="identity-link" to={`/accounts/${encodeURIComponent(row.original.id)}`} state={accountReturnState(location)}>{row.original.username}</Link><span>{row.original.email}</span></div></div> },
    { id: 'devices', header: '设备', cell: ({ row }) => <div className="ratio-cell"><strong>{row.original.online_devices}{tr("/")}{row.original.device_count}</strong><span>{row.original.device_count ? Math.round(row.original.online_devices / row.original.device_count * 100) : 0}{tr("% 在线")}</span></div> },
    { accessorKey: 'network_count', header: '网络' },
    { accessorKey: 'room_count', header: '房间' },
    { id: 'last_seen', header: '最近活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
    { id: 'created_at', header: '注册时间', cell: ({ row }) => formatDate(row.original.created_at) },
  ], [location])

  const hasFilters = Boolean(query.trim())
  const clearFilters = () => update({ q: '', cursor: '', page: '' })
  const resetPage = () => update({ cursor: '', page: '' }, true)
  const resultTitle = `${tr('账号列表')}${result.data && debounced === query ? ` · ${result.data.total}` : ''}`

  return <div className="page-stack resource-page">
    <PageHeader title={tr('所有账号')} description={tr('查看账号的设备、网络和最近活动。')} />
    <Panel className="resource-results-panel" title={resultTitle} action={result.data?.items.length && debounced === query ? <SnapshotExport items={result.data.items} filename="accounts" total={result.data.total} scope={{ q: query, cursor: paging.cursor }} /> : undefined}>
      <div className="resource-list-toolbar" role="search" aria-label={tr('账号筛选')}>
        <div className="resource-toolbar-fields">
          <label className="search-field"><Search size={16} aria-hidden /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr('搜索用户名或邮箱')} aria-label={tr('搜索用户名或邮箱')} /></label>
          {hasFilters && <button type="button" className="button secondary resource-filter-clear" onClick={clearFilters}>{tr('清除筛选')}</button>}
        </div>
      </div>
      <div className="resource-list-status"><QueryStatus queries={[result]} /></div>
      {debounced === query && paging.cursor && result.error instanceof ApiError && result.error.status === 400 && <div className="resource-query-recovery"><button type="button" className="button secondary" onClick={resetPage}>{tr('重新从首页加载')}</button></div>}
      {result.isPending || debounced !== query ? <PendingBlock queries={[result]} /> : result.error && !result.data ? <ErrorBlock error={result.error} onRetry={() => { void result.refetch() }} /> : result.data ? <>
        {result.data.items.length ? <DataTable<AdminAccount> columns={columns} data={result.data.items} /> : <ResourceEmptyState
          message={paging.cursor ? '当前页没有记录' : hasFilters ? '没有符合条件的账号' : '暂无账号'}
          description={paging.cursor ? '列表可能已更新，请返回首页重新读取。' : hasFilters ? '请调整筛选条件，或清除筛选查看全部记录。' : '账号注册后会显示在这里，此页面仅提供只读查看。'}
          onReset={paging.cursor ? resetPage : undefined}
          onClear={hasFilters ? clearFilters : undefined}
          action={{ to: '/system', label: '查看运行状态' }}
        />}
        {result.data.total > 0 && <CursorPagination
          total={result.data.total}
          pageIndex={paging.pageIndex}
          canPrev={paging.canPrev}
          previousIsFirst={paging.previousIsFirst}
          itemCount={result.data.items.length}
          limit={PAGE_SIZE}
          canNext={Boolean(result.data.next_cursor)}
          onPrev={paging.prev}
          onNext={() => paging.next(result.data?.next_cursor || '')}
        />}
      </> : <ErrorBlock error={new Error('控制面未返回账号列表。')} />}
    </Panel>
  </div>
}
