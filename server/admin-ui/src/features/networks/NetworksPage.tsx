import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { AccountScopePicker } from '../../AccountScopePicker'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { getLocale, tr } from '../../i18n'
import { useCursorPage, usePageState, useResourceTabState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { CursorPagination, ErrorBlock, Panel, PendingBlock, ResourceEmptyState, ResourceReturnLink, ResourceTabs, useDebouncedValue } from '../../shared/console'
import type { ResourceAccountScope } from '../../types'
import { NetworkTable, RoomTable } from '../resources/ResourceTables'
const PAGE_SIZE = 25

export function NetworksPage({ accountScope, fixedTab }: { accountScope?: ResourceAccountScope; fixedTab?: 'networks' | 'rooms' }) {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const tab = fixedTab || (params.get('tab') === 'rooms' ? 'rooms' : 'networks')
  const setTab = useResourceTabState(tab, 'networks', ['networks', 'rooms'])
  const query = params.get('q') || ''
  const debounced = useDebouncedValue(query)
  const accountId = accountScope?.id || params.get('account_id') || ''
  const account = accountScope || (accountId ? { id: accountId, username: params.get('account_name') || accountId } : null)
  const paging = useCursorPage()
  const filters = { query: debounced, accountId }
  const networks = useQuery({ queryKey: ['networks', 'snapshot', tab, accountId, debounced, paging.cursor], queryFn: ({ signal }) => adminApi.networksSnapshot(filters, paging.cursor, PAGE_SIZE, signal), enabled: tab === 'networks' && debounced === query, refetchInterval: refreshInterval })
  const rooms = useQuery({ queryKey: ['rooms', 'snapshot', tab, accountId, debounced, paging.cursor], queryFn: ({ signal }) => adminApi.roomsSnapshot(filters, paging.cursor, PAGE_SIZE, signal), enabled: tab === 'rooms' && debounced === query, refetchInterval: refreshInterval })
  const active = tab === 'networks' ? networks : rooms
  const hasFilters = Boolean(query.trim() || (!accountScope && accountId))
  const clearFilters = () => update({ q: '', network_page: '', room_page: '', cursor: '', page: '', ...(!accountScope ? { account_id: '', account_name: '' } : {}) })
  const resetPage = () => update({ cursor: '', page: '' }, true)
  const resultCount = active.data && debounced === query ? new Intl.NumberFormat(getLocale()).format(active.data.total) : null
  const emptyMessage = paging.cursor ? '当前页没有记录' : hasFilters ? tab === 'rooms' ? '没有符合条件的房间' : '没有符合条件的网络' : tab === 'rooms' ? '暂无房间' : '暂无网络'
  const emptyDescription = paging.cursor ? '返回首页，重新读取列表。' : hasFilters ? '换个关键词，或清除筛选。' : tab === 'rooms' ? '在客户端创建或加入房间后，即可在这里查看。' : '创建或加入网络后，即可在这里查看。'

  return <div className="page-stack resource-page">
    {!accountScope && <ResourceReturnLink />}
    <PageHeader title={tr(fixedTab ? tab === 'rooms' ? '房间网络' : '全部网络' : '网络与房间')} description={tr('查看网络成员、地址段与房间加入状态。')} />
    <Panel className="resource-results-panel">
      {!fixedTab && <div className="resource-list-tabs"><ResourceTabs id="network-resources" label="网络类型" value={tab} onChange={setTab} tabs={[{ value: 'networks', label: tr('全部网络') }, { value: 'rooms', label: tr('房间网络') }]} /></div>}
      <div {...(!fixedTab ? { role: 'tabpanel', id: 'network-resources-panel', 'aria-labelledby': `network-resources-${tab}`, tabIndex: 0 } : {})}>
        <div className="resource-list-toolbar" role="search" aria-label={tr('网络筛选')}>
          <div className="resource-toolbar-fields">
            <label className="search-field"><Search size={16} aria-hidden /><input value={query} onChange={(event) => update({ q: event.target.value, network_page: '', room_page: '', cursor: '', page: '' }, true)} placeholder={tr('搜索名称、ID、网段或房间码')} aria-label={tr('搜索名称、ID、网段或房间码')} /></label>
            {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', network_page: '', room_page: '', cursor: '', page: '' })} />}
            {hasFilters && <button type="button" className="button secondary resource-filter-clear" onClick={clearFilters}>{tr('清除筛选')}</button>}
          </div>
        </div>
        <div className="resource-list-meta">
          {resultCount !== null && <span className="resource-result-count"><strong>{resultCount}</strong>{tr('条记录')}</span>}
          <QueryStatus queries={[active]} />
          {debounced === query && tab === 'networks' && networks.data?.items.length ? <SnapshotExport items={networks.data.items} filename="networks" generatedAt={networks.data.generated_at} total={networks.data.total} scope={{ q: query, account_id: accountId, cursor: paging.cursor }} /> : debounced === query && tab === 'rooms' && rooms.data?.items.length ? <SnapshotExport items={rooms.data.items} filename="rooms" generatedAt={rooms.data.generated_at} total={rooms.data.total} scope={{ q: query, account_id: accountId, cursor: paging.cursor }} /> : null}
        </div>
        {debounced === query && paging.cursor && active.error instanceof ApiError && active.error.status === 400 && <div className="resource-query-recovery"><button type="button" className="button secondary" onClick={resetPage}>{tr('重新从首页加载')}</button></div>}
        {active.isPending || debounced !== query ? <PendingBlock queries={[active]} /> : active.error && !active.data ? <ErrorBlock error={active.error} onRetry={() => { void active.refetch() }} /> : active.data ? <>
          {tab === 'networks' && networks.data?.items.length ? <NetworkTable networks={networks.data.items} accountId={accountId} /> : tab === 'rooms' && rooms.data?.items.length ? <RoomTable rooms={rooms.data.items} accountId={accountId} /> : <ResourceEmptyState
            message={emptyMessage}
            description={emptyDescription}
            onReset={paging.cursor ? resetPage : undefined}
            onClear={hasFilters ? clearFilters : undefined}
            action={{ to: '/devices', label: '查看设备' }}
          />}
          {active.data.total > 0 && <CursorPagination total={active.data.total} pageIndex={paging.pageIndex} itemCount={active.data.items.length} limit={PAGE_SIZE} canNext={Boolean(active.data.next_cursor)} canPrev={paging.canPrev} previousIsFirst={paging.previousIsFirst} onPrev={paging.prev} onNext={() => paging.next(active.data?.next_cursor || '')} />}
        </> : <ErrorBlock error={new Error('控制面未返回完整的网络与房间列表。')} />}
      </div>
    </Panel>
  </div>
}
