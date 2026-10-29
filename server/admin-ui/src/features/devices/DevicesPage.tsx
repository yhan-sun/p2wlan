import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { AccountScopePicker } from '../../AccountScopePicker'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { tr } from '../../i18n'
import { useCursorPage, usePageState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { CursorPagination, ErrorBlock, Panel, PendingBlock, ResourceEmptyState, ResourceReturnLink, useDebouncedValue } from '../../shared/console'
import type { ResourceAccountScope } from '../../types'
import { DeviceTable } from '../resources/ResourceTables'
const PAGE_SIZE = 25

export function DevicesPage({ accountScope }: { accountScope?: ResourceAccountScope }) {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const paging = useCursorPage()
  const query = params.get('q') || ''
  const accountId = accountScope?.id || params.get('account_id') || ''
  const account = accountScope || (accountId ? { id: accountId, username: params.get('account_name') || accountId } : null)
  const status = ['online', 'offline'].includes(params.get('status') || '') ? params.get('status')! : 'all'
  const debounced = useDebouncedValue(query)
  const result = useQuery({
    queryKey: ['devices', 'cursor', accountId, debounced, status, paging.cursor],
    queryFn: ({ signal }) => adminApi.devicesSnapshot(debounced, status, paging.cursor, PAGE_SIZE, signal, accountId),
    refetchInterval: refreshInterval, enabled: debounced === query,
  })
  const hasFilters = Boolean(query.trim() || status !== 'all' || (!accountScope && accountId))
  const clearFilters = () => update({ q: '', status: '', cursor: '', page: '', ...(!accountScope ? { account_id: '', account_name: '' } : {}) })
  const resetPage = () => update({ cursor: '', page: '' }, true)
  const resultTitle = `${tr('设备列表')}${result.data && debounced === query ? ` · ${result.data.total}` : ''}`

  return <div className="page-stack resource-page">
    {!accountScope && <ResourceReturnLink />}
    <PageHeader title={tr('设备')} description={tr(account ? '所选账号下已注册的设备。' : '全部账号下已注册的 P2WLAN 设备。')} />
    <Panel className="resource-results-panel" title={resultTitle} action={result.data?.items.length && debounced === query ? <SnapshotExport items={result.data.items} filename="devices" generatedAt={result.data.generated_at} total={result.data.total} scope={{ q: query, status, account_id: accountId, cursor: paging.cursor }} /> : undefined}>
      <div className="resource-list-toolbar" role="search" aria-label={tr('设备筛选')}>
        <div className="resource-toolbar-fields">
          <label className="search-field"><Search size={16} aria-hidden /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr('搜索设备、账号、IP 或网络')} aria-label={tr('搜索设备、账号、IP 或网络')} /></label>
          <select className="select-field" value={status} onChange={(event) => update({ status: event.target.value === 'all' ? '' : event.target.value, cursor: '', page: '' })} aria-label={tr('全部状态')}><option value="all">{tr('全部状态')}</option><option value="online">{tr('在线')}</option><option value="offline">{tr('离线')}</option></select>
          {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', cursor: '', page: '' })} />}
          {hasFilters && <button type="button" className="button secondary resource-filter-clear" onClick={clearFilters}>{tr('清除筛选')}</button>}
        </div>
      </div>
      <div className="resource-list-status"><QueryStatus queries={[result]} /></div>
      {debounced === query && paging.cursor && result.error instanceof ApiError && result.error.status === 400 && <div className="resource-query-recovery"><button type="button" className="button secondary" onClick={resetPage}>{tr('重新从首页加载')}</button></div>}
      {result.isPending || debounced !== query ? <PendingBlock queries={[result]} /> : result.error && !result.data ? <ErrorBlock error={result.error} onRetry={() => { void result.refetch() }} /> : result.data ? <>
        {result.data.items.length ? <DeviceTable devices={result.data.items} accountId={accountId} /> : <ResourceEmptyState
          message={paging.cursor ? '当前页没有记录' : hasFilters ? '没有符合条件的设备' : '尚无设备'}
          description={paging.cursor ? '列表可能已更新，请返回首页重新读取。' : hasFilters ? '请调整筛选条件，或清除筛选查看全部记录。' : '设备通过 P2WLAN 客户端注册后显示在这里。'}
          onReset={paging.cursor ? resetPage : undefined}
          onClear={hasFilters ? clearFilters : undefined}
          action={{ to: '/accounts', label: '查看账号' }}
        />}
        {result.data.total > 0 && <CursorPagination total={result.data.total} pageIndex={paging.pageIndex} itemCount={result.data.items.length} limit={PAGE_SIZE} canNext={Boolean(result.data.next_cursor)} canPrev={paging.canPrev} previousIsFirst={paging.previousIsFirst} onPrev={paging.prev} onNext={() => paging.next(result.data?.next_cursor || '')} />}
      </> : <ErrorBlock error={new Error('控制面未返回设备列表。')} />}
    </Panel>
  </div>
}
