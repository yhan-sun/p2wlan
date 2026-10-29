import { useInfiniteQuery } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { adminApi } from '../../api'
import { PageHeader } from '../../components/ui/console'
import { getLocale, tr } from '../../i18n'
import { QueryStatus } from '../../refresh'
import { ResourceReturnLink } from '../../shared/console'
import { ConnectionHealthPage } from '../health/ConnectionHealthPage'
import { ConnectionTrends } from './ConnectionTrends'
import { ConnectionsPage } from './ConnectionsPage'
import { healthSignalLabel } from './connectionLabels'
import { connectionWorkspaceSearch, connectionWorkspaceTab, readDirectionOnlySearch, selectConnectionSearch, type ConnectionWorkspaceTab } from './connectionNavigation'
import { readHealthSearch } from './trends'
import { useConnectionSearchParams } from './useConnectionSearch'

const tabs = [
  { id: 'health', label: '待关注' },
  { id: 'all', label: '全部观测' },
  { id: 'topology', label: '连接拓扑' },
  { id: 'trends', label: '历史趋势' },
] as const

function NetworkTrends() {
  const [params, setParams] = useConnectionSearchParams()
  const { networkId, trendHours } = readHealthSearch(params)
  const networks = useInfiniteQuery({
    queryKey: ['connections', 'networks'],
    queryFn: ({ pageParam, signal }) => adminApi.networks(100, pageParam, signal),
    initialPageParam: 0,
    getNextPageParam: (last) => last.items.length > 0 && last.offset + last.items.length < last.total ? last.offset + last.items.length : undefined,
    staleTime: 60_000,
  })
  const items = networks.data?.pages.flatMap((page) => page.items) ?? []
  const update = (key: string, value: string) => setParams((current) => {
    const next = key === 'network_id' ? selectConnectionSearch(current, null) : new URLSearchParams(current)
    if (value) next.set(key, value)
    else next.delete(key)
    if (key === 'network_id') {
      next.delete('trend_hour')
      next.delete('page')
      next.delete('alert_page')
    }
    return next
  })
  return <div className="page-stack connection-trends-page">
    <h3 className="sr-only">{tr('历史趋势')}</h3>
    <p className="connection-view-scope">{tr('按网络汇总观测；下方图表不应用账号或设备筛选。')}</p>
    <div className="connections-toolbar">
      <select className="select-field" aria-label={tr('按网络过滤')} value={networkId} onChange={(event) => update('network_id', event.target.value)}>
        <option value="">{tr('全部网络')}</option>
        {networkId && !items.some((item) => item.id === networkId) && <option value={networkId}>{networkId}</option>}
        {items.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
      </select>
      {networks.hasNextPage && <button className="button secondary compact" disabled={networks.isFetchingNextPage} onClick={() => void networks.fetchNextPage()}>{tr('加载更多网络')}</button>}
    </div>
    {(networks.error || networks.fetchStatus === 'paused') && <QueryStatus queries={[networks]} />}
    <ConnectionTrends networkId={networkId} windowHours={trendHours} onWindowChange={(hours) => update('window_hours', String(hours))} />
  </div>
}

function retainedFilterValue(key: string, value: string): string {
  if (key === 'window_seconds') return ['3600', '21600', '86400'].includes(value) ? `${Number(value) / 3600}h` : '—'
  if (key === 'window_hours') return ({ '24': '24h', '168': '7d', '720': '30d' } as Record<string, string>)[value] ?? '—'
  if (key === 'path') return tr(({ direct: 'Direct', relay: 'Relay', none: 'None' } as Record<string, string>)[value] ?? '未知')
  if (key === 'freshness') return tr(({ fresh: 'Fresh', stale: 'Stale / reporter offline' } as Record<string, string>)[value] ?? '未知')
  if (key === 'signal') return healthSignalLabel(value, getLocale())
  if (key === 'direction_only') return tr('仅显示所选方向')
  return value
}

function RetainedFilters({ active }: { active: ConnectionWorkspaceTab }) {
  const [params, setParams] = useConnectionSearchParams()
  const filters = [
    ['q', '搜索', ['all', 'topology']],
    ['path', '路径', ['all', 'topology']],
    ['freshness', '观测新鲜度', ['all', 'topology']],
    ['signal', '健康信号', ['health']],
    ['window_seconds', '健康窗口', ['health']],
    ['window_hours', '趋势窗口', ['trends']],
    ['account_id', '账号', ['all', 'topology', 'health']],
    ['user_id', '账号', ['all', 'topology', 'health']],
    ['device_id', '设备', ['all', 'topology', 'health']],
    ['direction_only', '方向范围', ['all', 'topology']],
  ] as const
  const unused = filters.filter(([key, , views]) => params.get(key) && !(views as readonly string[]).includes(active) && (key !== 'direction_only' || readDirectionOnlySearch(params)))
  if (!unused.length) return null
  const scope = active === 'trends' ? '当前图表仅按网络和趋势窗口汇总。'
    : active === 'health' ? '当前按网络、账号、设备、健康信号和健康窗口筛选。'
      : '当前按网络、账号、设备、搜索、路径和新鲜度筛选。'
  return <details className="connection-retained-filters">
    <summary>{tr('保留但未应用的筛选')} · {unused.length}<span>{tr(scope)}</span></summary>
    <div>{unused.map(([key, label]) => <span className="connection-retained-filter" key={key}>{tr(label)}：<span>{retainedFilterValue(key, params.get(key)!)}</span></span>)}
      <button type="button" className="button secondary compact" onClick={() => setParams((current) => {
        const removesScope = unused.some(([key]) => ['account_id', 'user_id', 'device_id'].includes(key))
        const next = removesScope ? selectConnectionSearch(current, null) : new URLSearchParams(current)
        for (const [key] of unused) next.delete(key)
        if (removesScope || unused.some(([key]) => ['q', 'path', 'freshness'].includes(key))) next.delete('page')
        if (removesScope || unused.some(([key]) => ['signal', 'window_seconds'].includes(key))) next.delete('alert_page')
        return next
      })}>{tr('清除这些保留筛选')}</button>
    </div>
  </details>
}

export function enterConnectionView(surface: HTMLElement | null, preference: MediaQueryList) {
  if (!surface?.animate || preference.matches) return
  // Do not transform this ancestor: it owns a position:fixed fullscreen graph.
  const animation = surface.animate([{ opacity: 0.45 }, { opacity: 1 }], {
    duration: 200, easing: 'cubic-bezier(.2,.65,.3,1)',
  })
  const reduce = () => { if (preference.matches) animation.cancel() }
  preference.addEventListener('change', reduce)
  return () => {
    animation.cancel()
    preference.removeEventListener('change', reduce)
  }
}

export function ConnectionWorkspace() {
  const [params] = useConnectionSearchParams()
  const { pathname, state } = useLocation()
  const active = connectionWorkspaceTab(params, pathname)
  const viewRef = useRef<HTMLDivElement>(null)
  // Polling and filter changes retain this owner and never replay its entrance.
  useEffect(() => enterConnectionView(viewRef.current, window.matchMedia('(prefers-reduced-motion: reduce)')), [active])
  const href = (tab: ConnectionWorkspaceTab) => `/connections?${connectionWorkspaceSearch(params, tab)}`
  return <div className="page-stack connection-workspace">
    <ResourceReturnLink />
    <PageHeader title={tr('连接排障')} description={tr('查看设备之间的连接路径、延迟与最近变化。')} />
    <nav className="connection-workspace-tabs" aria-label={tr('连接排障视图')}>
      {tabs.map(({ id, label }) => <Link key={id} to={href(id)} state={state} aria-current={active === id ? 'page' : undefined} className={active === id ? 'active' : ''}>{tr(label)}</Link>)}
    </nav>
    <RetainedFilters active={active} />
    <div ref={viewRef} className="connection-workspace-view">
      {active === 'health' ? <ConnectionHealthPage /> : active === 'trends' ? <NetworkTrends /> : <ConnectionsPage />}
    </div>
  </div>
}
