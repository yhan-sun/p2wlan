import { createContext, useContext, useState, type ReactNode } from 'react'
import { useIsFetching } from '@tanstack/react-query'
import { Clock3, RefreshCw, WifiOff } from 'lucide-react'
import { getLocale, tr } from './i18n'
import './refresh.css'

const RefreshContext = createContext({ enabled: true, setEnabled: (_enabled: boolean) => {} })

export function AdminRefreshProvider({ children }: { children: ReactNode }) {
  const [enabled, setEnabled] = useState(true)
  return <RefreshContext.Provider value={{ enabled, setEnabled }}>{children}</RefreshContext.Provider>
}

export function useAutoRefresh(interval = 15_000): number | false {
  return useContext(RefreshContext).enabled ? interval : false
}

export function RefreshToggle() {
  const { enabled, setEnabled } = useContext(RefreshContext)
  const fetching = useIsFetching()
  return <label className="refresh-toggle" title={tr('关闭后仍可手动刷新；切换页面会读取所需数据。')}>
    <RefreshCw size={14} className={fetching ? 'spin' : ''} aria-hidden />
    <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
    <span>{tr('自动刷新')}</span>
  </label>
}

interface QueryState {
  dataUpdatedAt: number
  fetchStatus: string
  error?: unknown
  refetch: () => unknown
}

// Retained data remains useful during outages, but must be labelled as a snapshot.
export function queryFreshness(queries: Pick<QueryState, 'dataUpdatedAt' | 'fetchStatus' | 'error'>[]) {
  const timestamps = queries.map((query) => query.dataUpdatedAt).filter((timestamp) => timestamp > 0)
  return {
    paused: queries.some((query) => query.fetchStatus === 'paused'),
    failed: queries.some((query) => Boolean(query.error)),
    fetching: queries.some((query) => query.fetchStatus === 'fetching'),
    updatedAt: timestamps.length ? Math.min(...timestamps) : 0,
  }
}

export function QueryStatus({ queries }: { queries: QueryState[] }) {
  const enabled = useContext(RefreshContext).enabled
  const state = queryFreshness(queries)
  const degraded = state.paused || state.failed
  const time = state.updatedAt ? new Intl.DateTimeFormat(getLocale(), { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(state.updatedAt) : ''
  return <div className={`query-status${degraded ? ' degraded' : ''}`} role={degraded ? 'alert' : 'status'}>
    {state.paused ? <WifiOff size={15} /> : <Clock3 size={15} />}
    <span>{tr(state.paused ? '当前离线，更新已暂停。' : state.failed ? '刷新失败。' : !enabled ? '自动刷新已关闭。' : state.fetching ? '正在更新…' : '自动刷新已开启。')}
      {time && <> {tr('最后成功更新：')}<time dateTime={new Date(state.updatedAt).toISOString()}>{time}</time></>}
      {degraded && state.updatedAt > 0 && <> {tr('以下为缓存快照，不能确认当前状态。')}</>}
    </span>
    {state.failed && !state.paused && <button type="button" className="button secondary compact" disabled={state.fetching} onClick={() => { for (const query of queries) void query.refetch() }}>{tr('重试')}</button>}
  </div>
}
