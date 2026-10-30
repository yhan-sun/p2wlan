import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table'
import { ChevronLeft, ChevronRight, CircleAlert } from 'lucide-react'
import { useEffect, useState, type CSSProperties } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { accountColor, colorWithAlpha } from '../colors'
import { getLocale, tr } from '../i18n'
import { readResourceReturn } from '../pageState'
import type { AdminAccount, AdminTopology } from '../types'

export function formatAgo(unix?: number): string {
  if (!unix) return tr('从未')
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
  return new Intl.DateTimeFormat(locale, { month: '2-digit', day: '2-digit', year: 'numeric' }).format(new Date(unix * 1000))
}

export function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat(getLocale(), {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  }).format(new Date(unix * 1000))
}

export function formatDuration(seconds?: number): string {
  let value = Math.max(0, seconds ?? 0)
  const days = Math.floor(value / 86400)
  value %= 86400
  const hours = Math.floor(value / 3600)
  value %= 3600
  const minutes = Math.floor(value / 60)
  if (getLocale() === 'en-US') {
    if (days) return `${days}d ${hours}h`
    if (hours) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }
  if (days) return `${days} 天 ${hours} 小时`
  if (hours) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}

export function natLabel(value: string): string {
  if (!value || value.toLowerCase() === 'unknown') return tr('Unknown')
  const match = value.match(/(?:^|;)m=([^;]+)/i)
  const normalized = (match?.[1] ?? value).replaceAll('_', ' ')
  return tr(getLocale() === 'zh-CN' ? normalized.toLowerCase() : normalized)
}

export function useDebouncedValue<T>(value: T, delay = 250): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [value, delay])
  return debounced
}

export function AccountMark({ account, size = 'normal' }: { account: Pick<AdminAccount, 'id' | 'username'>; size?: 'normal' | 'small' | 'large' }) {
  const color = accountColor(account.id)
  const initials = (account.username || '?').trim().slice(0, 2).toUpperCase()
  return <span className={`account-mark ${size}`} style={{
    '--account-mark-color': color,
    color,
    background: colorWithAlpha(color, 0.12),
    borderColor: colorWithAlpha(color, 0.22),
  } as CSSProperties}>{initials}</span>
}

export function Status({ online }: { online: boolean }) {
  return <span className={`status-label ${online ? 'online' : ''}`}><span />{tr(online ? '在线' : '离线')}</span>
}

export function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block" role="status" aria-live="polite"><div className="spinner" />{tr(label)}</div>
}

export function ErrorBlock({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block" role="alert"><CircleAlert size={18} /><div><strong>{tr("无法加载数据")}</strong><span>{tr(message)}</span></div>{onRetry && <button className="button secondary compact" onClick={onRetry}>{tr("重试")}</button>}</div>
}

// A paused query (the browser is offline) is neither loading nor failed:
// react-query keeps isPending true while isFetching is false, so gating a page
// on isLoading would render nothing at all, with no message and no retry hint.
export function PendingBlock({ queries, label = '加载中…' }: { queries: { fetchStatus: string }[]; label?: string }) {
  if (queries.some((query) => query.fetchStatus === 'paused')) {
    return <ErrorBlock error={new Error('浏览器当前离线，无法访问控制面。网络恢复后会自动重新请求。')} />
  }
  return <LoadingBlock label={label} />
}

// Control owns whether a live Direct/Relay path is observable at all. Render the
// control plane's own statement, and only fall back to the localized
// explanation while the control plane confirms the path is not observable —
// otherwise the console would keep asserting something it no longer knows.
export function PathNotice({ data, fallback }: { data?: AdminTopology; fallback: string }) {
  const note = data?.path_observation_available ? data.path_observation_note : ''
  return <div className="truth-notice"><CircleAlert size={15} /><span>{tr(note || fallback)}</span></div>
}

export { MetricCard, Panel } from '../components/ui/console'

export function DataTable<T>({ columns, data, onRowClick, empty = '暂无数据' }: {
  columns: ColumnDef<T, unknown>[]
  data: T[]
  onRowClick?: (row: T) => void
  empty?: string
}) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() })
  const rows = table.getRowModel().rows
  return <div className="data-table-container">
    <div className="data-table-wrap"><table className="data-table">
      <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
        const heading = header.column.columnDef.header
        return <th key={header.id} scope="col">{header.isPlaceholder ? null : typeof heading === 'string' ? tr(heading) : flexRender(heading, header.getContext())}</th>
      })}</tr>)}</thead>
      <tbody>
        {rows.map((row) => <tr key={row.id} className={onRowClick ? 'clickable' : ''} tabIndex={onRowClick ? 0 : undefined} onClick={() => onRowClick?.(row.original)} onKeyDown={(event) => {
          if (onRowClick && (event.key === 'Enter' || event.key === ' ')) {
            event.preventDefault()
            onRowClick(row.original)
          }
        }}>{row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}
        {data.length === 0 && <tr><td className="table-empty" colSpan={columns.length}>{tr(empty)}</td></tr>}
      </tbody>
    </table></div>
    <div className="data-mobile-list">
      {rows.map((row) => {
        const cells = row.getVisibleCells().filter((cell) => {
          const heading = table.getColumn(cell.column.id)?.columnDef.header
          return typeof heading === 'string' && heading.trim().length > 0
        })
        const [primary, ...details] = cells
        const content = <>
          {primary && <div className="data-mobile-card-primary">{flexRender(primary.column.columnDef.cell, primary.getContext())}</div>}
          <div className="data-mobile-facts">
            {details.map((cell) => <div className="data-mobile-fact" key={cell.id}>
              <span>{tr(table.getColumn(cell.column.id)?.columnDef.header as string)}</span>
              <div>{flexRender(cell.column.columnDef.cell, cell.getContext())}</div>
            </div>)}
          </div>
        </>
        return onRowClick
          ? <button type="button" className="data-mobile-card clickable" key={row.id} onClick={() => onRowClick(row.original)}>{content}</button>
          : <article className="data-mobile-card" key={row.id}>{content}</article>
      })}
      {rows.length === 0 && <div className="data-mobile-empty">{tr(empty)}</div>}
    </div>
  </div>
}

export function Pagination({ total, offset, limit, onChange }: { total: number; offset: number; limit: number; onChange: (offset: number) => void }) {
  const start = total === 0 || offset >= total ? 0 : offset + 1
  const end = start === 0 ? 0 : Math.min(total, offset + limit)
  return <div className="pagination-v2"><span>{start}{tr("–")}{end} {tr("/ ")}{total}</span><div>
    <button className="button secondary compact" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}><ChevronLeft size={15} />{tr("上一页")}</button>
    <button className="button secondary compact" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>{tr("下一页")}<ChevronRight size={15} /></button>
  </div></div>
}

export function CursorPagination({ total, pageIndex, itemCount, canNext, canPrev = pageIndex > 0, previousIsFirst = false, onPrev, onNext }: {
  total: number
  pageIndex: number
  itemCount: number
  limit: number
  canNext: boolean
  canPrev?: boolean
  previousIsFirst?: boolean
  onPrev: () => void
  onNext: () => void
}) {
  return <div className="pagination-v2"><span>{tr('本页 ')}{itemCount}{tr(' 条 · 共 ')}{total}{tr(' 条')}</span><div>
    <button className="button secondary compact" disabled={!canPrev} onClick={onPrev}><ChevronLeft size={15} />{tr(previousIsFirst ? "返回首页" : "上一页")}</button>
    <button className="button secondary compact" disabled={!canNext} onClick={onNext}>{tr("下一页")}<ChevronRight size={15} /></button>
  </div></div>
}


export function ResourceTabs({ id, label, tabs, value, onChange }: {
  id: string; label: string; tabs: { value: string; label: string }[]; value: string; onChange: (value: string) => void
}) {
  const [focused, setFocused] = useState(value)
  useEffect(() => setFocused(value), [value])
  return <div className="tabs-v2" role="tablist" aria-label={tr(label)} onBlur={(event) => {
    if (!event.currentTarget.contains(event.relatedTarget)) setFocused(value)
  }}>
    {tabs.map((tab, index) => <button key={tab.value} type="button" role="tab" id={`${id}-${tab.value}`} aria-controls={`${id}-panel`} aria-selected={tab.value === value} tabIndex={tab.value === focused ? 0 : -1} className={tab.value === value ? 'active' : ''} onFocus={() => setFocused(tab.value)} onClick={() => { if (tab.value !== value) onChange(tab.value) }} onKeyDown={(event) => {
      const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1
      if (next < 0) return
      event.preventDefault()
      setFocused(tabs[next].value)
      const buttons = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')
      buttons?.[next].focus()
    }}>{tab.label}</button>)}
  </div>
}

export function ResourceReturnLink() {
  const location = useLocation()
  const origin = readResourceReturn(location.state)
  return origin ? <div className="resource-return"><Link className="text-link" to={origin.to} state={origin.state}><ChevronLeft size={15} />{tr(origin.label)}</Link></div> : null
}

export function ResourceEmptyState({ message, description, onClear, onReset, action }: {
  message: string
  description?: string
  onClear?: () => void
  onReset?: () => void
  action?: { to: string; label: string }
}) {
  return <div className="resource-empty-state" role="status">
    <strong>{tr(message)}</strong>
    {description && <p>{tr(description)}</p>}
    {onReset ? <button type="button" className="button secondary" onClick={onReset}>{tr('重新从首页加载')}</button>
      : onClear ? <button type="button" className="button secondary" onClick={onClear}>{tr('清除筛选')}</button>
        : action && <Link className="button secondary" to={action.to}>{tr(action.label)}</Link>}
  </div>
}
