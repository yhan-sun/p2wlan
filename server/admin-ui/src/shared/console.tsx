import { useEffect, useState } from 'react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { ChevronLeft, ChevronRight, CircleAlert } from 'lucide-react'
import { accountColor, colorWithAlpha } from '../colors'
import type { AdminAccount, AdminTopology } from '../types'

export function formatAgo(unix?: number): string {
  if (!unix) return '从未'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  if (seconds < 45) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} 天前`
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', year: 'numeric' }).format(new Date(unix * 1000))
}

export function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
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
  if (days) return `${days} 天 ${hours} 小时`
  if (hours) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}

export function natLabel(value: string): string {
  if (!value || value.toLowerCase() === 'unknown') return 'Unknown'
  const match = value.match(/(?:^|;)m=([^;]+)/i)
  return (match?.[1] ?? value).replaceAll('_', ' ')
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
  return <span className={`account-mark ${size}`} style={{ color, background: colorWithAlpha(color, 0.12), borderColor: colorWithAlpha(color, 0.22) }}>{initials}</span>
}

export function Status({ online }: { online: boolean }) {
  return <span className={`status-label ${online ? 'online' : ''}`}><span />{online ? '在线' : '离线'}</span>
}

export function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block"><div className="spinner" />{label}</div>
}

export function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>无法加载数据</strong><span>{message}</span></div></div>
}

// A paused query (the browser is offline) is neither loading nor failed:
// react-query keeps isPending true while isFetching is false, so gating a page
// on isLoading would render nothing at all, with no message and no retry hint.
export function PendingBlock({ queries, label = '加载中…' }: { queries: { fetchStatus: string }[]; label?: string }) {
  if (queries.some((query) => query.fetchStatus === 'paused')) {
    return <ErrorBlock error={new Error('浏览器当前离线，无法访问 Control。恢复网络后会自动重新请求。')} />
  }
  return <LoadingBlock label={label} />
}

// Control owns whether a live Direct/Relay path is observable at all. Render the
// control plane's own statement, and only fall back to the localized
// explanation while the control plane confirms the path is not observable —
// otherwise the console would keep asserting something it no longer knows.
export function PathNotice({ data, fallback }: { data?: AdminTopology; fallback: string }) {
  const note = data?.path_observation_available ? data.path_observation_note : ''
  return <div className="truth-notice"><CircleAlert size={15} /><span>{note || fallback}</span></div>
}

export function DataTable<T>({ columns, data, onRowClick, empty = '暂无数据' }: {
  columns: ColumnDef<T, unknown>[]
  data: T[]
  onRowClick?: (row: T) => void
  empty?: string
}) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() })
  return <div className="data-table-wrap"><table className="data-table">
    <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => <th key={header.id}>{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}</th>)}</tr>)}</thead>
    <tbody>
      {table.getRowModel().rows.map((row) => <tr key={row.id} className={onRowClick ? 'clickable' : ''} onClick={() => onRowClick?.(row.original)}>{row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}
      {data.length === 0 && <tr><td className="table-empty" colSpan={columns.length}>{empty}</td></tr>}
    </tbody>
  </table></div>
}

export function Pagination({ total, offset, limit, onChange }: { total: number; offset: number; limit: number; onChange: (offset: number) => void }) {
  const start = total === 0 ? 0 : offset + 1
  const end = Math.min(total, offset + limit)
  return <div className="pagination-v2"><span>{start}–{end} / {total}</span><div>
    <button className="button secondary compact" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}><ChevronLeft size={15} />上一页</button>
    <button className="button secondary compact" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>下一页<ChevronRight size={15} /></button>
  </div></div>
}

export function CursorPagination({ total, pageIndex, itemCount, limit, canNext, onPrev, onNext }: {
  total: number
  pageIndex: number
  itemCount: number
  limit: number
  canNext: boolean
  onPrev: () => void
  onNext: () => void
}) {
  const start = itemCount === 0 ? 0 : pageIndex * limit + 1
  const end = itemCount === 0 ? 0 : start + itemCount - 1
  return <div className="pagination-v2"><span>{start}–{Math.min(end, total)} / {total}</span><div>
    <button className="button secondary compact" disabled={pageIndex === 0} onClick={onPrev}><ChevronLeft size={15} />上一页</button>
    <button className="button secondary compact" disabled={!canNext} onClick={onNext}>下一页<ChevronRight size={15} /></button>
  </div></div>
}
