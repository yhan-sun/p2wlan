import { useEffect, useId, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, ChevronDown, ChevronLeft, ChevronRight, Search, X } from 'lucide-react'
import { adminApi } from './api'
import { tr } from './i18n'
import type { AdminAccount } from './types'
import { useOverlay } from './useOverlay'
import './account-scope-picker.css'

type AccountScope = Pick<AdminAccount, 'id' | 'username'>
const PAGE_SIZE = 25

export function AccountScopePicker({ value, onChange }: {
  value: AccountScope | null
  onChange: (value: AccountScope | null) => void
}) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [cursors, setCursors] = useState([''])
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const panelId = useId()
  useOverlay(open, () => { setOpen(false); triggerRef.current?.focus() }, { lockScroll: false })

  useEffect(() => {
    const timeout = window.setTimeout(() => { setQuery(search.trim()); setCursors(['']) }, 250)
    return () => window.clearTimeout(timeout)
  }, [search])

  useEffect(() => {
    if (!open) return
    const frame = window.requestAnimationFrame(() => searchRef.current?.focus())
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)
    return () => {
      window.cancelAnimationFrame(frame)
      document.removeEventListener('pointerdown', outside)
    }
  }, [open])

  const cursor = cursors[cursors.length - 1]
  const result = useQuery({
    queryKey: ['accounts', 'scope-picker', query, cursor],
    queryFn: ({ signal }) => adminApi.accountsCursor(query, cursor, PAGE_SIZE, signal),
    enabled: open,
    gcTime: 60_000,
  })
  const searching = search.trim() !== query
  const choose = (account: AccountScope | null) => {
    onChange(account)
    setOpen(false)
    triggerRef.current?.focus()
  }

  return <div className="account-scope-picker" ref={rootRef} onBlur={(event) => {
    if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setOpen(false)
  }}>
    <button ref={triggerRef} type="button" className="select-field account-scope-trigger" aria-label={`${tr('筛选账号')}: ${value?.username ?? tr('全部账号')}`} aria-expanded={open} aria-controls={panelId} aria-haspopup="dialog" onClick={() => setOpen((current) => !current)}>
      <span>{value?.username ?? tr('全部账号')}</span><ChevronDown size={15} />
    </button>
    {open && <section id={panelId} className="account-scope-panel" role="dialog" aria-label={tr('账号筛选')}>
      <header><strong>{tr('筛选账号')}</strong><button type="button" className="icon-button-v2" aria-label={tr('关闭账号筛选')} onClick={() => { setOpen(false); triggerRef.current?.focus() }}><X size={15} /></button></header>
      <div className="search-field"><Search size={15} /><input ref={searchRef} aria-label={tr('搜索账号')} placeholder={tr('搜索用户名或邮箱')} value={search} onChange={(event) => setSearch(event.target.value)} /></div>
      <button type="button" className="account-scope-option" aria-pressed={!value} onClick={() => choose(null)}><span>{tr('全部账号')}</span>{!value && <Check size={15} />}</button>
      <div className="account-scope-results" aria-busy={result.isFetching || searching}>
        {result.fetchStatus === 'paused' ? <p role="alert">{tr('浏览器当前离线，无法访问控制面。网络恢复后会自动重新请求。')}</p> : result.isPending || searching ? <p role="status">{tr('加载中…')}</p> : result.isError ? <div role="alert"><p>{tr('无法加载数据')}</p><button type="button" className="button secondary compact" onClick={() => result.refetch()}>{tr('重试')}</button></div> : <>
          {result.data.items.map((account) => <button type="button" className="account-scope-option" key={account.id} aria-pressed={value?.id === account.id} onClick={() => choose(account)}><span><strong>{account.username}</strong><small>{account.email}</small></span>{value?.id === account.id && <Check size={15} />}</button>)}
          {result.data.items.length === 0 && <p>{tr('没有符合条件的账号')}</p>}
        </>}
      </div>
      <footer>
        <button type="button" className="button secondary compact" disabled={cursors.length === 1 || result.isFetching || searching} onClick={() => setCursors((current) => current.slice(0, -1))}><ChevronLeft size={14} />{tr('上一页')}</button>
        <span>{cursors.length}</span>
        <button type="button" className="button secondary compact" disabled={!result.data?.next_cursor || result.isFetching || searching || result.isError || result.fetchStatus === 'paused'} onClick={() => { if (result.data?.next_cursor) setCursors((current) => [...current, result.data.next_cursor!]) }}>{tr('下一页')}<ChevronRight size={14} /></button>
      </footer>
    </section>}
  </div>
}
