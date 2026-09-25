import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { ChevronRight, Search } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { adminApi } from '../../api'
import { PageHeader, Panel } from '../../components/ui/console'
import {
  AccountMark,
  CursorPagination,
  DataTable,
  ErrorBlock,
  PendingBlock,
  useDebouncedValue,
  formatAgo,
  formatDate,
} from '../../shared/console'
import type { AdminAccount } from '../../types'

const PAGE_SIZE = 25

export function AccountsPage() {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState('')
  const [cursorHistory, setCursorHistory] = useState<string[]>([])
  const debounced = useDebouncedValue(query)

  useEffect(() => {
    setCursor('')
    setCursorHistory([])
  }, [debounced])

  const result = useQuery({
    queryKey: ['accounts', 'cursor', debounced, cursor],
    queryFn: () => adminApi.accountsCursor(debounced, cursor, PAGE_SIZE),
  })

  const columns = useMemo<ColumnDef<AdminAccount, unknown>[]>(() => [
    { id: 'account', header: '账号', cell: ({ row }) => <div className="identity-cell"><AccountMark account={row.original} /><div><strong>{row.original.username}</strong><span>{row.original.email}</span></div></div> },
    { id: 'devices', header: '设备', cell: ({ row }) => <div className="ratio-cell"><strong>{row.original.online_devices}/{row.original.device_count}</strong><span>{row.original.device_count ? Math.round(row.original.online_devices / row.original.device_count * 100) : 0}% 在线</span></div> },
    { accessorKey: 'network_count', header: '网络' },
    { accessorKey: 'room_count', header: '房间' },
    { id: 'last_seen', header: '最近活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
    { id: 'created_at', header: '注册时间', cell: ({ row }) => formatDate(row.original.created_at) },
    { id: 'action', header: '', cell: () => <ChevronRight className="row-chevron" size={16} /> },
  ], [])

  const next = () => {
    if (!result.data?.next_cursor) return
    setCursorHistory((history) => [...history, cursor])
    setCursor(result.data.next_cursor)
  }

  const prev = () => {
    const previous = cursorHistory[cursorHistory.length - 1]
    if (previous === undefined) return
    setCursor(previous)
    setCursorHistory((history) => history.slice(0, -1))
  }

  return <div className="page-stack">
    <PageHeader
      eyebrow="IDENTITY"
      title="账号"
      description="账号按稳定 ID 游标翻页；最近活动只用于展示，不参与分页排序。"
      actions={<label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索用户名或邮箱" aria-label="搜索账号" /></label>}
    />
    <Panel>
      {result.isPending ? <PendingBlock queries={[result]} /> : result.error ? <ErrorBlock error={result.error} /> : result.data ? <>
        <DataTable<AdminAccount> columns={columns} data={result.data.items} onRowClick={(account) => navigate(`/accounts/${encodeURIComponent(account.id)}`)} empty="没有符合条件的账号" />
        <CursorPagination
          total={result.data.total}
          pageIndex={cursorHistory.length}
          itemCount={result.data.items.length}
          limit={PAGE_SIZE}
          canNext={Boolean(result.data.next_cursor)}
          onPrev={prev}
          onNext={next}
        />
      </> : <ErrorBlock error={new Error('Control 未返回账号列表。')} />}
    </Panel>
  </div>
}
