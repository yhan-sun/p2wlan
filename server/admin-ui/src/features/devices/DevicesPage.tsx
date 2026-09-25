import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Search } from 'lucide-react'
import { adminApi } from '../../api'
import { PageHeader, Panel, StatusPill } from '../../components/ui/console'
import {
  DataTable,
  ErrorBlock,
  Pagination,
  PendingBlock,
  formatAgo,
  natLabel,
  useDebouncedValue,
} from '../../shared/console'
import type { AdminDevice } from '../../types'

const PAGE_SIZE = 25

export function DevicesPage() {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [offset, setOffset] = useState(0)
  const debounced = useDebouncedValue(query)
  useEffect(() => setOffset(0), [debounced, status])
  const result = useQuery({ queryKey: ['devices', debounced, status, offset], queryFn: () => adminApi.devices(debounced, status, PAGE_SIZE, offset) })
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.device_name}</strong><span>{row.original.platform} · {row.original.app_version || '未知版本'}</span></div> },
    { accessorKey: 'username', header: '账号' },
    { accessorKey: 'network_name', header: '网络' },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="mono">{row.original.virtual_ip}</span> },
    { id: 'nat', header: 'NAT', cell: ({ row }) => natLabel(row.original.nat_type) },
    { id: 'rtt', header: 'Relay RTT', cell: ({ row }) => row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` },
    { id: 'status', header: '状态', cell: ({ row }) => <StatusPill tone={row.original.online ? 'success' : 'neutral'} dot>{row.original.online ? '在线' : '离线'}</StatusPill> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [])

  return <div className="page-stack">
    <PageHeader
      eyebrow="DEVICES"
      title="设备"
      description="全部账号下已注册的 P2WLAN 设备。"
      actions={<div className="toolbar-controls">
        <label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索设备、账号、IP 或网络" aria-label="搜索设备" /></label>
        <select className="select-field" value={status} onChange={(event) => setStatus(event.target.value)} aria-label="按在线状态过滤"><option value="all">全部状态</option><option value="online">在线</option><option value="offline">离线</option></select>
      </div>}
    />
    <Panel>{result.isPending ? <PendingBlock queries={[result]} /> : result.error ? <ErrorBlock error={result.error} /> : result.data ? <><DataTable<AdminDevice> columns={columns} data={result.data.items} /><Pagination total={result.data.total} offset={offset} limit={PAGE_SIZE} onChange={setOffset} /></> : <ErrorBlock error={new Error('Control 未返回设备列表。')} />}</Panel>
  </div>
}
