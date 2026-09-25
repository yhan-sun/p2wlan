import { useMemo } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { DataTable, Status, formatAgo, natLabel } from '../../shared/console'
import type { AdminDevice, AdminNetwork, AdminRoom } from '../../types'

export function DeviceTable({ devices }: { devices: AdminDevice[] }) {
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.device_name}</strong><span>{row.original.platform} · {row.original.app_version || '未知版本'}</span></div> },
    { accessorKey: 'network_name', header: '网络' },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="mono">{row.original.virtual_ip}</span> },
    { id: 'nat', header: 'NAT', cell: ({ row }) => natLabel(row.original.nat_type) },
    { id: 'rtt', header: 'Relay RTT', cell: ({ row }) => row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` },
    { id: 'status', header: '状态', cell: ({ row }) => <Status online={row.original.online} /> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [])
  return <DataTable<AdminDevice> columns={columns} data={devices} empty="该账号还没有设备" />
}

export function NetworkTable({ networks }: { networks: AdminNetwork[] }) {
  const columns = useMemo<ColumnDef<AdminNetwork, unknown>[]>(() => [
    { id: 'name', header: '网络', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.name}</strong><span className="mono">{row.original.id}</span></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { accessorKey: 'owner_username', header: '所有者' },
    { accessorKey: 'member_count', header: '成员' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} 在线` },
    { id: 'type', header: '类型', cell: ({ row }) => <span className={`badge ${row.original.is_room ? 'purple' : ''}`}>{row.original.is_room ? '房间网络' : '普通网络'}</span> },
  ], [])
  return <DataTable<AdminNetwork> columns={columns} data={networks} empty="该账号还没有网络" />
}

export function RoomTable({ rooms }: { rooms: AdminRoom[] }) {
  const columns = useMemo<ColumnDef<AdminRoom, unknown>[]>(() => [
    { id: 'name', header: '房间', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.name}</strong><span className="mono">#{row.original.code}</span></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { accessorKey: 'owner_username', header: '所有者' },
    { accessorKey: 'member_count', header: '成员' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} 在线` },
    { id: 'join', header: '加入', cell: ({ row }) => <span className={`badge ${row.original.join_locked ? 'warning' : 'success'}`}>{row.original.join_locked ? '已锁定' : '可加入'}</span> },
  ], [])
  return <DataTable<AdminRoom> columns={columns} data={rooms} empty="该账号没有加入房间" />
}
