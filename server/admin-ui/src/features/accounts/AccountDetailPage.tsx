import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { adminApi } from '../../api'
import { accountColor } from '../../colors'
import { Panel, SegmentedControl } from '../../components/ui/console'
import { AccountMark, ErrorBlock, PathNotice, PendingBlock } from '../../shared/console'
import { TopologyCanvas } from '../relationships/TopologyCanvas'
import { DeviceTable, NetworkTable, RoomTable } from '../resources/ResourceTables'

export function AccountDetailPage() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<'topology' | 'devices' | 'networks' | 'rooms'>('topology')
  const detail = useQuery({ queryKey: ['account', id], queryFn: () => adminApi.account(id), enabled: Boolean(id) })
  const topology = useQuery({ queryKey: ['topology', 'account', id], queryFn: () => adminApi.topology(id), enabled: Boolean(id) })
  if (detail.isPending) return <PendingBlock queries={[detail]} label="正在加载账号…" />
  if (detail.error) return <ErrorBlock error={detail.error} />
  if (!detail.data) return <ErrorBlock error={new Error('Control 未返回该账号详情，请返回账号列表重试。')} />
  const account = detail.data.account
  const color = accountColor(account.id)

  return <div className="page-stack">
    <section className="account-hero">
      <AccountMark account={account} size="large" />
      <div className="account-hero-copy"><span className="account-color-label" style={{ color }}>ACCOUNT</span><h2>{account.username}</h2><p>{account.email}</p></div>
      <div className="account-hero-stats"><div><strong>{account.device_count}</strong><span>设备</span></div><div><strong className="positive-text">{account.online_devices}</strong><span>在线</span></div><div><strong>{account.network_count}</strong><span>网络</span></div><div><strong>{account.room_count}</strong><span>房间</span></div></div>
    </section>

    <SegmentedControl
      label="账号详情视图"
      value={tab}
      onChange={setTab}
      options={[
        { value: 'topology', label: '关系' },
        { value: 'devices', label: `设备 ${account.device_count}` },
        { value: 'networks', label: `网络 ${account.network_count}` },
        { value: 'rooms', label: `房间 ${account.room_count}` },
      ]}
    />

    {tab === 'topology' && <Panel title={`${account.username} 的资源关系`} subtitle="包含该账号以及共享网络 / 房间中的对端账号和设备">
      <PathNotice data={topology.data} fallback="这是 Control 资源关系图：只展示成员关系、设备挂载和可选的待处理 signaling。daemon 权威路径观测保存在独立的 Connections 工作区，这里不会把它们混成资源关系。" />
      <TopologyCanvas data={topology.data} loading={topology.isPending} error={topology.error instanceof Error ? topology.error.message : undefined} />
    </Panel>}
    {tab === 'devices' && <Panel><DeviceTable devices={detail.data.devices} /></Panel>}
    {tab === 'networks' && <Panel><NetworkTable networks={detail.data.networks} /></Panel>}
    {tab === 'rooms' && <Panel><RoomTable rooms={detail.data.rooms} /></Panel>}
  </div>
}
