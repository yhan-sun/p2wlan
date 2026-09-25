import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { adminApi } from '../../api'
import { Panel } from '../../components/ui/console'
import { ErrorBlock, PendingBlock } from '../../shared/console'
import { NetworkTable, RoomTable } from '../resources/ResourceTables'

const PAGE_SIZE = 25

export function NetworksPage() {
  const [tab, setTab] = useState<'networks' | 'rooms'>('networks')
  const [networkOffset, setNetworkOffset] = useState(0)
  const [roomOffset, setRoomOffset] = useState(0)
  const networks = useQuery({
    queryKey: ['networks', networkOffset],
    queryFn: () => adminApi.networks(PAGE_SIZE, networkOffset),
  })
  const rooms = useQuery({
    queryKey: ['rooms', roomOffset],
    queryFn: () => adminApi.rooms(PAGE_SIZE, roomOffset),
  })
  const error = networks.error || rooms.error
  if (networks.isPending || rooms.isPending) return <PendingBlock queries={[networks, rooms]} />
  if (error) return <ErrorBlock error={error} />
  if (!networks.data || !rooms.data) return <ErrorBlock error={new Error('Control 未返回完整的网络与房间列表。')} />

  return <div className="page-stack">
    <div className="page-intro"><div><h2>网络与房间</h2><p>按页读取 Control 数据，避免大规模部署打开页面时一次扫完整个集合。</p></div></div>
    <div className="tabs-v2"><button className={tab === 'networks' ? 'active' : ''} onClick={() => setTab('networks')}>网络 {networks.data.total}</button><button className={tab === 'rooms' ? 'active' : ''} onClick={() => setTab('rooms')}>房间 {rooms.data.total}</button></div>
    <Panel>{tab === 'networks'
      ? <><NetworkTable networks={networks.data.items} /><Pagination total={networks.data.total} offset={networkOffset} limit={PAGE_SIZE} onChange={setNetworkOffset} /></>
      : <><RoomTable rooms={rooms.data.items} /><Pagination total={rooms.data.total} offset={roomOffset} limit={PAGE_SIZE} onChange={setRoomOffset} /></>}
    </Panel>
  </div>
}
