import { useMemo, useState } from 'react'
import dagre from '@dagrejs/dagre'
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react'
import { CircleAlert, Expand, Eye, EyeOff, MonitorSmartphone, Shrink } from 'lucide-react'
import type { AdminConnection } from './types'

const NODE_WIDTH = 220
const NODE_HEIGHT = 76

interface ConnectionTopologyProps {
  connections: AdminConnection[]
  networkName: string
  search?: string
  showStale: boolean
  partial?: boolean
  onShowStaleChange: (value: boolean) => void
  onSelect: (connection: AdminConnection) => void
}

interface DeviceNodeData {
  id: string
  name: string
  username: string
  freshInbound: number
  freshOutbound: number
}

function connectionKey(connection: AdminConnection): string {
  return `${connection.network_id}:${connection.reporting_device_id}:${connection.remote_device_id}`
}

function pathLabel(path?: string | null): string {
  if (!path) return 'None'
  if (path === 'direct') return 'Direct'
  if (path === 'relay') return 'Relay'
  return path.replaceAll('_', ' ')
}

function pathClass(connection: AdminConnection): string {
  if (!connection.fresh) return 'stale'
  if (connection.current_path === 'direct') return 'direct'
  if (connection.current_path === 'relay') return 'relay'
  return 'unknown'
}

function buildGraph(connections: AdminConnection[], search: string): { nodes: Node[]; edges: Edge[] } {
  const normalizedSearch = search.trim().toLowerCase()
  const devices = new Map<string, DeviceNodeData>()

  for (const connection of connections) {
    const reporting = devices.get(connection.reporting_device_id) ?? {
      id: connection.reporting_device_id,
      name: connection.reporting_device_name,
      username: connection.reporting_username,
      freshInbound: 0,
      freshOutbound: 0,
    }
    const remote = devices.get(connection.remote_device_id) ?? {
      id: connection.remote_device_id,
      name: connection.remote_device_name,
      username: connection.remote_username,
      freshInbound: 0,
      freshOutbound: 0,
    }
    if (connection.fresh) {
      reporting.freshOutbound += 1
      remote.freshInbound += 1
    }
    devices.set(reporting.id, reporting)
    devices.set(remote.id, remote)
  }

  let visibleConnections = connections
  let visibleDeviceIDs = new Set(devices.keys())
  if (normalizedSearch) {
    const matched = new Set(
      [...devices.values()]
        .filter((device) => [device.name, device.username].some((value) => value.toLowerCase().includes(normalizedSearch)))
        .map((device) => device.id),
    )
    if (matched.size === 0) return { nodes: [], edges: [] }
    visibleConnections = connections.filter(
      (connection) => matched.has(connection.reporting_device_id) || matched.has(connection.remote_device_id),
    )
    visibleDeviceIDs = new Set<string>()
    for (const connection of visibleConnections) {
      visibleDeviceIDs.add(connection.reporting_device_id)
      visibleDeviceIDs.add(connection.remote_device_id)
    }
  }

  const sortedDevices = [...devices.values()]
    .filter((device) => visibleDeviceIDs.has(device.id))
    .sort((a, b) => a.id.localeCompare(b.id))

  const graph = new dagre.graphlib.Graph()
  graph.setDefaultEdgeLabel(() => ({}))
  graph.setGraph({ rankdir: 'LR', ranksep: 120, nodesep: 56, edgesep: 26, marginx: 48, marginy: 48 })
  for (const device of sortedDevices) graph.setNode(device.id, { width: NODE_WIDTH, height: NODE_HEIGHT })
  for (const connection of visibleConnections) graph.setEdge(connection.reporting_device_id, connection.remote_device_id)
  dagre.layout(graph)

  const nodes: Node[] = sortedDevices.map((device) => {
    const point = graph.node(device.id) as { x: number; y: number } | undefined
    return {
      id: device.id,
      position: {
        x: (point?.x ?? 0) - NODE_WIDTH / 2,
        y: (point?.y ?? 0) - NODE_HEIGHT / 2,
      },
      data: {
        label: <div className="connection-node">
          <span className="connection-node-icon"><MonitorSmartphone size={17} /></span>
          <span className="connection-node-copy">
            <strong>{device.name}</strong>
            <small>{device.username} · {device.freshOutbound} out / {device.freshInbound} in</small>
          </span>
        </div>,
      },
      style: {
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        borderRadius: 10,
        border: '1px solid #d7dde6',
        background: '#fff',
        boxShadow: '0 4px 16px rgba(15, 23, 42, .06)',
        padding: 0,
      },
      draggable: false,
      selectable: false,
    }
  })

  const pairCounts = new Map<string, number>()
  for (const connection of visibleConnections) {
    const pair = [connection.reporting_device_id, connection.remote_device_id].sort().join(':')
    pairCounts.set(pair, (pairCounts.get(pair) ?? 0) + 1)
  }

  const edges: Edge[] = visibleConnections.map((connection) => {
    const kind = pathClass(connection)
    const pair = [connection.reporting_device_id, connection.remote_device_id].sort().join(':')
    const hasReverse = (pairCounts.get(pair) ?? 0) > 1
    const lexicalForward = connection.reporting_device_id.localeCompare(connection.remote_device_id) < 0
    const stroke = kind === 'direct' ? '#16803d' : kind === 'relay' ? '#2563eb' : '#98a2b3'
    const label = `${pathLabel(connection.current_path)}${connection.last_validation_rtt_ms !== undefined ? ` · ${connection.last_validation_rtt_ms} ms` : ''}${connection.fresh ? '' : ' · stale'}`
    return {
      id: connectionKey(connection),
      source: connection.reporting_device_id,
      target: connection.remote_device_id,
      type: 'smoothstep',
      pathOptions: { offset: hasReverse ? (lexicalForward ? 18 : 38) : 24, borderRadius: 14 },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
      label,
      labelStyle: { fontSize: 11, fill: kind === 'stale' ? '#667085' : '#344054', fontWeight: 650 },
      labelBgStyle: { fill: '#ffffff', fillOpacity: 0.94 },
      style: {
        stroke,
        strokeWidth: connection.fresh ? 2 : 1.6,
        strokeDasharray: connection.fresh ? undefined : '6 5',
        opacity: connection.fresh ? 0.88 : 0.58,
      },
      data: { connection },
      selectable: true,
      focusable: true,
      ariaLabel: `${connection.reporting_device_name} to ${connection.remote_device_name}: ${label}`,
    }
  })

  return { nodes, edges }
}

export function ConnectionTopology({
  connections,
  networkName,
  search = '',
  showStale,
  partial = false,
  onShowStaleChange,
  onSelect,
}: ConnectionTopologyProps) {
  const [fullscreen, setFullscreen] = useState(false)
  const graph = useMemo(() => buildGraph(connections, search), [connections, search])

  if (connections.length === 0) {
    return <div className="connection-topology-empty">
      <CircleAlert size={18} />
      <div><strong>暂无可展示的连接</strong><span>只有 daemon 权威上报的路径观测才会生成连接边。</span></div>
    </div>
  }

  if (search.trim() && graph.nodes.length === 0) {
    return <div className="connection-topology-empty"><CircleAlert size={18} />没有匹配的设备连接。</div>
  }

  return <div className={`connection-topology ${fullscreen ? 'fullscreen' : ''}`}>
    <div className="connection-topology-head">
      <div><strong>{networkName}</strong><span>{connections.length} 条 directional observation{partial ? ' · 当前视图已截断' : ''}</span></div>
      <div>
        <button className={`topology-filter-button ${showStale ? 'active' : ''}`} onClick={() => onShowStaleChange(!showStale)}>
          {showStale ? <Eye size={15} /> : <EyeOff size={15} />}Stale
        </button>
        <button className="icon-button topology-fullscreen-button" onClick={() => setFullscreen((value) => !value)} aria-label={fullscreen ? '退出全屏' : '全屏'}>
          {fullscreen ? <Shrink size={16} /> : <Expand size={16} />}
        </button>
      </div>
    </div>
    <ReactFlow
      nodes={graph.nodes}
      edges={graph.edges}
      fitView
      fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
      minZoom={0.2}
      maxZoom={1.7}
      nodesConnectable={false}
      nodesDraggable={false}
      onlyRenderVisibleElements
      onEdgeClick={(_, edge) => {
        const connection = edge.data?.connection as AdminConnection | undefined
        if (connection) onSelect(connection)
      }}
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#d8dee8" />
      <Controls showInteractive={false} position="bottom-left" />
      <MiniMap
        pannable
        zoomable
        nodeStrokeWidth={2}
        nodeColor={() => '#cbd5e1'}
      />
    </ReactFlow>
    <div className="connection-topology-legend">
      <span><i className="connection-legend-line direct" />Direct</span>
      <span><i className="connection-legend-line relay" />Relay</span>
      {showStale && <span><i className="connection-legend-line stale" />Stale</span>}
    </div>
  </div>
}
