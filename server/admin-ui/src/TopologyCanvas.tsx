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
import {
  Box,
  CircleAlert,
  Expand,
  Laptop,
  Network,
  RadioTower,
  Server,
  Shrink,
  Smartphone,
  Users,
  X,
} from 'lucide-react'
import { accountColor, colorWithAlpha } from './colors'
import type { AdminTopology, AdminTopologyNode } from './types'

interface TopologyCanvasProps {
  data?: AdminTopology
  loading?: boolean
  error?: string
  search?: string
  compact?: boolean
}

const dimensions: Record<AdminTopologyNode['kind'], { width: number; height: number }> = {
  account: { width: 220, height: 84 },
  network: { width: 210, height: 82 },
  room: { width: 210, height: 82 },
  device: { width: 232, height: 88 },
}

function DeviceIcon({ platform }: { platform?: string }) {
  const normalized = platform?.toLowerCase() ?? ''
  if (normalized.includes('android') || normalized.includes('ios')) return <Smartphone size={17} />
  if (normalized.includes('server') || normalized.includes('linux')) return <Server size={17} />
  return <Laptop size={17} />
}

function nodeIcon(node: AdminTopologyNode) {
  if (node.kind === 'account') return <Users size={17} />
  if (node.kind === 'room') return <RadioTower size={17} />
  if (node.kind === 'network') return <Network size={17} />
  return <DeviceIcon platform={node.platform} />
}

function nodeMeta(node: AdminTopologyNode): string {
  if (node.kind === 'account') return node.focus ? '当前账号' : '账号'
  if (node.kind === 'room') return [node.room_code && `#${node.room_code}`, node.cidr].filter(Boolean).join(' · ')
  if (node.kind === 'network') return node.cidr || '网络'
  return [node.virtual_ip, node.platform].filter(Boolean).join(' · ')
}

function TopologyNodeLabel({ node }: { node: AdminTopologyNode }) {
  const color = accountColor(node.account_id || (node.kind === 'account' ? node.account_id : node.owner_id))
  return (
    <div className="topology-node-content">
      <div className="topology-node-icon" style={{ color, background: colorWithAlpha(color, 0.11) }}>
        {nodeIcon(node)}
      </div>
      <div className="topology-node-copy">
        <div className="topology-node-title-row">
          <strong>{node.label}</strong>
          {node.kind === 'device' && <span className={`presence-dot ${node.online ? 'online' : ''}`} />}
        </div>
        <span>{nodeMeta(node)}</span>
      </div>
    </div>
  )
}

function buildGraph(data: AdminTopology, search: string): { nodes: Node[]; edges: Edge[] } {
  const graph = new dagre.graphlib.Graph()
  graph.setDefaultEdgeLabel(() => ({}))
  graph.setGraph({ rankdir: 'LR', ranksep: 100, nodesep: 34, edgesep: 20, marginx: 40, marginy: 40 })

  const normalizedSearch = search.trim().toLowerCase()
  const sourceNodes = new Map(data.nodes.map((node) => [node.id, node]))
  const matches = (node: AdminTopologyNode) => {
    if (!normalizedSearch) return true
    return [node.label, node.username, node.virtual_ip, node.cidr, node.room_code, node.platform]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(normalizedSearch))
  }

  for (const node of data.nodes) {
    const size = dimensions[node.kind]
    graph.setNode(node.id, size)
  }
  for (const edge of data.edges) {
    if (edge.kind !== 'pending_signal') graph.setEdge(edge.source, edge.target)
  }
  dagre.layout(graph)

  const nodes: Node[] = data.nodes.map((node) => {
    const size = dimensions[node.kind]
    const point = graph.node(node.id) as { x: number; y: number } | undefined
    const ownerColor = accountColor(node.account_id || (node.kind === 'account' ? node.account_id : node.owner_id))
    const isMatch = matches(node)
    const neutral = node.kind === 'network' || node.kind === 'room'
    return {
      id: node.id,
      position: {
        x: (point?.x ?? 0) - size.width / 2,
        y: (point?.y ?? 0) - size.height / 2,
      },
      data: { label: <TopologyNodeLabel node={node} /> },
      style: {
        width: size.width,
        height: size.height,
        padding: 0,
        borderRadius: 13,
        border: node.focus ? `2px solid ${ownerColor}` : neutral ? '1px solid #cbd5e1' : `1px solid ${colorWithAlpha(ownerColor, 0.42)}`,
        background: neutral ? '#ffffff' : colorWithAlpha(ownerColor, node.focus ? 0.09 : 0.045),
        boxShadow: node.focus ? `0 0 0 4px ${colorWithAlpha(ownerColor, 0.10)}, 0 8px 24px rgba(15, 23, 42, .08)` : '0 4px 16px rgba(15, 23, 42, .055)',
        color: '#0f172a',
        opacity: isMatch ? 1 : 0.18,
        transition: 'opacity 150ms ease, box-shadow 150ms ease',
      },
      draggable: false,
      selectable: true,
    }
  })

  const edges: Edge[] = data.edges.map((edge) => {
    const source = sourceNodes.get(edge.source)
    const target = sourceNodes.get(edge.target)
    const colorSource = edge.kind === 'attachment' ? target : source
    const color = accountColor(colorSource?.account_id || (colorSource?.kind === 'account' ? colorSource.account_id : colorSource?.owner_id))
    const endpointsMatch = (!normalizedSearch || (source && matches(source)) || (target && matches(target)))
    const isSignal = edge.kind === 'pending_signal'
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated: false,
      style: {
        stroke: isSignal ? '#d97706' : color,
        strokeWidth: isSignal ? 1.6 : edge.kind === 'membership' ? 1.8 : 1.4,
        strokeDasharray: isSignal ? '6 5' : undefined,
        opacity: endpointsMatch ? (isSignal ? 0.78 : 0.48) : 0.08,
      },
      markerEnd: isSignal ? { type: MarkerType.ArrowClosed, color: '#d97706', width: 14, height: 14 } : undefined,
      label: isSignal && edge.count && edge.count > 1 ? `${edge.signal_type} ×${edge.count}` : undefined,
      labelStyle: { fontSize: 10, fill: '#92400e' },
      labelBgStyle: { fill: '#fffbeb', fillOpacity: 0.95 },
    }
  })

  return { nodes, edges }
}

function DetailPanel({ node, onClose }: { node: AdminTopologyNode; onClose: () => void }) {
  const color = accountColor(node.account_id || (node.kind === 'account' ? node.account_id : node.owner_id))
  return (
    <div className="topology-detail">
      <button className="icon-button topology-detail-close" onClick={onClose} aria-label="关闭详情"><X size={16} /></button>
      <div className="topology-detail-type" style={{ color }}>{node.kind.toUpperCase()}</div>
      <h3>{node.label}</h3>
      {node.username && node.kind !== 'account' && <p className="topology-detail-owner">账号 · {node.username}</p>}
      <dl>
        {node.virtual_ip && <div><dt>Virtual IP</dt><dd className="mono">{node.virtual_ip}</dd></div>}
        {node.cidr && <div><dt>CIDR</dt><dd className="mono">{node.cidr}</dd></div>}
        {node.room_code && <div><dt>房间号</dt><dd className="mono">{node.room_code}</dd></div>}
        {node.platform && <div><dt>平台</dt><dd>{node.platform}</dd></div>}
        {node.app_version && <div><dt>版本</dt><dd>{node.app_version}</dd></div>}
        {node.nat_type && <div><dt>NAT</dt><dd>{node.nat_type}</dd></div>}
        {node.relay_rtt_ms !== undefined && <div><dt>Relay RTT</dt><dd>{node.relay_rtt_ms} ms</dd></div>}
        {node.online !== undefined && <div><dt>状态</dt><dd><span className={`status-label ${node.online ? 'online' : ''}`}><span />{node.online ? '在线' : '离线'}</span></dd></div>}
      </dl>
    </div>
  )
}

export function TopologyCanvas({ data, loading, error, search = '', compact = false }: TopologyCanvasProps) {
  const [fullscreen, setFullscreen] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const graph = useMemo(() => data ? buildGraph(data, search) : { nodes: [], edges: [] }, [data, search])
  const selected = data?.nodes.find((node) => node.id === selectedId)
  const accounts = useMemo(() => data?.nodes.filter((node) => node.kind === 'account') ?? [], [data])

  if (loading) return <div className="topology-state"><div className="spinner" />正在构建拓扑…</div>
  if (error) return <div className="topology-state error"><CircleAlert size={18} />{error}</div>
  if (!data || data.nodes.length === 0) return <div className="topology-state"><Box size={18} />暂无可展示的拓扑数据</div>

  return (
    <div className={`topology-canvas ${compact ? 'compact' : ''} ${fullscreen ? 'fullscreen' : ''}`}>
      <ReactFlow
        nodes={graph.nodes}
        edges={graph.edges}
        fitView
        fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
        minZoom={0.2}
        maxZoom={1.6}
        nodesConnectable={false}
        nodesDraggable={false}
        onNodeClick={(_, node) => setSelectedId(node.id)}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#d7dee9" />
        <Controls showInteractive={false} position="bottom-left" />
        {!compact && <MiniMap
          pannable
          zoomable
          nodeStrokeWidth={3}
          nodeColor={(node) => {
            const source = data.nodes.find((item) => item.id === node.id)
            if (!source) return '#94a3b8'
            return source.kind === 'network' || source.kind === 'room'
              ? '#cbd5e1'
              : accountColor(source.account_id || source.owner_id)
          }}
        />}
      </ReactFlow>

      <button className="icon-button topology-fullscreen-button" onClick={() => setFullscreen((value) => !value)} aria-label={fullscreen ? '退出全屏' : '全屏'}>
        {fullscreen ? <Shrink size={16} /> : <Expand size={16} />}
      </button>

      {!compact && <div className="topology-legend">
        <div className="topology-legend-heading">账号</div>
        {accounts.slice(0, 8).map((account) => (
          <div className="legend-row" key={account.id}>
            <span className="legend-color" style={{ background: accountColor(account.account_id) }} />
            <span>{account.label}</span>
          </div>
        ))}
        {accounts.length > 8 && <div className="legend-more">+{accounts.length - 8} 个账号</div>}
        <div className="topology-legend-heading edge-heading">关系</div>
        <div className="legend-row"><span className="legend-line solid" />成员 / 设备</div>
        <div className="legend-row"><span className="legend-line dashed" />待处理信令</div>
      </div>}

      {selected && <DetailPanel node={selected} onClose={() => setSelectedId(null)} />}
    </div>
  )
}
