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
  Eye,
  EyeOff,
  Laptop,
  Network,
  RadioTower,
  Server,
  Shrink,
  Smartphone,
  Users,
  X,
} from 'lucide-react'
import { accountColor, accountIdentity, colorWithAlpha } from './colors'
import type { AdminTopology, AdminTopologyNode } from './types'

interface TopologyCanvasProps {
  data?: AdminTopology
  loading?: boolean
  error?: string
  search?: string
  compact?: boolean
}

const dimensions: Record<AdminTopologyNode['kind'], { width: number; height: number }> = {
  account: { width: 228, height: 88 },
  network: { width: 218, height: 86 },
  room: { width: 218, height: 86 },
  device: { width: 238, height: 92 },
}

function DeviceIcon({ platform }: { platform?: string }) {
  const normalized = platform?.toLowerCase() ?? ''
  if (normalized.includes('android') || normalized.includes('ios')) return <Smartphone size={18} />
  if (normalized.includes('server') || normalized.includes('linux')) return <Server size={18} />
  return <Laptop size={18} />
}

function nodeIcon(node: AdminTopologyNode) {
  if (node.kind === 'account') return <Users size={18} />
  if (node.kind === 'room') return <RadioTower size={18} />
  if (node.kind === 'network') return <Network size={18} />
  return <DeviceIcon platform={node.platform} />
}

function nodeMeta(node: AdminTopologyNode): string {
  if (node.kind === 'account') return node.focus ? '当前账号' : '账号'
  if (node.kind === 'room') return [node.room_code && `#${node.room_code}`, node.cidr].filter(Boolean).join(' · ')
  if (node.kind === 'network') return node.cidr || '网络'
  return [node.virtual_ip, node.platform].filter(Boolean).join(' · ')
}

function ownerColor(node: AdminTopologyNode): string {
  return accountColor(node.account_id || (node.kind === 'account' ? node.account_id : node.owner_id))
}

function TopologyNodeLabel({ node }: { node: AdminTopologyNode }) {
  const identity = accountIdentity(node.account_id || (node.kind === 'account' ? node.account_id : node.owner_id))
  const color = identity.color
  return (
    <div className="topology-node-content">
      <div className="topology-node-icon" style={{ color, background: colorWithAlpha(color, 0.1) }}>
        {nodeIcon(node)}
      </div>
      <div className="topology-node-copy">
        <div className="topology-node-title-row">
          <strong>{node.label}</strong>
          <span className="account-identity-code" style={{ color, borderColor: colorWithAlpha(color, 0.3), background: colorWithAlpha(color, 0.08) }}>{identity.code}</span>
          {node.kind === 'device' && <span className={`presence-dot ${node.online ? 'online' : ''}`} title={node.online ? '在线' : '离线'} />}
        </div>
        <span>{nodeMeta(node)}</span>
      </div>
    </div>
  )
}

interface GraphOptions {
  showOffline: boolean
  showSignals: boolean
}

function topologyNodeMatches(node: AdminTopologyNode, normalizedSearch: string): boolean {
  if (!normalizedSearch) return true
  return [node.label, node.username, node.virtual_ip, node.cidr, node.room_code, node.platform]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(normalizedSearch))
}

function applySearch(graph: { nodes: Node[]; edges: Edge[] }, data: AdminTopology, search: string): { nodes: Node[]; edges: Edge[] } {
  const normalizedSearch = search.trim().toLowerCase()
  if (!normalizedSearch) return graph
  const sourceNodes = new Map(data.nodes.map((node) => [node.id, node]))
  const matchedIds = new Set(data.nodes.filter((node) => topologyNodeMatches(node, normalizedSearch)).map((node) => node.id))
  return {
    nodes: graph.nodes.map((node) => ({ ...node, style: { ...node.style, opacity: matchedIds.has(node.id) ? 1 : 0.16 } })),
    edges: graph.edges.map((edge) => {
      const matches = matchedIds.has(edge.source) || matchedIds.has(edge.target)
      const source = sourceNodes.get(edge.source)
      const target = sourceNodes.get(edge.target)
      if (!source || !target) return edge
      return { ...edge, style: { ...edge.style, opacity: matches ? (edge.style?.opacity ?? 1) : 0.07 } }
    }),
  }
}

function buildGraph(data: AdminTopology, options: GraphOptions): { nodes: Node[]; edges: Edge[] } {
  const { showOffline, showSignals } = options
  const sourceNodes = new Map(data.nodes.map((node) => [node.id, node]))
  const visibleSourceNodes = data.nodes.filter((node) => showOffline || node.kind !== 'device' || node.online)
  const visibleIds = new Set(visibleSourceNodes.map((node) => node.id))
  const visibleEdges = data.edges.filter((edge) => {
    if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) return false
    return showSignals || edge.kind !== 'pending_signal'
  })

  const graph = new dagre.graphlib.Graph()
  graph.setDefaultEdgeLabel(() => ({}))
  graph.setGraph({ rankdir: 'LR', ranksep: 112, nodesep: 38, edgesep: 24, marginx: 56, marginy: 56 })
  for (const node of visibleSourceNodes) graph.setNode(node.id, dimensions[node.kind])
  for (const edge of visibleEdges) {
    if (edge.kind !== 'pending_signal') graph.setEdge(edge.source, edge.target)
  }
  dagre.layout(graph)

  const nodes: Node[] = visibleSourceNodes.map((node) => {
    const size = dimensions[node.kind]
    const point = graph.node(node.id) as { x: number; y: number } | undefined
    const color = ownerColor(node)
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
        borderRadius: 12,
        border: node.focus ? `2px solid ${color}` : neutral ? '1px solid #cfd6df' : `1px solid ${colorWithAlpha(color, 0.38)}`,
        background: neutral ? '#ffffff' : colorWithAlpha(color, node.focus ? 0.09 : 0.045),
        boxShadow: node.focus
          ? `0 0 0 4px ${colorWithAlpha(color, 0.1)}, 0 10px 28px rgba(15, 23, 42, .09)`
          : '0 5px 18px rgba(15, 23, 42, .055)',
        color: '#0f172a',
        opacity: 1,
        transition: 'opacity 150ms ease, box-shadow 150ms ease',
      },
      draggable: false,
      selectable: true,
    }
  })

  const edges: Edge[] = visibleEdges.map((edge) => {
    const source = sourceNodes.get(edge.source)
    const target = sourceNodes.get(edge.target)
    const colorSource = edge.kind === 'attachment' ? target : source
    const color = colorSource ? ownerColor(colorSource) : '#94a3b8'
    const isSignal = edge.kind === 'pending_signal'
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated: false,
      style: {
        stroke: isSignal ? '#d97706' : color,
        strokeWidth: isSignal ? 1.7 : edge.kind === 'membership' ? 2 : 1.5,
        strokeDasharray: isSignal ? '7 6' : undefined,
        opacity: isSignal ? 0.78 : 0.46,
      },
      markerEnd: isSignal ? { type: MarkerType.ArrowClosed, color: '#d97706', width: 14, height: 14 } : undefined,
      label: isSignal && edge.count && edge.count > 1 ? `${edge.signal_type || 'signal'} ×${edge.count}` : undefined,
      labelStyle: { fontSize: 11, fill: '#92400e', fontWeight: 600 },
      labelBgStyle: { fill: '#fffbeb', fillOpacity: 0.96 },
    }
  })

  return { nodes, edges }
}

function DetailPanel({ node, onClose }: { node: AdminTopologyNode; onClose: () => void }) {
  const color = ownerColor(node)
  return (
    <aside className="topology-detail" aria-label="拓扑节点详情">
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
    </aside>
  )
}

function TopologySummary({ data }: { data: AdminTopology }) {
  const counts = useMemo(() => ({
    accounts: data.nodes.filter((node) => node.kind === 'account').length,
    networks: data.nodes.filter((node) => node.kind === 'network' || node.kind === 'room').length,
    devices: data.nodes.filter((node) => node.kind === 'device').length,
    online: data.nodes.filter((node) => node.kind === 'device' && node.online).length,
  }), [data])
  return <div className="topology-summary" aria-label="拓扑摘要">
    <span><strong>{counts.accounts}</strong>账号</span>
    <span><strong>{counts.networks}</strong>网络</span>
    <span><strong>{counts.online}/{counts.devices}</strong>设备在线</span>
  </div>
}

export function TopologyCanvas({ data, loading, error, search = '', compact = false }: TopologyCanvasProps) {
  const [fullscreen, setFullscreen] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showOffline, setShowOffline] = useState(true)
  const [showSignals, setShowSignals] = useState(true)
  const layoutGraph = useMemo(
    () => data ? buildGraph(data, { showOffline, showSignals }) : { nodes: [], edges: [] },
    [data, showOffline, showSignals],
  )
  const graph = useMemo(
    () => data ? applySearch(layoutGraph, data, search) : layoutGraph,
    [layoutGraph, data, search],
  )
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
        fitViewOptions={{ padding: compact ? 0.12 : 0.18, maxZoom: 1.05 }}
        minZoom={0.18}
        maxZoom={1.7}
        onlyRenderVisibleElements
        nodesConnectable={false}
        nodesDraggable={false}
        onPaneClick={() => setSelectedId(null)}
        onNodeClick={(_, node) => setSelectedId(node.id)}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#d8dee8" />
        <Controls showInteractive={false} position="bottom-left" />
        {!compact && <MiniMap
          pannable
          zoomable
          nodeStrokeWidth={3}
          nodeColor={(node) => {
            const source = data.nodes.find((item) => item.id === node.id)
            if (!source) return '#94a3b8'
            return source.kind === 'network' || source.kind === 'room' ? '#cbd5e1' : ownerColor(source)
          }}
        />}
      </ReactFlow>

      <div className="topology-canvas-actions">
        {!compact && <>
          <button className={`topology-filter-button ${showOffline ? 'active' : ''}`} onClick={() => setShowOffline((value) => !value)} title="显示或隐藏离线设备">
            {showOffline ? <Eye size={15} /> : <EyeOff size={15} />}离线设备
          </button>
          <button className={`topology-filter-button ${showSignals ? 'active' : ''}`} onClick={() => setShowSignals((value) => !value)} title="显示或隐藏待处理信令">
            <RadioTower size={15} />待处理信令
          </button>
        </>}
        <button className="icon-button topology-fullscreen-button" onClick={() => setFullscreen((value) => !value)} aria-label={fullscreen ? '退出全屏' : '全屏'}>
          {fullscreen ? <Shrink size={16} /> : <Expand size={16} />}
        </button>
      </div>

      <TopologySummary data={data} />

      {!compact && <aside className="topology-legend">
        <div className="topology-legend-heading">账号颜色</div>
        <div className="topology-account-legend-list">
          {accounts.map((account) => (
            <div className="legend-row" key={account.id}>
              <span className="legend-color" style={{ background: accountColor(account.account_id) }} />
              <span className="legend-code">{accountIdentity(account.account_id).code}</span>
              <span title={account.label}>{account.label}</span>
            </div>
          ))}
        </div>
        <div className="topology-legend-heading edge-heading">关系</div>
        <div className="legend-row"><span className="legend-line solid" />成员 / 设备挂载</div>
        <div className="legend-row"><span className="legend-line dashed" />待处理信令</div>
      </aside>}

      {selected && <DetailPanel node={selected} onClose={() => setSelectedId(null)} />}
    </div>
  )
}
