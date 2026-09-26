import { getFlowAriaLabelConfig, getLocale, tr, useLocale } from './i18n'
import '@xyflow/react/dist/style.css'
import { type CSSProperties, useEffect, useMemo, useState } from 'react'
import dagre from '@dagrejs/dagre'
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  Position,
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
  Info,
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
import { useTheme } from './theme'
import { useOverlay } from './useOverlay'
import { TopologyViewport } from './TopologyViewport'
import type { AdminTopology, AdminTopologyNode } from './types'

interface TopologyCanvasProps {
  data?: AdminTopology
  loading?: boolean
  error?: string
  search?: string
  compact?: boolean
}

const dimensions: Record<AdminTopologyNode['kind'], { width: number; height: number }> = {
  account: { width: 218, height: 76 },
  network: { width: 208, height: 74 },
  room: { width: 208, height: 74 },
  device: { width: 222, height: 80 },
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
  if (node.kind === 'account') return tr(node.focus ? '当前账号' : '账号')
  if (node.kind === 'room') return [node.room_code && `#${node.room_code}`, node.cidr].filter(Boolean).join(' · ')
  if (node.kind === 'network') return node.cidr || tr('网络')
  return [node.virtual_ip, node.platform].filter(Boolean).join(' · ')
}

function natLabel(value: string): string {
  const match = value.match(/(?:^|;)m=([^;]+)/i)
  const normalized = (match?.[1] ?? value).replaceAll('_', ' ')
  return tr(getLocale() === 'zh-CN' ? normalized.toLowerCase() : normalized)
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
          <strong title={node.label}>{node.label}</strong>
          <span className="account-identity-code" style={{ color, borderColor: colorWithAlpha(color, 0.3), background: colorWithAlpha(color, 0.08) }}>{identity.code}</span>
          {node.kind === 'device' && <span className={`presence-dot ${node.online ? 'online' : ''}`} title={tr(node.online ? '在线' : '离线')} />}
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

function filterTopology(data: AdminTopology, options: GraphOptions, search: string): AdminTopology {
  const nodes = data.nodes.filter((node) => options.showOffline || node.kind !== 'device' || node.online)
  const visibleIds = new Set(nodes.map((node) => node.id))
  const edges = data.edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target) && (options.showSignals || edge.kind !== 'pending_signal'))
  const normalizedSearch = search.trim().toLowerCase()
  if (!normalizedSearch) return { ...data, nodes, edges }

  const matchedIds = new Set(
    nodes.filter((node) => topologyNodeMatches(node, normalizedSearch)).map((node) => node.id),
  )
  if (matchedIds.size === 0) return { ...data, nodes: [], edges: [] }

  // A search result is useful only with enough local context to explain why the
  // resource is in this graph. Keep the direct one-hop neighborhood and hide
  // unrelated branches instead of leaving a low-opacity hairball behind.
  const contextIds = new Set(matchedIds)
  for (const edge of edges) {
    if (matchedIds.has(edge.source) || matchedIds.has(edge.target)) {
      contextIds.add(edge.source)
      contextIds.add(edge.target)
    }
  }
  return {
    ...data,
    nodes: nodes.filter((node) => contextIds.has(node.id)),
    edges: edges.filter((edge) => contextIds.has(edge.source) && contextIds.has(edge.target)),
  }
}

function buildGraph(data: AdminTopology, narrow = false): { nodes: Node[]; edges: Edge[] } {
  const sourceNodes = new Map(data.nodes.map((node) => [node.id, node]))
  const visibleSourceNodes = [...data.nodes].sort((left, right) => left.id.localeCompare(right.id))
  const visibleEdges = data.edges

  const graph = new dagre.graphlib.Graph()
  graph.setDefaultEdgeLabel(() => ({}))
  const positions = new Map<string, { x: number; y: number }>()
  const stackForNarrow = narrow && visibleSourceNodes.length <= 24
  if (stackForNarrow) {
    const rank = (node: AdminTopologyNode) => node.kind === 'account' ? 0 : node.kind === 'device' ? 2 : 1
    const ordered = [...visibleSourceNodes].sort((left, right) => rank(left) - rank(right) || left.label.localeCompare(right.label))
    let y = 36
    for (const node of ordered) {
      positions.set(node.id, { x: (222 - dimensions[node.kind].width) / 2, y })
      y += dimensions[node.kind].height + 16
    }
  } else {
    graph.setGraph({ rankdir: 'LR', ranksep: 82, nodesep: 22, edgesep: 18, marginx: 36, marginy: 34 })
    // dagre mutates each label with x/y coordinates while laying out the graph.
    // Never share the dimension object between same-kind nodes: shared labels
    // make every account/device in that rank land on top of one another.
    for (const node of visibleSourceNodes) graph.setNode(node.id, { ...dimensions[node.kind] })
    for (const edge of visibleEdges) {
      if (edge.kind !== 'pending_signal') graph.setEdge(edge.source, edge.target)
    }
    dagre.layout(graph)
    for (const node of visibleSourceNodes) {
      const point = graph.node(node.id) as { x: number; y: number } | undefined
      const size = dimensions[node.kind]
      positions.set(node.id, { x: (point?.x ?? 0) - size.width / 2, y: (point?.y ?? 0) - size.height / 2 })
    }
  }

  const nodes: Node[] = visibleSourceNodes.map((node) => {
    const size = dimensions[node.kind]
    const point = positions.get(node.id)
    const color = ownerColor(node)
    const neutral = node.kind === 'network' || node.kind === 'room'
    return {
      id: node.id,
      width: size.width,
      height: size.height,
      position: point ?? { x: 0, y: 0 },
      sourcePosition: Position.Right,
      targetPosition: stackForNarrow ? Position.Right : Position.Left,
      data: { label: <TopologyNodeLabel node={node} /> },
      style: {
        width: size.width,
        height: size.height,
        padding: 0,
        borderRadius: 12,
        border: node.focus ? `2px solid ${color}` : neutral ? '1px solid var(--topology-neutral-border, #cfd6df)' : `1px solid ${colorWithAlpha(color, 0.38)}`,
        background: neutral ? 'var(--topology-node-surface, #ffffff)' : colorWithAlpha(color, node.focus ? 0.09 : 0.045),
        boxShadow: node.focus
          ? `0 0 0 4px ${colorWithAlpha(color, 0.1)}, var(--topology-node-shadow, 0 10px 28px rgba(15, 23, 42, .09))`
          : 'var(--topology-node-shadow, 0 5px 18px rgba(15, 23, 42, .055))',
        color: 'var(--topology-node-text, #0f172a)',
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
        stroke: isSignal ? '#d97706' : edge.kind === 'attachment' ? '#64748b' : color,
        strokeWidth: isSignal ? 1.7 : edge.kind === 'membership' ? 2 : 1.5,
        strokeDasharray: isSignal ? '7 6' : edge.kind === 'attachment' ? '4 4' : undefined,
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
  useOverlay(true, onClose, { lockScroll: false })
  const color = ownerColor(node)
  return (
    <aside className="topology-detail" aria-label={tr("关系图节点详情")}>
      <button className="icon-button topology-detail-close" onClick={onClose} aria-label={tr("关闭详情")}><X size={16} /></button>
      <div className="topology-detail-type" style={{ color }}>{tr(node.kind === 'account' ? '账号' : node.kind === 'device' ? '设备' : node.kind === 'room' ? '房间' : '网络')}</div>
      <h3>{node.label}</h3>
      {node.username && node.kind !== 'account' && <p className="topology-detail-owner">{tr("账号 · ")}{node.username}</p>}
      <dl>
        {node.virtual_ip && <div><dt>{tr("Virtual IP")}</dt><dd className="mono">{node.virtual_ip}</dd></div>}
        {node.cidr && <div><dt>{tr("CIDR")}</dt><dd className="mono">{node.cidr}</dd></div>}
        {node.room_code && <div><dt>{tr("房间号")}</dt><dd className="mono">{node.room_code}</dd></div>}
        {node.platform && <div><dt>{tr("平台")}</dt><dd>{node.platform}</dd></div>}
        {node.app_version && <div><dt>{tr("版本")}</dt><dd>{node.app_version}</dd></div>}
        {node.nat_type && <div><dt>{tr("NAT")}</dt><dd>{natLabel(node.nat_type)}</dd></div>}
        {node.relay_rtt_ms !== undefined && <div><dt>{tr("Relay RTT")}</dt><dd>{node.relay_rtt_ms} {tr("ms")}</dd></div>}
        {node.online !== undefined && <div><dt>{tr("状态")}</dt><dd><span className={`status-label ${node.online ? 'online' : ''}`}><span />{tr(node.online ? '在线' : '离线')}</span></dd></div>}
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
  return <div className="topology-summary" aria-label={tr("拓扑摘要")}>
    <span><strong>{counts.accounts}</strong>{tr("账号")}</span>
    <span><strong>{counts.networks}</strong>{tr("网络")}</span>
    <span><strong>{counts.online}{tr("/")}{counts.devices}</strong>{tr("设备在线")}</span>
  </div>
}

function useNarrowViewport() {
  const [narrow, setNarrow] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 650px)').matches)
  useEffect(() => {
    const query = window.matchMedia('(max-width: 650px)')
    const update = () => setNarrow(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])
  return narrow
}

export function TopologyCanvas({ data, loading, error, search = '', compact = false }: TopologyCanvasProps) {
  const locale = useLocale()
  const theme = useTheme()
  const [fullscreen, setFullscreen] = useState(false)
  const [legendOpen, setLegendOpen] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showOffline, setShowOffline] = useState(true)
  const [showSignals, setShowSignals] = useState(false)
  const narrow = useNarrowViewport()
  const visibleData = useMemo(
    () => data ? filterTopology(data, { showOffline, showSignals }, search) : undefined,
    [data, showOffline, showSignals, search],
  )
  const graph = useMemo(
    () => visibleData ? buildGraph(visibleData, narrow) : { nodes: [], edges: [] },
    [visibleData, locale, narrow],
  )
  const mobileStack = narrow && graph.nodes.length > 0 && graph.nodes.length <= 24
  const mobileStackHeight = mobileStack
    ? Math.max(540, Math.ceil(graph.nodes.reduce((height, node) => height + (node.height ?? 76) + 16, 56)))
    : undefined
  const selected = visibleData?.nodes.find((node) => node.id === selectedId)
  const canvasVisible = !loading && !error && graph.nodes.length > 0
  useOverlay(fullscreen && canvasVisible, () => setFullscreen(false))
  useEffect(() => {
    if (!canvasVisible) setFullscreen(false)
    if (selectedId && !selected) setSelectedId(null)
  }, [canvasVisible, selectedId, selected])
  if (loading) return <div className="topology-state"><div className="spinner" />{tr("正在构建资源关系图…")}</div>
  if (error) return <div className="topology-state error"><CircleAlert size={18} />{tr(error)}</div>
  if (!data || data.nodes.length === 0) return <div className="topology-state"><Box size={18} />{tr("暂无可展示的资源关系")}</div>
  if (search.trim() && graph.nodes.length === 0) return <div className="topology-state"><Box size={18} />{tr("没有匹配的账号、设备、IP 或网络")}</div>

  return (
    <div
      className={`topology-canvas ${compact ? 'compact' : ''} ${fullscreen ? 'fullscreen' : ''} ${mobileStack ? 'mobile-stack' : ''}`}
      style={mobileStackHeight ? { '--topology-mobile-height': `${mobileStackHeight}px` } as CSSProperties : undefined}
    >
      <ReactFlow
        nodes={graph.nodes}
        edges={graph.edges}
        ariaLabelConfig={getFlowAriaLabelConfig()}
        minZoom={0.08}
        maxZoom={1.7}
        style={{ '--xy-background-color': 'var(--topology-flow-surface, #f8fafc)' } as CSSProperties}
        zoomOnScroll={!narrow}
        onlyRenderVisibleElements
        nodesConnectable={false}
        nodesDraggable={false}
        onPaneClick={() => setSelectedId(null)}
        onNodeClick={(_, node) => setSelectedId(node.id)}
        proOptions={{ hideAttribution: true }}
      >
        <TopologyViewport nodes={graph.nodes} fullscreen={fullscreen} padding={narrow ? 0.1 : compact ? 0.12 : 0.18} maxZoom={narrow ? 0.92 : 1.15} />
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--topology-grid, #d8dee8)" />
        <Controls showInteractive={false} position="bottom-left" />
        {!compact && <MiniMap
          pannable
          zoomable
          bgColor={theme === 'dark' ? '#142033' : 'rgba(255, 255, 255, .96)'}
          maskColor={theme === 'dark' ? 'rgba(148, 163, 184, .2)' : 'rgba(240, 240, 240, .6)'}
          nodeStrokeWidth={3}
          nodeColor={(node) => {
            const source = data.nodes.find((item) => item.id === node.id)
            if (!source) return '#94a3b8'
            return source.kind === 'network' || source.kind === 'room' ? '#cbd5e1' : ownerColor(source)
          }}
        />}
      </ReactFlow>

      <section className="topology-legend" id="resource-topology-legend" aria-label={tr('图例')} hidden={!legendOpen}>
        <div className="topology-legend-title"><span>{tr('图例')}</span><button type="button" className="icon-button topology-legend-close" onClick={() => setLegendOpen(false)} aria-label={tr('关闭图例')}><X size={14} /></button></div>
        <div className="topology-legend-section">
          <div className="topology-legend-heading">{tr('资源类型')}</div>
          <div className="legend-row"><Users className="legend-kind-icon account" size={15} />{tr('账号')}</div>
          <div className="legend-row"><Network className="legend-kind-icon network" size={15} />{tr('网络')}</div>
          <div className="legend-row"><RadioTower className="legend-kind-icon room" size={15} />{tr('房间')}</div>
          <div className="legend-row"><Laptop className="legend-kind-icon device" size={15} />{tr('设备')}</div>
        </div>
        <div className="topology-legend-section">
          <div className="topology-legend-heading">{tr('关系类型')}</div>
          <div className="legend-row"><span className="legend-line membership" />{tr('成员关系')}</div>
          <div className="legend-row"><span className="legend-line attachment" />{tr('设备挂载')}</div>
          <div className="legend-row"><span className="legend-line dashed" />{tr('待处理信令')}</div>
        </div>
      </section>

      <div className="topology-canvas-actions">
        {!compact && <>
          <button className={`topology-filter-button topology-legend-toggle ${legendOpen ? 'active' : ''}`} onClick={() => setLegendOpen((value) => !value)} aria-expanded={legendOpen} aria-controls="resource-topology-legend" title={tr('图例')}>
            <Info size={15} />{tr('图例')}</button>
          <button className={`topology-filter-button ${showOffline ? 'active' : ''}`} onClick={() => setShowOffline((value) => !value)} title={tr("显示或隐藏离线设备")}>
            {showOffline ? <Eye size={15} /> : <EyeOff size={15} />}{tr("离线设备")}</button>
          <button className={`topology-filter-button ${showSignals ? 'active' : ''}`} onClick={() => setShowSignals((value) => !value)} title={tr("显示或隐藏控制面的待处理信令")}>
            <RadioTower size={15} />{tr("控制信令")}</button>
        </>}
        <button className="icon-button topology-fullscreen-button" onClick={() => { setSelectedId(null); setFullscreen((value) => !value) }} aria-label={tr(fullscreen ? '退出全屏' : '全屏')}>
          {fullscreen ? <Shrink size={16} /> : <Expand size={16} />}
        </button>
      </div>

      {visibleData && <TopologySummary data={visibleData} />}

      {selected && <DetailPanel node={selected} onClose={() => setSelectedId(null)} />}
    </div>
  )
}
