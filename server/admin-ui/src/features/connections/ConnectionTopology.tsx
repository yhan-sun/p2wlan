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
import { CircleAlert, Expand, Eye, EyeOff, Info, MonitorSmartphone, Shrink } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import { getFlowAriaLabelConfig, tr, useLocale } from '../../i18n'
import { TopologyViewport } from '../../shared/TopologyViewport'
import type { AdminConnection } from '../../types'
import { useOverlay } from '../../useOverlay'
import type { ConnectionIdentity } from './connectionNavigation'

const NODE_WIDTH = 220
const NODE_HEIGHT = 76

interface ConnectionTopologyProps {
  connections: AdminConnection[]
  networkName: string
  showStale: boolean
  partial?: boolean
  onShowStaleChange: (value: boolean) => void
  onSelect: (connection: AdminConnection) => void
  onClearSelection?: () => void
  onIsolateSelected?: () => void
  selected?: ConnectionIdentity | null
  directionOnly?: boolean
}

interface DeviceNodeData {
  id: string
  name: string
  username: string
  freshInbound: number
  freshOutbound: number
}

function connectionKey(connection: ConnectionIdentity): string {
  return `${connection.network_id}:${connection.reporting_device_id}:${connection.remote_device_id}`
}

function pathLabel(path?: string | null): string {
  if (!path) return tr('None')
  if (path === 'direct') return tr('Direct')
  if (path === 'relay') return tr('Relay')
  return tr(path.replaceAll('_', ' '))
}

function pathClass(connection: AdminConnection): string {
  if (!connection.fresh) return 'stale'
  if (connection.current_path === 'direct') return 'direct'
  if (connection.current_path === 'relay') return 'relay'
  return 'unknown'
}

function buildGraph(connections: AdminConnection[], locale: string, onSelect: (connection: AdminConnection) => void, selected?: ConnectionIdentity | null): { nodes: Node[]; edges: Edge[] } {
  const activeConnections = connections.filter((connection) => Boolean(connection.current_path))
  const devices = new Map<string, DeviceNodeData>()

  // Nodes may be known from a no-path observation; only committed paths form edges.
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
    if (connection.fresh && connection.current_path) {
      reporting.freshOutbound += 1
      remote.freshInbound += 1
    }
    devices.set(reporting.id, reporting)
    devices.set(remote.id, remote)
  }

  const visibleConnections = activeConnections
  const visibleDeviceIDs = new Set(devices.keys())

  const sortedDevices = [...devices.values()]
    .filter((device) => visibleDeviceIDs.has(device.id))
    .sort((a, b) => a.id.localeCompare(b.id))

  const graph = new dagre.graphlib.Graph()
  graph.setDefaultEdgeLabel(() => ({}))
  graph.setGraph({ rankdir: 'TB', ranksep: 50, nodesep: 42, edgesep: 22, marginx: 36, marginy: 36 })
  for (const device of sortedDevices) graph.setNode(device.id, { width: NODE_WIDTH, height: NODE_HEIGHT })
  for (const connection of visibleConnections) graph.setEdge(connection.reporting_device_id, connection.remote_device_id)
  dagre.layout(graph)

  const nodes: Node[] = sortedDevices.map((device) => {
    const point = graph.node(device.id) as { x: number; y: number } | undefined
    return {
      id: device.id,
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      position: {
        x: (point?.x ?? 0) - NODE_WIDTH / 2,
        y: (point?.y ?? 0) - NODE_HEIGHT / 2,
      },
      data: {
        label: <div className="connection-node">
          <span className="connection-node-icon"><MonitorSmartphone size={17} /></span>
          <span className="connection-node-copy">
            <strong>{device.name}</strong>
            <small>{device.username} · {locale === 'zh-CN'
              ? `${device.freshOutbound} 出 / ${device.freshInbound} 入`
              : `${device.freshOutbound} out / ${device.freshInbound} in`}</small>
          </span>
        </div>,
      },
      style: {
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        borderRadius: 10,
        border: '1px solid var(--topology-neutral-border, #d7dde6)',
        background: 'var(--topology-node-surface, #fff)',
        boxShadow: '0 4px 16px rgba(15, 23, 42, .06)',
        padding: 0,
      },
      draggable: false,
      selectable: false,
      className: selected && [selected.reporting_device_id, selected.remote_device_id].includes(device.id) ? 'connection-focused-node' : '',
    }
  })

  const pairCounts = new Map<string, number>()
  for (const connection of visibleConnections) {
    const pair = [connection.reporting_device_id, connection.remote_device_id].sort().join(':')
    pairCounts.set(pair, (pairCounts.get(pair) ?? 0) + 1)
  }

  const edges: Edge[] = visibleConnections.map<Edge>((connection) => {
    const kind = pathClass(connection)
    const pair = [connection.reporting_device_id, connection.remote_device_id].sort().join(':')
    const hasReverse = (pairCounts.get(pair) ?? 0) > 1
    const lexicalForward = connection.reporting_device_id.localeCompare(connection.remote_device_id) < 0
    // Reciprocal paths can share the same midpoint even when their bends differ.
    const labelTransform = hasReverse ? `translateY(${lexicalForward ? -10 : 10}px)` : undefined
    const stroke = kind === 'direct' ? '#16803d' : kind === 'relay' ? '#2563eb' : '#98a2b3'
    const label = `${pathLabel(connection.current_path)}${connection.fresh ? '' : ` · ${tr('Stale')}`}`
    return {
      id: connectionKey(connection),
      source: connection.reporting_device_id,
      target: connection.remote_device_id,
      type: 'smoothstep',
      pathOptions: { offset: hasReverse ? (lexicalForward ? 18 : 38) : 24, borderRadius: 14 },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
      label,
      labelStyle: { fontSize: 12, fill: 'var(--topology-edge-label-color, #344054)', fontWeight: 650, transform: labelTransform },
      labelBgStyle: { fill: 'var(--topology-edge-label-bg, #ffffff)', fillOpacity: 0.94, transform: labelTransform },
      style: {
        stroke,
        strokeWidth: selected && connectionKey(selected) === connectionKey(connection) ? 4 : connection.fresh ? 2 : 1.6,
        strokeDasharray: connection.fresh ? undefined : '6 5',
        opacity: connection.fresh ? 0.88 : 0.58,
      },
      data: { connection },
      selectable: true,
      selected: Boolean(selected && connectionKey(selected) === connectionKey(connection)),
      focusable: true,
      ariaRole: 'button',
      ariaLabel: `${connection.reporting_device_name} ${locale === 'zh-CN' ? '到' : 'to'} ${connection.remote_device_name}: ${label}`,
      domAttributes: {
        onKeyDown: (event) => {
          if ((event.key === 'Enter' || event.key === ' ') && !event.repeat) {
            event.preventDefault()
            event.stopPropagation()
            onSelect(connection)
          }
        },
      },
    }
  })

  return { nodes, edges }
}

export function ConnectionTopology({
  connections,
  networkName,
  showStale,
  partial = false,
  onShowStaleChange,
  onSelect,
  onClearSelection,
  onIsolateSelected,
  selected,
  directionOnly = false,
}: ConnectionTopologyProps) {
  const [fullscreen, setFullscreen] = useState(false)
  const surfaceRef = useRef<HTMLDivElement>(null)
  const [legendOpen, setLegendOpen] = useState(false)
  const locale = useLocale()
  const [narrow, setNarrow] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 650px)').matches)
  const [showCanvas, setShowCanvas] = useState(false)
  const [focusDevice, setFocusDevice] = useState('')
  useEffect(() => {
    const media = window.matchMedia('(max-width: 650px)')
    const update = () => setNarrow(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  const devices = useMemo(() => {
    const values = new Map<string, string>()
    for (const connection of connections) {
      values.set(connection.reporting_device_id, connection.reporting_device_name)
      values.set(connection.remote_device_id, connection.remote_device_name)
    }
    return [...values].map(([id, name]) => ({ id, name }))
  }, [connections])
  const activeDevice = selected?.reporting_device_id || (devices.some((device) => device.id === focusDevice) ? focusDevice : devices[0]?.id) || ''
  const visibleConnections = narrow && !fullscreen && activeDevice
    ? connections.filter((connection) => connection.reporting_device_id === activeDevice || connection.remote_device_id === activeDevice)
    : connections
  const graph = useMemo(() => buildGraph(visibleConnections, locale, onSelect, selected), [visibleConnections, locale, onSelect, selected])
  const noPath = visibleConnections.filter((connection) => !connection.current_path)
  const listMode = narrow && !showCanvas && !fullscreen
  const selectedVisible = !selected || connections.some((connection) => connectionKey(connection) === connectionKey(selected))

  const activeConnectionCount = visibleConnections.filter((connection) => Boolean(connection.current_path)).length

  useOverlay(fullscreen && graph.nodes.length > 0, () => setFullscreen(false), { modalRef: surfaceRef })
  useEffect(() => {
    if (connections.length === 0) setFullscreen(false)
  }, [connections.length])

  return <div className="connection-topology-workspace">
    {selected && onClearSelection && <div className="connection-focus-note"><span>{tr('当前定位')}：{devices.find((device) => device.id === selected.reporting_device_id)?.name || selected.reporting_device_id} → {devices.find((device) => device.id === selected.remote_device_id)?.name || selected.remote_device_id}</span><button type="button" className="button secondary compact" onClick={onClearSelection}>{tr('清除定位')}</button></div>}
    {!selectedVisible && <div className="connection-context-note" role="status"><span>{tr(directionOnly ? '此方向已无可用观测；可清除方向范围查看其他连接。' : '所选方向不在当前已加载范围内；调整筛选后再定位。')}</span>{onIsolateSelected && <button type="button" className="button secondary compact" onClick={onIsolateSelected}>{tr('仅查看此方向（清除其他筛选）')}</button>}</div>}
    {narrow && !fullscreen && <div className="connection-local-controls">
      <label>{tr('设备一跳视图')}<select className="select-field" value={activeDevice} onChange={(event) => { setFocusDevice(event.target.value); onClearSelection?.(); }}>{activeDevice && !devices.some((device) => device.id === activeDevice) && <option value={activeDevice}>{activeDevice}</option>}{devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label>
      <button className="button secondary compact" onClick={() => setShowCanvas((value) => !value)}>{tr(showCanvas ? '查看方向清单' : '打开连接图')}</button>
    </div>}
    <div ref={surfaceRef} role={fullscreen ? 'dialog' : undefined} aria-modal={fullscreen ? true : undefined} aria-label={fullscreen ? tr('全屏连接拓扑') : undefined} tabIndex={fullscreen ? -1 : undefined} className={`connection-topology ${fullscreen ? 'fullscreen' : ''} ${listMode ? 'list-mode' : ''}`}>
    <div className="connection-topology-head">
      <div><strong>{networkName}</strong><span>{activeConnectionCount} {tr("条单向路径观测")}{partial ? ` · ${tr('当前视图已截断')}` : ''}</span></div>
      <div>
        <button className={`topology-filter-button ${showStale ? 'active' : ''}`} onClick={() => onShowStaleChange(!showStale)} aria-pressed={showStale} aria-label={tr('显示过期观测')}>
          {showStale ? <Eye size={15} /> : <EyeOff size={15} />}{tr("Stale")}</button>
        <button className={`topology-filter-button connection-legend-toggle ${legendOpen ? 'active' : ''}`} onClick={() => setLegendOpen((value) => !value)} aria-expanded={legendOpen} aria-controls="connection-topology-legend"><Info size={15} />{tr('图例')}</button>
        <button data-fullscreen-toggle className="icon-button connection-topology-fullscreen-button" disabled={graph.nodes.length === 0} onClick={() => setFullscreen((value) => !value)} aria-label={tr(fullscreen ? '退出全屏' : '全屏')}>
          {fullscreen ? <Shrink size={16} /> : <Expand size={16} />}
        </button>
      </div>
    </div>
    {connections.length === 0 ? <div className="connection-topology-empty">
      <CircleAlert size={18} />
      <div><strong>{tr("暂无可展示的路径观测")}</strong><span>{tr("只有守护进程权威上报且 current_path 非空的观测才会生成连接边；无路径观测仍保留在列表中用于诊断。")}</span></div>
    </div> : listMode ? <div className="connection-neighbor-list">{visibleConnections.map((connection) => <button key={connectionKey(connection)} onClick={() => onSelect(connection)} className={selected && connectionKey(selected) === connectionKey(connection) ? 'active' : ''}>
      <strong>{connection.reporting_device_name} → {connection.remote_device_name}</strong>
      <span>{pathLabel(connection.current_path)} · {tr(connection.freshness)}</span>
    </button>)}</div> : <ReactFlow
      nodes={graph.nodes}
      edges={graph.edges}
      ariaLabelConfig={getFlowAriaLabelConfig()}
      minZoom={0.08}
      maxZoom={1.7}
      style={{ '--xy-background-color': 'var(--topology-flow-surface, #f8fafc)' } as CSSProperties}
      nodesConnectable={false}
      nodesDraggable={false}
      zoomOnScroll={!narrow}
      onlyRenderVisibleElements
      onEdgeClick={(_, edge) => {
        const connection = edge.data?.connection as AdminConnection | undefined
        if (connection) onSelect(connection)
      }}
      proOptions={{ hideAttribution: true }}
    >
      <TopologyViewport nodes={graph.nodes} fullscreen={fullscreen} focusNodeIds={selected ? [selected.reporting_device_id, selected.remote_device_id] : []} focusKey={selected ? connectionKey(selected) : activeDevice} />
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--topology-grid, #d8dee8)" />
      <Controls showInteractive={false} position="bottom-left" />
      {!narrow && <MiniMap
        pannable
        zoomable
        bgColor="var(--surface)"
        maskColor="var(--minimap-mask)"
        nodeStrokeWidth={2}
        nodeColor={() => '#cbd5e1'}
      />}
    </ReactFlow>}
    <div className="connection-topology-legend" id="connection-topology-legend" aria-label={tr('图例')} hidden={!legendOpen}>
      <span><i className="connection-legend-line direct" />{tr("Direct")}</span>
      <span><i className="connection-legend-line relay" />{tr("Relay")}</span>
      {showStale && <span><i className="connection-legend-line stale" />{tr("Stale")}</span>}
    </div>
    </div>
    {noPath.length > 0 && !fullscreen && !listMode && <details className="connection-no-path" open>
      <summary>{tr('无路径观测')} · {noPath.length}</summary>
      <p>{tr('设备保留在图中；没有已提交路径的方向不绘制连接边。')}</p>
      <div className="connection-neighbor-list">{noPath.map((connection) => <button key={connectionKey(connection)} onClick={() => onSelect(connection)}><strong>{connection.reporting_device_name} → {connection.remote_device_name}</strong><span>{tr(connection.freshness)}</span></button>)}</div>
    </details>}
  </div>
}
