import { getFlowAriaLabelConfig, tr, useLocale } from './i18n'
import '@xyflow/react/dist/style.css'
import { type CSSProperties, useEffect, useMemo, useState } from 'react'
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
import type { AdminConnection } from './types'
import { useTheme } from './theme'
import { useOverlay } from './useOverlay'
import { TopologyViewport } from './TopologyViewport'

const NODE_WIDTH = 220
const NODE_HEIGHT = 76

interface ConnectionTopologyProps {
  connections: AdminConnection[]
  networkName: string
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

function buildGraph(connections: AdminConnection[], locale: string): { nodes: Node[]; edges: Edge[] } {
  const activeConnections = connections.filter((connection) => Boolean(connection.current_path))
  const devices = new Map<string, DeviceNodeData>()

  for (const connection of activeConnections) {
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
    const label = `${pathLabel(connection.current_path)}${connection.fresh ? '' : ` · ${tr('Stale')}`}`
    return {
      id: connectionKey(connection),
      source: connection.reporting_device_id,
      target: connection.remote_device_id,
      type: 'smoothstep',
      pathOptions: { offset: hasReverse ? (lexicalForward ? 18 : 38) : 24, borderRadius: 14 },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
      label,
      labelStyle: { fontSize: 10, fill: 'var(--topology-edge-label-color, #344054)', fontWeight: 650 },
      labelBgStyle: { fill: 'var(--topology-edge-label-bg, #ffffff)', fillOpacity: 0.94 },
      style: {
        stroke,
        strokeWidth: connection.fresh ? 2 : 1.6,
        strokeDasharray: connection.fresh ? undefined : '6 5',
        opacity: connection.fresh ? 0.88 : 0.58,
      },
      data: { connection },
      selectable: true,
      focusable: true,
      ariaLabel: `${connection.reporting_device_name} ${locale === 'zh-CN' ? '到' : 'to'} ${connection.remote_device_name}: ${label}`,
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
}: ConnectionTopologyProps) {
  const [fullscreen, setFullscreen] = useState(false)
  const [legendOpen, setLegendOpen] = useState(false)
  const locale = useLocale()
  const theme = useTheme()
  const graph = useMemo(() => buildGraph(connections, locale), [connections, locale])

  const activeConnectionCount = connections.filter((connection) => Boolean(connection.current_path)).length

  useOverlay(fullscreen && activeConnectionCount > 0, () => setFullscreen(false))
  useEffect(() => {
    if (activeConnectionCount === 0) setFullscreen(false)
  }, [activeConnectionCount])

  return <div className={`connection-topology ${fullscreen ? 'fullscreen' : ''}`}>
    <div className="connection-topology-head">
      <div><strong>{networkName}</strong><span>{activeConnectionCount} {tr("条单向路径观测")}{partial ? ` · ${tr('当前视图已截断')}` : ''}</span></div>
      <div>
        <button className={`topology-filter-button ${showStale ? 'active' : ''}`} onClick={() => onShowStaleChange(!showStale)} aria-pressed={showStale} aria-label={tr('显示过期观测')}>
          {showStale ? <Eye size={15} /> : <EyeOff size={15} />}{tr("Stale")}</button>
        <button className={`topology-filter-button connection-legend-toggle ${legendOpen ? 'active' : ''}`} onClick={() => setLegendOpen((value) => !value)} aria-expanded={legendOpen} aria-controls="connection-topology-legend"><Info size={15} />{tr('图例')}</button>
        <button className="icon-button connection-topology-fullscreen-button" disabled={activeConnectionCount === 0} onClick={() => setFullscreen((value) => !value)} aria-label={tr(fullscreen ? '退出全屏' : '全屏')}>
          {fullscreen ? <Shrink size={16} /> : <Expand size={16} />}
        </button>
      </div>
    </div>
    {activeConnectionCount === 0 ? <div className="connection-topology-empty">
      <CircleAlert size={18} />
      <div><strong>{tr("暂无可展示的路径观测")}</strong><span>{tr("只有守护进程权威上报且 current_path 非空的观测才会生成连接边；无路径观测仍保留在列表中用于诊断。")}</span></div>
    </div> : <ReactFlow
      nodes={graph.nodes}
      edges={graph.edges}
      ariaLabelConfig={getFlowAriaLabelConfig()}
      minZoom={0.08}
      maxZoom={1.7}
      style={{ '--xy-background-color': 'var(--topology-flow-surface, #f8fafc)' } as CSSProperties}
      nodesConnectable={false}
      nodesDraggable={false}
      onlyRenderVisibleElements
      onEdgeClick={(_, edge) => {
        const connection = edge.data?.connection as AdminConnection | undefined
        if (connection) onSelect(connection)
      }}
      proOptions={{ hideAttribution: true }}
    >
      <TopologyViewport nodes={graph.nodes} fullscreen={fullscreen} />
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--topology-grid, #d8dee8)" />
      <Controls showInteractive={false} position="bottom-left" />
      <MiniMap
        pannable
        zoomable
        bgColor={theme === 'dark' ? '#142033' : 'rgba(255, 255, 255, .96)'}
        maskColor={theme === 'dark' ? 'rgba(148, 163, 184, .2)' : 'rgba(240, 240, 240, .6)'}
        nodeStrokeWidth={2}
        nodeColor={() => '#cbd5e1'}
      />
    </ReactFlow>}
    <div className="connection-topology-legend" id="connection-topology-legend" aria-label={tr('图例')} hidden={!legendOpen}>
      <span><i className="connection-legend-line direct" />{tr("Direct")}</span>
      <span><i className="connection-legend-line relay" />{tr("Relay")}</span>
      {showStale && <span><i className="connection-legend-line stale" />{tr("Stale")}</span>}
    </div>
  </div>
}
