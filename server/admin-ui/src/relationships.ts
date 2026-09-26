import type { AdminTopology, AdminTopologyNode } from './types'

export interface NetworkSummary {
  id: string
  node: AdminTopologyNode
  personal: boolean
  owner?: string
  memberCount: number
  deviceCount: number
  onlineCount: number
  searchText: string
}

export function topologyForNetwork(data: AdminTopology, node: AdminTopologyNode): AdminTopology {
  const personal = node.kind === 'account'
  const relatedEdges = data.edges.filter((edge) => personal
    ? edge.kind === 'attachment' && edge.role === 'private-default' && edge.source === node.id
    : (edge.kind === 'membership' && edge.target === node.id) || (edge.kind === 'attachment' && edge.source === node.id))
  const ids = new Set([node.id])
  for (const edge of relatedEdges) { ids.add(edge.source); ids.add(edge.target) }
  const nodes = data.nodes.filter((item) => ids.has(item.id))
  const nodeIds = new Set(nodes.map((item) => item.id))
  return { ...data, nodes, edges: data.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)) }
}

export function summarizeNetworks(data?: AdminTopology): NetworkSummary[] {
  if (!data) return []
  const privateAccounts = new Set(data.edges.filter((edge) => edge.kind === 'attachment' && edge.role === 'private-default').map((edge) => edge.source))
  const accounts = new Map(data.nodes.filter((node) => node.kind === 'account').map((node) => [node.id, node]))
  return data.nodes.filter((node) => node.kind === 'network' || node.kind === 'room' || (node.kind === 'account' && privateAccounts.has(node.id))).map((node) => {
    const personal = node.kind === 'account'
    const scoped = topologyForNetwork(data, node)
    const members = scoped.nodes.filter((item) => item.kind === 'account')
    const devices = scoped.nodes.filter((item) => item.kind === 'device')
    const owner = personal ? node.label : node.owner_id ? accounts.get(`account:${node.owner_id}`)?.label : undefined
    return {
      id: personal ? `personal:${node.account_id || node.id.slice('account:'.length)}` : node.network_id || node.id.replace(/^network:/, ''),
      node, personal, owner,
      memberCount: members.length,
      deviceCount: devices.length,
      onlineCount: devices.filter((device) => device.online).length,
      searchText: [node.label, node.cidr, owner, ...members.flatMap((item) => [item.label, item.username]), ...devices.flatMap((item) => [item.label, item.virtual_ip, item.platform])].filter(Boolean).join(' ').toLowerCase(),
    }
  }).sort((left, right) => left.node.label.localeCompare(right.node.label))
}
