export interface AdminOverview {
  generated_at: number
  users: number
  networks: number
  rooms: number
  devices: number
  online_devices: number
  active_tunnels: number
  pending_signals: number
  recent_devices: AdminDevice[]
}

export interface AdminRuntime {
  status: string
  build_version: string
  build_commit: string
  started_at: number
  uptime_seconds: number
  admin_mode: string
}

export interface AdminDevice {
  id: string
  username: string
  device_name: string
  platform: string
  virtual_ip: string
  network_id: string
  network_name: string
  nat_type: string
  relay_rtt_ms?: number
  last_seen: number
  app_version: string
  online: boolean
}

export interface AdminNetwork {
  id: string
  name: string
  cidr: string
  owner_username: string
  member_count: number
  device_count: number
  online_devices: number
  is_room: boolean
  created_at: number
}

export interface AdminRoom {
  id: string
  code: string
  name: string
  cidr: string
  owner_username: string
  member_count: number
  device_count: number
  online_devices: number
  join_locked: boolean
  created_at: number
}

export interface AdminAccount {
  id: string
  username: string
  email: string
  device_count: number
  online_devices: number
  network_count: number
  room_count: number
  last_seen: number
  created_at: number
}

export interface AdminAccountDetail {
  account: AdminAccount
  devices: AdminDevice[]
  networks: AdminNetwork[]
  rooms: AdminRoom[]
}

export interface Page<T> {
  total: number
  limit: number
  offset: number
  items: T[]
}

export interface CursorPage<T> {
  total: number
  limit: number
  next_cursor?: string
  items: T[]
}

export type TopologyNodeKind = 'account' | 'network' | 'room' | 'device'
export type TopologyEdgeKind = 'membership' | 'attachment' | 'pending_signal'

export interface AdminTopologyNode {
  id: string
  kind: TopologyNodeKind
  label: string
  account_id?: string
  username?: string
  owner_id?: string
  network_id?: string
  network_kind?: string
  cidr?: string
  room_code?: string
  virtual_ip?: string
  platform?: string
  nat_type?: string
  app_version?: string
  relay_rtt_ms?: number
  last_seen?: number
  online?: boolean
  focus?: boolean
}

export interface AdminTopologyEdge {
  id: string
  source: string
  target: string
  kind: TopologyEdgeKind
  role?: string
  signal_type?: string
  count?: number
  created_at?: number
}

export interface AdminTopology {
  generated_at: number
  graph_kind: 'control_relationships'
  scope: 'global' | 'account'
  focus_account_id?: string
  path_observation_available: boolean
  path_observation_note: string
  nodes: AdminTopologyNode[]
  edges: AdminTopologyEdge[]
}

export interface AdminTopologyPage extends AdminTopology {
  next_cursor?: string
  complete: boolean
  partial: boolean
  partial_reason?: 'node_budget' | 'edge_budget' | string
  loaded_accounts: number
  total_accounts: number
  node_budget: number
  edge_budget: number
}
