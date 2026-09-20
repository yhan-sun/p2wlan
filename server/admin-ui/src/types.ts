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


export interface AdminConnection {
  schema_version: number
  directional: true
  reporting_device_id: string
  reporting_device_name: string
  reporting_user_id: string
  reporting_username: string
  remote_device_id: string
  remote_device_name: string
  remote_user_id: string
  remote_username: string
  network_id: string
  network_name: string
  lifecycle: string
  current_path: string | null
  previous_path: string | null
  transition_reason: string
  direct_state?: string
  relay_state?: string
  recovery_state?: string
  relay_server?: string
  selected_path_mtu?: number
  selected_udp_datagram_size?: number
  last_handshake_age_ms?: number
  last_validation_rtt_ms?: number
  path_age_ms: number
  observed_at: number
  received_at: number
  fresh: boolean
  freshness: 'fresh' | 'stale' | 'reporter_offline' | string
  observation_revision: number
}

export interface AdminConnectionPage extends Page<AdminConnection> {}

export interface AdminConnectionTransition {
  id: string
  schema_version: number
  directional: true
  reporting_device_id: string
  remote_device_id: string
  network_id: string
  lifecycle: string
  current_path: string | null
  previous_path: string | null
  transition_reason: string
  selected_path_mtu?: number
  observed_at: number
  created_at: number
  observation_revision: number
}

export interface AdminConnectionTransitionPage {
  limit: number
  next_cursor?: string
  items: AdminConnectionTransition[]
}

export interface AdminConnectionFilters {
  query?: string
  networkId?: string
  accountId?: string
  deviceId?: string
  reportingDeviceId?: string
  remoteDeviceId?: string
  path?: string
  freshness?: 'fresh' | 'stale' | ''
}
