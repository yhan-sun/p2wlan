import type {
  AdminAccount,
  AdminAccountDetail,
  AdminConnectionFilters,
  AdminConnectionHealth,
  AdminConnectionHealthFilters,
  AdminConnectionPage,
  AdminConnectionTransitionPage,
  AdminDevice,
  AdminNetwork,
  AdminOverview,
  AdminRoom,
  AdminRuntime,
  AdminTopology,
  AdminTopologyPage,
  CursorPage,
  Page,
} from './types'

const TOKEN_KEY = 'p2wlan-admin-token'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function getAdminToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? ''
}

export function setAdminToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token)
}

export function clearAdminToken(): void {
  sessionStorage.removeItem(TOKEN_KEY)
}

async function parseError(response: Response): Promise<string> {
  try {
    const payload = await response.json() as { error?: string }
    return payload.error || `HTTP ${response.status}`
  } catch {
    return `HTTP ${response.status}`
  }
}

export async function verifyAdminToken(token: string): Promise<void> {
  const response = await fetch('/admin/api/v1/runtime', {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    cache: 'no-store',
  })
  if (!response.ok) throw new ApiError(response.status, await parseError(response))
}

export async function api<T>(path: string): Promise<T> {
  const token = getAdminToken()
  const response = await fetch(`/admin/api/v1${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    cache: 'no-store',
  })
  if (response.status === 401) {
    clearAdminToken()
    window.dispatchEvent(new Event('p2wlan:unauthorized'))
  }
  if (!response.ok) throw new ApiError(response.status, await parseError(response))
  return response.json() as Promise<T>
}

async function accountPage(query: string, limit: number, offset: number): Promise<Page<AdminAccount>> {
  const params = new URLSearchParams({ q: query, limit: String(limit), offset: String(offset) })
  return api<Page<AdminAccount>>(`/accounts?${params}`)
}

export const adminApi = {
  overview: () => api<AdminOverview>('/overview'),
  runtime: () => api<AdminRuntime>('/runtime'),
  accounts: (query = '', limit = 50, offset = 0) => {
    return accountPage(query, limit, offset)
  },
  accountsCursor: (query = '', cursor = '', limit = 25) => {
    const params = new URLSearchParams({ q: query, limit: String(limit) })
    if (cursor) params.set('cursor', cursor)
    return api<CursorPage<AdminAccount>>(`/accounts/cursor?${params}`)
  },
  account: (id: string) => api<AdminAccountDetail>(`/accounts/${encodeURIComponent(id)}`),
  topology: (accountId: string) => api<AdminTopology>(`/accounts/${encodeURIComponent(accountId)}/topology`),
  topologyPage: (cursor = '', limit = 12, nodeLimit = 600) => {
    const params = new URLSearchParams({ limit: String(limit), node_limit: String(nodeLimit) })
    if (cursor) params.set('cursor', cursor)
    return api<AdminTopologyPage>(`/topology?${params}`)
  },
  devices: (query = '', status = 'all', limit = 50, offset = 0) => {
    const params = new URLSearchParams({ q: query, status, limit: String(limit), offset: String(offset) })
    return api<Page<AdminDevice>>(`/devices?${params}`)
  },
  networks: (limit = 50, offset = 0) => api<Page<AdminNetwork>>(`/networks?limit=${limit}&offset=${offset}`),
  rooms: (limit = 50, offset = 0) => api<Page<AdminRoom>>(`/rooms?limit=${limit}&offset=${offset}`),
  connections: (filters: AdminConnectionFilters = {}, limit = 25, offset = 0) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (filters.query) params.set('q', filters.query)
    if (filters.networkId) params.set('network_id', filters.networkId)
    if (filters.accountId) params.set('account_id', filters.accountId)
    if (filters.deviceId) params.set('device_id', filters.deviceId)
    if (filters.reportingDeviceId) params.set('reporting_device_id', filters.reportingDeviceId)
    if (filters.remoteDeviceId) params.set('remote_device_id', filters.remoteDeviceId)
    if (filters.path) params.set('path', filters.path)
    if (filters.freshness) params.set('freshness', filters.freshness)
    return api<AdminConnectionPage>(`/connections?${params}`)
  },
  connectionTransitions: (reportingDeviceId: string, remoteDeviceId: string, networkId: string, limit = 20, cursor = '') => {
    const params = new URLSearchParams({
      reporting_device_id: reportingDeviceId,
      remote_device_id: remoteDeviceId,
      network_id: networkId,
      limit: String(limit),
    })
    if (cursor) params.set('cursor', cursor)
    return api<AdminConnectionTransitionPage>(`/connection-transitions?${params}`)
  },
  connectionHealth: (filters: AdminConnectionHealthFilters = {}, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) })
    if (filters.networkId) params.set('network_id', filters.networkId)
    if (filters.accountId) params.set('account_id', filters.accountId)
    if (filters.deviceId) params.set('device_id', filters.deviceId)
    if (filters.windowSeconds) params.set('window_seconds', String(filters.windowSeconds))
    return api<AdminConnectionHealth>(`/connection-health?${params}`)
  },
}
