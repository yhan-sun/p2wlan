import type {
  AdminAccount,
  AdminAccountDetail,
  AdminDevice,
  AdminNetwork,
  AdminOverview,
  AdminRoom,
  AdminRuntime,
  AdminTopology,
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

export const adminApi = {
  overview: () => api<AdminOverview>('/overview'),
  runtime: () => api<AdminRuntime>('/runtime'),
  accounts: (query = '', limit = 50, offset = 0) => {
    const params = new URLSearchParams({ q: query, limit: String(limit), offset: String(offset) })
    return api<Page<AdminAccount>>(`/accounts?${params}`)
  },
  account: (id: string) => api<AdminAccountDetail>(`/accounts/${encodeURIComponent(id)}`),
  topology: (accountId?: string) => accountId
    ? api<AdminTopology>(`/accounts/${encodeURIComponent(accountId)}/topology`)
    : api<AdminTopology>('/topology'),
  devices: (query = '', status = 'all', limit = 50, offset = 0) => {
    const params = new URLSearchParams({ q: query, status, limit: String(limit), offset: String(offset) })
    return api<Page<AdminDevice>>(`/devices?${params}`)
  },
  networks: (limit = 100, offset = 0) => api<Page<AdminNetwork>>(`/networks?limit=${limit}&offset=${offset}`),
  rooms: (limit = 100, offset = 0) => api<Page<AdminRoom>>(`/rooms?limit=${limit}&offset=${offset}`),
}
