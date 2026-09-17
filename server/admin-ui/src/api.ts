import type {
  AdminAccount,
  AdminAccountDetail,
  AdminDevice,
  AdminNetwork,
  AdminOverview,
  AdminRoom,
  AdminRuntime,
  AdminTopology,
  AdminTopologyPage,
  CursorPage,
  Page,
  TopologyView,
} from './types'

const TOKEN_KEY = 'p2wlan-admin-token'
const MAX_SERVER_PAGE = 200

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

export async function api<T>(path: string, signal?: AbortSignal): Promise<T> {
  const token = getAdminToken()
  const response = await fetch(`/admin/api/v1${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    cache: 'no-store',
    signal,
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

// Legacy all-page helpers remain for compatibility with code outside the
// console's primary list routes. New interactive pages use the cursor methods
// below so a mutable last_seen value cannot shift offset boundaries.
async function fetchAllPages<T>(fetchPage: (limit: number, offset: number) => Promise<Page<T>>): Promise<Page<T>> {
  const items: T[] = []
  let offset = 0
  let total = 0

  do {
    const page = await fetchPage(MAX_SERVER_PAGE, offset)
    total = page.total
    items.push(...page.items)
    offset += page.items.length
    if (page.items.length === 0) break
  } while (offset < total)

  return { total, limit: items.length, offset: 0, items }
}

function cursorParams(limit: number, cursor = ''): URLSearchParams {
  const params = new URLSearchParams({ pagination: 'cursor', limit: String(limit) })
  if (cursor) params.set('cursor', cursor)
  return params
}

export const adminApi = {
  overview: () => api<AdminOverview>('/overview'),
  runtime: () => api<AdminRuntime>('/runtime'),

  // Kept for the bounded dashboard "recent accounts" card.
  accounts: (query = '', limit = 50, offset = 0) => accountPage(query, limit, offset),

  accountsCursor: (query = '', limit = 50, cursor = '', signal?: AbortSignal) => {
    const params = cursorParams(limit, cursor)
    params.set('q', query)
    return api<CursorPage<AdminAccount>>(`/accounts?${params}`, signal)
  },
  account: (id: string) => api<AdminAccountDetail>(`/accounts/${encodeURIComponent(id)}`),

  // The old full topology endpoint remains available for API compatibility;
  // the console exclusively uses topologyPage so server work is bounded.
  topology: (accountId?: string) => accountId
    ? api<AdminTopology>(`/accounts/${encodeURIComponent(accountId)}/topology`)
    : api<AdminTopology>('/topology'),
  topologyPage: (accountId: string | undefined, view: TopologyView, cursor = '', limit = 100, signal?: AbortSignal) => {
    const params = new URLSearchParams({ view, limit: String(limit) })
    if (cursor) params.set('cursor', cursor)
    const base = accountId
      ? `/accounts/${encodeURIComponent(accountId)}/topology`
      : '/topology'
    return api<AdminTopologyPage>(`${base}?${params}`, signal)
  },

  devices: (query = '', status = 'all', limit = 50, offset = 0) => {
    const params = new URLSearchParams({ q: query, status, limit: String(limit), offset: String(offset) })
    return api<Page<AdminDevice>>(`/devices?${params}`)
  },
  devicesCursor: (query = '', status = 'all', limit = 50, cursor = '', signal?: AbortSignal) => {
    const params = cursorParams(limit, cursor)
    params.set('q', query)
    params.set('status', status)
    return api<CursorPage<AdminDevice>>(`/devices?${params}`, signal)
  },

  networks: () => fetchAllPages((limit, offset) => api<Page<AdminNetwork>>(`/networks?limit=${limit}&offset=${offset}`)),
  rooms: () => fetchAllPages((limit, offset) => api<Page<AdminRoom>>(`/rooms?limit=${limit}&offset=${offset}`)),
  networksCursor: (limit = 50, cursor = '', signal?: AbortSignal) => {
    const params = cursorParams(limit, cursor)
    return api<CursorPage<AdminNetwork>>(`/networks?${params}`, signal)
  },
  roomsCursor: (limit = 50, cursor = '', signal?: AbortSignal) => {
    const params = cursorParams(limit, cursor)
    return api<CursorPage<AdminRoom>>(`/rooms?${params}`, signal)
  },
}
