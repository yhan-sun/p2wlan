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

async function allTopologyAccounts(): Promise<Page<AdminAccount>> {
  return fetchAllPages((limit, offset) => accountPage('', limit, offset))
}

async function allNetworks(): Promise<Page<AdminNetwork>> {
  return fetchAllPages((limit, offset) => api<Page<AdminNetwork>>(`/networks?limit=${limit}&offset=${offset}`))
}

async function allRooms(): Promise<Page<AdminRoom>> {
  return fetchAllPages((limit, offset) => api<Page<AdminRoom>>(`/rooms?limit=${limit}&offset=${offset}`))
}

export const adminApi = {
  overview: () => api<AdminOverview>('/overview'),
  runtime: () => api<AdminRuntime>('/runtime'),
  accounts: (query = '', limit = 50, offset = 0) => {
    // The topology selector intentionally asks for the server maximum (200).
    // Treat that call as an all-account option request and continue paging so
    // installations with hundreds or thousands of accounts remain navigable.
    if (query === '' && limit === MAX_SERVER_PAGE && offset === 0) return allTopologyAccounts()
    return accountPage(query, limit, offset)
  },
  account: (id: string) => api<AdminAccountDetail>(`/accounts/${encodeURIComponent(id)}`),
  topology: (accountId?: string) => accountId
    ? api<AdminTopology>(`/accounts/${encodeURIComponent(accountId)}/topology`)
    : api<AdminTopology>('/topology'),
  devices: (query = '', status = 'all', limit = 50, offset = 0) => {
    const params = new URLSearchParams({ q: query, status, limit: String(limit), offset: String(offset) })
    return api<Page<AdminDevice>>(`/devices?${params}`)
  },
  networks: () => allNetworks(),
  rooms: () => allRooms(),
}
