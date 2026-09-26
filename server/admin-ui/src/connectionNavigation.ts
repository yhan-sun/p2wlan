import type { AdminConnection } from './types'

export const CONNECTION_PAGE_SIZE = 25

export type ConnectionIdentity = Pick<AdminConnection, 'network_id' | 'reporting_device_id' | 'remote_device_id'> &
  Partial<Pick<AdminConnection, 'network_name' | 'reporting_device_name' | 'reporting_username' | 'remote_device_name' | 'remote_username'>>

export function readConnectionSearch(params: URLSearchParams) {
  const rawPage = Number(params.get('page') ?? 1)
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 && Number.isSafeInteger((rawPage - 1) * CONNECTION_PAGE_SIZE) ? rawPage : 1
  const networkId = params.get('network_id') ?? ''
  const selectedNetworkId = params.get('selected_network_id') || networkId
  const reportingDeviceId = params.get('reporting_device_id') ?? ''
  const remoteDeviceId = params.get('remote_device_id') ?? ''
  const path = params.get('path') ?? ''
  const freshness = params.get('freshness') ?? ''
  return {
    query: params.get('q') ?? '',
    networkId,
    accountId: params.get('account_id') || params.get('user_id') || '',
    deviceId: params.get('device_id') ?? '',
    path: ['direct', 'relay', 'none'].includes(path) ? path : '',
    freshness: (freshness === 'fresh' || freshness === 'stale' ? freshness : '') as 'fresh' | 'stale' | '',
    view: params.get('view') === 'topology' ? 'topology' as const : 'table' as const,
    showStale: params.get('show_stale') === '1',
    page,
    selected: selectedNetworkId && reportingDeviceId && remoteDeviceId ? {
      network_id: selectedNetworkId,
      reporting_device_id: reportingDeviceId,
      remote_device_id: remoteDeviceId,
    } : null,
  }
}

/** Preserve unrelated scope and list state when opening or closing a direction. */
export function updateConnectionSearch(params: URLSearchParams, changes: Record<string, string | null>): URLSearchParams {
  const next = new URLSearchParams(params)
  for (const [key, value] of Object.entries(changes)) {
    if (!value || (key === 'page' && value === '1') || (key === 'view' && value === 'table')) next.delete(key)
    else next.set(key, value)
  }
  return next
}

export function selectConnectionSearch(params: URLSearchParams, connection: ConnectionIdentity | null): URLSearchParams {
  return updateConnectionSearch(params, {
    selected_network_id: connection?.network_id ?? null,
    reporting_device_id: connection?.reporting_device_id ?? null,
    remote_device_id: connection?.remote_device_id ?? null,
  })
}

export function lastAvailableConnectionPage(page: number, total: number): number {
  return Math.min(page, Math.max(1, Math.ceil(total / CONNECTION_PAGE_SIZE)))
}
