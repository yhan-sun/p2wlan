import { api } from './api'

export interface TrendBucket {
  bucket_start: number
  accepted_observation_samples: number
  direct_observation_samples: number
  relay_observation_samples: number
  no_path_observation_samples: number
  path_switches: number
  direct_failures: number
  relay_failures: number
  validation_rtt_samples: number
  average_validation_rtt_ms?: number
  max_validation_rtt_ms?: number
  validation_rtt_p50_upper_bound_ms?: number
  validation_rtt_p95_upper_bound_ms?: number
  validation_rtt_histogram: {
    le_50_ms: number
    le_100_ms: number
    le_250_ms: number
    le_500_ms: number
    le_1000_ms: number
    le_3000_ms: number
    le_10000_ms: number
    gt_10000_ms: number
  }
}

export interface ConnectionTrendData {
  schema_version: number
  generated_at: number
  bucket_seconds: number
  window_hours: number
  retention_hours: number
  network_id?: string
  network_name?: string
  sample_semantics: string
  percentile_semantics: string
  rtt_bucket_bounds_ms: number[]
  buckets: TrendBucket[]
}

export const TREND_WINDOWS = [24, 168, 720] as const

export function connectionTrends(networkId: string, windowHours: number, signal?: AbortSignal) {
  const params = new URLSearchParams({ window_hours: String(windowHours) })
  if (networkId) params.set('network_id', networkId)
  return api<ConnectionTrendData>(`/connection-trends?${params}`, signal)
}

export interface HealthDirection {
  network_id: string
  reporting_device_id: string
  remote_device_id: string
}

export function readHealthSearch(params: URLSearchParams) {
  const windowSeconds = Number(params.get('window_seconds'))
  const trendHours = Number(params.get('window_hours'))
  const direction = {
    network_id: params.get('selected_network_id') ?? '',
    reporting_device_id: params.get('reporting_device_id') ?? '',
    remote_device_id: params.get('remote_device_id') ?? '',
  }
  return {
    networkId: params.get('network_id') ?? '',
    accountId: params.get('account_id') ?? '',
    deviceId: params.get('device_id') ?? '',
    windowSeconds: [3600, 21600, 86400].includes(windowSeconds) ? windowSeconds : 3600,
    trendHours: TREND_WINDOWS.some((hours) => hours === trendHours) ? trendHours : 24,
    direction: Object.values(direction).every(Boolean) ? direction : null,
  }
}

export function selectHealthDirection(params: URLSearchParams, direction: HealthDirection | null) {
  const next = new URLSearchParams(params)
  for (const [parameter, value] of [
    ['selected_network_id', direction?.network_id],
    ['reporting_device_id', direction?.reporting_device_id],
    ['remote_device_id', direction?.remote_device_id],
  ]) {
    if (value) next.set(parameter!, value)
    else next.delete(parameter!)
  }
  return next
}

export function clearHealthScope(params: URLSearchParams, scope: 'account_id' | 'device_id' | 'all' = 'all') {
  const next = selectHealthDirection(params, null)
  if (scope === 'all' || scope === 'account_id') next.delete('account_id')
  if (scope === 'all' || scope === 'device_id') next.delete('device_id')
  return next
}

export function summarizeTrends(buckets: TrendBucket[]) {
  const totals = buckets.reduce((sum, bucket) => ({
    samples: sum.samples + bucket.accepted_observation_samples,
    direct: sum.direct + bucket.direct_observation_samples,
    relay: sum.relay + bucket.relay_observation_samples,
    noPath: sum.noPath + bucket.no_path_observation_samples,
    switches: sum.switches + bucket.path_switches,
    failures: sum.failures + bucket.direct_failures + bucket.relay_failures,
    rttSamples: sum.rttSamples + bucket.validation_rtt_samples,
  }), { samples: 0, direct: 0, relay: 0, noPath: 0, switches: 0, failures: 0, rttSamples: 0 })
  return { ...totals, directShare: totals.samples > 0 ? totals.direct / totals.samples : null }
}

// Missing P95 with RTT samples means the percentile is in the overflow bucket,
// not a zero-millisecond reading. Missing RTT samples must leave a chart gap.
export function bucketP95(bucket: TrendBucket): { kind: 'empty' } | { kind: 'overflow' } | { kind: 'bound'; value: number } {
  if (bucket.validation_rtt_samples <= 0) return { kind: 'empty' }
  if (bucket.validation_rtt_p95_upper_bound_ms !== undefined) return { kind: 'bound', value: bucket.validation_rtt_p95_upper_bound_ms }
  return { kind: 'overflow' }
}

export function lineSegments(values: Array<number | null>, max: number, width = 640, height = 150) {
  const segments: Array<Array<[number, number]>> = []
  let current: Array<[number, number]> = []
  const ceiling = Math.max(1, max)
  values.forEach((value, index) => {
    if (value === null || !Number.isFinite(value)) {
      if (current.length) segments.push(current)
      current = []
      return
    }
    current.push([(index + 0.5) * width / Math.max(1, values.length), height - value / ceiling * height])
  })
  if (current.length) segments.push(current)
  return segments
}
