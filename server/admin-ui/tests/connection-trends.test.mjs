import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { build } from 'esbuild'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

const require = createRequire(new URL('../package.json', import.meta.url))
// The in-memory TSX bundle uses CJS, so use the same query context entrypoint.
const { QueryClient, QueryClientProvider, onlineManager } = require('@tanstack/react-query')
const { MemoryRouter } = require('react-router-dom')
async function source(entry, plugins = []) {
  const result = await build({
    absWorkingDir: fileURLToPath(new URL('..', import.meta.url)),
    entryPoints: [entry], bundle: true, platform: 'node', format: 'cjs', write: false,
    external: ['react', 'react/jsx-runtime', '@tanstack/react-query', 'react-router-dom'], plugins,
    loader: { '.css': 'empty' },
  })
  const module = { exports: {} }
  new Function('module', 'exports', 'require', result.outputFiles[0].text)(module, module.exports, require)
  return module.exports
}
const { connectionTrends, clearHealthScope, readHealthSearch, selectHealthDirection, summarizeTrends, bucketP95, lineSegments } = await source('src/trends.ts')
const { adminApi } = await source('src/api.ts')
const { ConnectionTrends } = await source('src/ConnectionTrends.tsx')
const { ConnectionHealthPage } = await source('src/ConnectionHealthPage.tsx', [{
  name: 'unused-drawer',
  setup(builder) {
    builder.onResolve({ filter: /^\.\/ConnectionsPage$/ }, () => ({ path: 'drawer', namespace: 'test' }))
    builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export function ConnectionDrawer() { return null }' }))
  },
}])

function bucket(overrides = {}) {
  return {
    bucket_start: 1_800_000_000, accepted_observation_samples: 0,
    direct_observation_samples: 0, relay_observation_samples: 0, no_path_observation_samples: 0,
    path_switches: 0, direct_failures: 0, relay_failures: 0, validation_rtt_samples: 0,
    validation_rtt_histogram: { le_50_ms: 0, le_100_ms: 0, le_250_ms: 0, le_500_ms: 0, le_1000_ms: 0, le_3000_ms: 0, le_10000_ms: 0, gt_10000_ms: 0 },
    ...overrides,
  }
}

test('trends request preserves network identity, full 30-day window, and cancellation', async (t) => {
  const previous = new Map(['sessionStorage', 'fetch'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  t.after(() => { for (const [key, descriptor] of previous) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key) } })
  Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: { getItem: () => 'test-trends-token' } })
  const controller = new AbortController()
  const network = '网:/?+&=#络'
  globalThis.fetch = async (path, options) => {
    const url = new URL(path, 'https://control.example.test')
    assert.equal(url.pathname, '/admin/api/v1/connection-trends')
    assert.equal(url.searchParams.get('network_id'), network)
    assert.equal(url.searchParams.get('window_hours'), '720')
    assert.equal(options.signal, controller.signal)
    return Response.json({ buckets: [] })
  }
  assert.deepEqual(await connectionTrends(network, 720, controller.signal), { buckets: [] })
  controller.abort()
  globalThis.fetch = () => assert.fail('cancelled trend requests must not fetch')
  await assert.rejects(connectionTrends('', 24, controller.signal), { name: 'AbortError' })
})

test('health deep links validate windows and require the full directional identity', () => {
  assert.deepEqual(readHealthSearch(new URLSearchParams('window_seconds=-1&window_hours=721&reporting_device_id=a&remote_device_id=b')), {
    networkId: '', accountId: '', deviceId: '', windowSeconds: 3600, trendHours: 24, direction: null,
  })
  const params = new URLSearchParams({ network_id: 'scope', window_seconds: '21600', window_hours: '168', retained: 'yes' })
  const direction = { network_id: 'network:+&', reporting_device_id: 'source/?', remote_device_id: 'destination=尾' }
  const selected = selectHealthDirection(params, direction)
  assert.deepEqual(readHealthSearch(new URLSearchParams(selected.toString())), { networkId: 'scope', accountId: '', deviceId: '', windowSeconds: 21600, trendHours: 168, direction })
  const closed = selectHealthDirection(selected, null)
  assert.equal(closed.toString(), params.toString())
  assert.equal(readHealthSearch(selected).direction.reporting_device_id, direction.reporting_device_id)
})

test('health account and device deep links reach API filters without losing their identities', async (t) => {
  const previous = new Map(['sessionStorage', 'fetch'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  t.after(() => { for (const [key, descriptor] of previous) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key) } })
  Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: { getItem: () => 'test-health-token' } })
  const filters = readHealthSearch(new URLSearchParams({ network_id: 'room&1', account_id: 'owner/尾', device_id: 'lab?=stale', window_seconds: '86400' }))
  const controller = new AbortController()
  globalThis.fetch = async (path, options) => {
    const url = new URL(path, 'https://control.example.test')
    assert.equal(url.pathname, '/admin/api/v1/connection-health')
    assert.equal(url.searchParams.get('network_id'), 'room&1')
    assert.equal(url.searchParams.get('account_id'), 'owner/尾')
    assert.equal(url.searchParams.get('device_id'), 'lab?=stale')
    assert.equal(url.searchParams.get('window_seconds'), '86400')
    assert.equal(options.signal, controller.signal)
    return Response.json({ alerts: [] })
  }
  await adminApi.connectionHealth(filters, 100, controller.signal)
})

test('clearing health scopes closes the selected direction and preserves network and windows', () => {
  const params = selectHealthDirection(new URLSearchParams({ network_id: 'room', account_id: 'owner', device_id: 'device', window_seconds: '21600', window_hours: '720' }), {
    network_id: 'room', reporting_device_id: 'device', remote_device_id: 'other',
  })
  const accountOnly = readHealthSearch(clearHealthScope(params, 'device_id'))
  assert.equal(accountOnly.deviceId, '')
  assert.equal(accountOnly.accountId, 'owner')
  assert.equal(accountOnly.direction, null)
  const all = readHealthSearch(clearHealthScope(params))
  assert.deepEqual(all, { networkId: 'room', accountId: '', deviceId: '', windowSeconds: 21600, trendHours: 720, direction: null })
  assert.equal(readHealthSearch(params).deviceId, 'device')
})

test('scoped health renders its own cached summary and suppresses unsupported trend queries', (t) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  t.after(() => client.clear())
  client.setQueryData(['connection-health', 'room', 3600, 'owner', 'lab-stale'], {
    generated_at: 1_800_000_000, history_limit_per_direction: 50,
    alerts_total: 0, alerts: [], thresholds: { frequent_path_switches: 4, repeated_path_failures: 3 },
    summary: { total_observations: 321, fresh_observations: 1, stale_observations: 320, reporter_offline_observations: 0, fresh_direct: 1, fresh_relay: 0, fresh_online_no_path: 0, recent_path_switches: 0, recent_direct_failures: 0, recent_relay_failures: 0, validation_rtt_samples: 0 },
  })
  const html = renderToStaticMarkup(createElement(QueryClientProvider, { client }, createElement(MemoryRouter, { initialEntries: ['/health?network_id=room&account_id=owner&device_id=lab-stale'] }, createElement(ConnectionHealthPage))))
  assert.match(html, /321/)
  assert.match(html, /清除账号范围: owner/)
  assert.match(html, /清除设备范围: lab-stale/)
  assert.match(html, /历史趋势仅支持按网络汇总/)
  assert.doesNotMatch(html, /type="range"|connection-trends/)
  assert.equal(client.getQueryCache().findAll({ queryKey: ['connection-trends'] }).length, 0)
})

test('direct sample share uses all accepted samples, not an average of hourly percentages', () => {
  const totals = summarizeTrends([
    bucket({ accepted_observation_samples: 1, direct_observation_samples: 1 }),
    bucket({ accepted_observation_samples: 99, relay_observation_samples: 89, no_path_observation_samples: 10, path_switches: 3, direct_failures: 2, relay_failures: 4 }),
  ])
  assert.equal(totals.directShare, 0.01)
  assert.equal(totals.samples, 100)
  assert.equal(totals.switches, 3)
  assert.equal(totals.failures, 6)
  assert.equal(summarizeTrends([bucket()]).directShare, null)
})

test('P95 distinguishes no samples, a finite bucket upper bound, and histogram overflow', () => {
  assert.deepEqual(bucketP95(bucket()), { kind: 'empty' })
  assert.deepEqual(bucketP95(bucket({ validation_rtt_samples: 20, validation_rtt_p95_upper_bound_ms: 10000 })), { kind: 'bound', value: 10000 })
  assert.deepEqual(bucketP95(bucket({ validation_rtt_samples: 20 })), { kind: 'overflow' })
})

test('RTT gaps split lines without inventing zeros or bridging unobserved hours', () => {
  const segments = lineSegments([20, 40, null, 0, null, 60], 100, 600, 100)
  assert.deepEqual(segments, [[[50, 80], [150, 60]], [[350, 100]], [[550, 40]]])
  assert.deepEqual(lineSegments([null, null], 0), [])
  assert.ok(lineSegments([0], 0).flat(2).every(Number.isFinite))
})

function renderTrend(t, buckets, state = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  t.after(() => client.clear())
  const key = ['connection-trends', '', 24]
  client.setQueryData(key, {
    schema_version: 1, generated_at: 1_800_003_599, bucket_seconds: 3600,
    window_hours: 24, retention_hours: 720,
    sample_semantics: 'accepted_non_resync_committed_observation_samples',
    percentile_semantics: 'fixed_histogram_upper_bound',
    rtt_bucket_bounds_ms: [50, 100, 250, 500, 1000, 3000, 10000], buckets,
  })
  client.getQueryCache().find({ queryKey: key, exact: true }).setState(state)
  return renderToStaticMarkup(createElement(QueryClientProvider, { client }, createElement(ConnectionTrends, { networkId: '', windowHours: 24, onWindowChange() {} })))
}

test('a failed background refresh retains rendered history and labels it as cached', (t) => {
  const html = renderTrend(t, [bucket({ accepted_observation_samples: 12, direct_observation_samples: 9 })], { status: 'error', error: new Error('temporarily unavailable') })
  assert.match(html, /缓存快照/)
  assert.match(html, /75\.0%/)
  assert.match(html, /type="range"/)
  assert.doesNotMatch(html, /NaN|Infinity/)
})

test('offline cached trends keep their chart and show paused status', (t) => {
  const wasOnline = onlineManager.isOnline()
  onlineManager.setOnline(false)
  t.after(() => onlineManager.setOnline(wasOnline))
  const html = renderTrend(t, [bucket({ accepted_observation_samples: 1, relay_observation_samples: 1 })], { fetchStatus: 'paused' })
  assert.match(html, /当前离线/)
  assert.match(html, /缓存快照/)
  assert.match(html, /type="range"/)
})

test('zero samples render empty-state guidance while overflow keeps an explicit lower bound', (t) => {
  const empty = renderTrend(t, [bucket()])
  assert.match(empty, /此窗口没有已提交的观测样本/)
  assert.match(empty, /此窗口没有 RTT 验证样本/)
  assert.doesNotMatch(empty, /NaN|Infinity/)
  const overflow = renderTrend(t, [bucket({ accepted_observation_samples: 1, direct_observation_samples: 1, validation_rtt_samples: 1, average_validation_rtt_ms: 12000 })])
  assert.match(overflow, /&gt; 10,000 ms/)
  assert.match(overflow, /trend-overflow/)
  assert.doesNotMatch(overflow, /≤ 0 ms/)
})
