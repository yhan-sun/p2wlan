import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import test from 'node:test'
import { build } from 'esbuild'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { CONNECTION_PAGE_SIZE, closeConnectionDetailSearch, connectionDetailIsOpen, connectionWorkspaceSearch, connectionWorkspaceTab, isolateConnectionSearch, lastAvailableConnectionPage, readConnectionSearch, readDirectionOnlySearch, selectConnectionSearch, updateConnectionSearch } from '../src/features/connections/connectionNavigation.ts'

const require = createRequire(import.meta.url)
// Share the CJS contexts used by the in-memory compiled component.
const { MemoryRouter } = require('react-router-dom')
const { QueryClient, QueryClientProvider, QueryObserver, onlineManager } = require('@tanstack/react-query')

async function compileSource(entry, plugins = []) {
  const output = await build({
    absWorkingDir: new URL('..', import.meta.url).pathname,
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    write: false,
    external: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query', '@xyflow/react'],
    loader: { '.css': 'empty' },
    plugins,
  })
  const module = { exports: {} }
  new Function('module', 'exports', 'require', output.outputFiles[0].text)(module, module.exports, (name) => name.endsWith('.css') ? {} : require(name))
  return module.exports
}

const { ConnectionsPage } = await compileSource('src/features/connections/ConnectionsPage.tsx')
const { ConnectionWorkspace, enterConnectionView } = await compileSource('src/features/connections/ConnectionWorkspace.tsx')
const { ConnectionTopology } = await compileSource('src/features/connections/ConnectionTopology.tsx')
const inlineTopology = {
  name: 'synchronous-topology-test',
  setup(builder) {
    builder.onLoad({ filter: /ConnectionsPage\.tsx$/ }, ({ path: filename }) => ({
      // Resolve the real lazy module synchronously only in SSR so the tests can
      // inspect the surface's ownership during uncached requests and failures.
      contents: readFileSync(filename, 'utf8').replace(/const ConnectionTopology = lazy\([^\n]+\)/, "import { ConnectionTopology } from './ConnectionTopology'"),
      loader: 'tsx', resolveDir: path.dirname(filename),
    }))
  },
}
const { ConnectionsPage: InlineTopologyPage } = await compileSource('src/features/connections/ConnectionsPage.tsx', [inlineTopology])
const { ConnectionTopology: FullscreenTopology } = await compileSource('src/features/connections/ConnectionTopology.tsx', [{
  name: 'start-in-fullscreen',
  setup(builder) {
    builder.onLoad({ filter: /ConnectionTopology\.tsx$/ }, ({ path: filename }) => ({
      contents: readFileSync(filename, 'utf8').replace('const [fullscreen, setFullscreen] = useState(false)', 'const [fullscreen, setFullscreen] = useState(true)'),
      loader: 'tsx', resolveDir: path.dirname(filename),
    }))
  },
}])

test('connection scope, filters, view and page round-trip through a copied URL', () => {
  const search = updateConnectionSearch(new URLSearchParams(), {
    q: '张 工 + &', network_id: 'network:/&', account_id: 'account 1', device_id: 'device/2',
    path: 'relay', freshness: 'stale', view: 'topology', page: '3', show_stale: '1',
  })
  const value = readConnectionSearch(new URLSearchParams(search.toString()))
  assert.deepEqual(value, {
    query: '张 工 + &', networkId: 'network:/&', accountId: 'account 1', deviceId: 'device/2',
    path: 'relay', freshness: 'stale', view: 'topology', page: 3, showStale: true, selected: null,
  })
})

test('opening and closing a direction preserves the original list scope and page', () => {
  const list = new URLSearchParams('q=demo&account_id=account-a&page=2&freshness=stale')
  const selected = { network_id: 'network-b', reporting_device_id: 'a', remote_device_id: 'b' }
  const opened = selectConnectionSearch(list, selected)
  assert.deepEqual(readConnectionSearch(opened).selected, selected)
  assert.equal(opened.has('network_id'), false)
  assert.equal(opened.get('selected_network_id'), 'network-b')
  assert.equal(opened.get('page'), '2')
  assert.equal(selectConnectionSearch(opened, null).toString(), list.toString())
  assert.equal(list.has('selected_network_id'), false)
})

test('legacy scoped direction links remain valid and partial identities do not open a drawer', () => {
  const oldLink = new URLSearchParams('network_id=n&reporting_device_id=a&remote_device_id=b&user_id=u')
  assert.deepEqual(readConnectionSearch(oldLink).selected, { network_id: 'n', reporting_device_id: 'a', remote_device_id: 'b' })
  assert.equal(readConnectionSearch(oldLink).accountId, 'u')
  oldLink.delete('remote_device_id')
  assert.equal(readConnectionSearch(oldLink).selected, null)
})

test('closing details keeps the graph selection and clicking the direction reopens it', () => {
  const direction = { network_id: 'n', reporting_device_id: 'a', remote_device_id: 'b' }
  const opened = selectConnectionSearch(new URLSearchParams('tab=topology&network_id=n'), direction)
  assert.equal(connectionDetailIsOpen(opened), true)
  const closed = closeConnectionDetailSearch(opened)
  assert.deepEqual(readConnectionSearch(closed).selected, direction)
  assert.equal(connectionDetailIsOpen(closed), false)
  assert.equal(connectionDetailIsOpen(selectConnectionSearch(closed, direction)), true)
  assert.equal(selectConnectionSearch(closed, null).has('detail'), false)
  assert.equal(connectionDetailIsOpen(connectionWorkspaceSearch(closed, 'all')), false)
})

test('exact-direction recovery clears conflicting filters and remains visible until explicitly cleared', () => {
  const direction = { network_id: 'selected-network', reporting_device_id: 'a', remote_device_id: 'b' }
  const original = new URLSearchParams('network_id=other&q=filter&path=relay&freshness=stale&account_id=u&device_id=c&page=7&alert_page=2&window_hours=168')
  const focused = isolateConnectionSearch(original, direction)
  assert.deepEqual(readDirectionOnlySearch(focused), direction)
  assert.equal(focused.get('tab'), 'topology')
  assert.equal(focused.get('detail'), 'closed')
  for (const key of ['q', 'path', 'freshness', 'account_id', 'device_id', 'page', 'alert_page']) assert.equal(focused.has(key), false)
  assert.equal(focused.get('window_hours'), '168')
  assert.deepEqual(readDirectionOnlySearch(selectConnectionSearch(focused, direction)), direction)
  assert.equal(readDirectionOnlySearch(selectConnectionSearch(focused, null)), null)
  const incomplete = new URLSearchParams(focused)
  incomplete.delete('remote_device_id')
  assert.equal(readDirectionOnlySearch(incomplete), null)
  const wrongNetwork = new URLSearchParams(focused)
  wrongNetwork.set('network_id', 'other')
  assert.equal(readDirectionOnlySearch(wrongNetwork), null)
  assert.equal(original.get('q'), 'filter')
})

test('invalid URL enums and unsafe pages cannot create malformed API requests', () => {
  for (const page of ['-1', '0', '1.5', 'NaN', 'Infinity', '9007199254740991']) {
    const value = readConnectionSearch(new URLSearchParams({ page, path: 'invalid', freshness: 'invalid', view: 'invalid' }))
    assert.equal(value.page, 1)
    assert.equal(value.path, '')
    assert.equal(value.freshness, '')
    assert.equal(value.view, 'table')
  }
})

test('freshness expiration returns an out-of-range page to the final valid page', () => {
  assert.equal(CONNECTION_PAGE_SIZE, 25)
  assert.equal(lastAvailableConnectionPage(2, 26), 2)
  assert.equal(lastAvailableConnectionPage(2, 24), 1)
  assert.equal(lastAvailableConnectionPage(4, 50), 2)
  assert.equal(lastAvailableConnectionPage(4, 0), 1)
  assert.equal(lastAvailableConnectionPage(1, 100), 1)
})

test('workspace tabs preserve directional selection and use one freshness filter', () => {
  const original = new URLSearchParams('network_id=n&account_id=u&device_id=a&q=lab&freshness=stale&page=3&selected_network_id=n&reporting_device_id=a&remote_device_id=b')
  for (const tab of ['health', 'all', 'topology', 'trends']) {
    const next = connectionWorkspaceSearch(original, tab)
    assert.equal(connectionWorkspaceTab(next), tab)
    for (const name of ['network_id', 'account_id', 'device_id', 'q', 'freshness', 'page', 'selected_network_id', 'reporting_device_id', 'remote_device_id']) assert.equal(next.get(name), original.get(name))
    assert.equal(readConnectionSearch(next).freshness, 'stale')
  }
  assert.equal(original.has('tab'), false)
  assert.equal(connectionWorkspaceTab(new URLSearchParams(), '/health'), 'health')
  const legacy = connectionWorkspaceSearch(new URLSearchParams('view=topology&network_id=n'), 'all')
  assert.equal(legacy.get('freshness'), 'fresh')
  assert.equal(legacy.has('view'), false)
  assert.equal(readConnectionSearch(connectionWorkspaceSearch(new URLSearchParams(), 'topology')).freshness, '')
})

test('empty live topology retains the stale control so historical paths are reachable', () => {
  const html = renderToStaticMarkup(createElement(ConnectionTopology, {
    connections: [], networkName: 'Test network', showStale: false,
    onShowStaleChange() {}, onSelect() {},
  }))
  assert.match(html, /aria-label="显示过期观测"/)
  assert.match(html, /aria-pressed="false"/)
  assert.match(html, /暂无可展示的路径观测/)
  assert.match(html, /disabled=""[^>]*aria-label="全屏"/)
})

const connection = {
  schema_version: 1, directional: true,
  network_id: 'n', network_name: 'Test network', reporting_device_id: 'a', reporting_device_name: 'Device A',
  reporting_user_id: 'user-a', reporting_username: 'Alice', remote_device_id: 'b', remote_device_name: 'Device B',
  remote_user_id: 'user-b', remote_username: 'Bob', lifecycle: 'online', current_path: 'direct', previous_path: null,
  transition_reason: 'direct_committed', path_age_ms: 2000, observed_at: 1000, received_at: 1000,
  fresh: true, freshness: 'fresh', observation_revision: 1,
}

function renderPage(client, url = '/connections', PageComponent = ConnectionsPage) {
  return renderToStaticMarkup(createElement(QueryClientProvider, { client },
    createElement(MemoryRouter, { initialEntries: [url] }, createElement(PageComponent))))
}

test('uncached topology requests and failures retain the surface instead of replacing its state owner', async (t) => {
  const { client } = pageClient(t)
  const key = ['connections', 'topology', '', 'n', '', '', '', '']
  const url = '/connections?tab=topology&network_id=n'
  const pending = renderPage(client, url, InlineTopologyPage)
  assert.match(pending, /connection-topology-workspace/)
  assert.match(pending, /正在读取权威连接拓扑/)
  assert.doesNotMatch(pending, /暂无可展示的路径观测/)
  await assert.rejects(client.fetchQuery({ queryKey: key, queryFn: () => Promise.reject(new Error('Uncached topology unavailable')) }))
  client.setQueryDefaults(key, { retryOnMount: false })
  const failed = renderPage(client, url, InlineTopologyPage)
  assert.match(failed, /connection-topology-workspace/)
  assert.match(failed, /Uncached topology unavailable/)
  assert.match(failed, /重试/)
  client.setQueryData(key, { total: 0, limit: 100, offset: 0, items: [] })
  const empty = renderPage(client, url, InlineTopologyPage)
  assert.match(empty, /connection-topology-workspace/)
  assert.match(empty, /暂无可展示的路径观测/)
})

test('fullscreen keeps an enabled exit for loading, offline, failed and empty filter results', () => {
  for (const state of [{ loading: true }, { loading: true, offline: true }, { error: new Error('Filter failed') }, {}]) {
    const html = renderToStaticMarkup(createElement(FullscreenTopology, {
      ...state, connections: [], networkName: 'Test network', showStale: false, onShowStaleChange() {}, onSelect() {},
    }))
    assert.match(html, /role="dialog"/)
    assert.match(html, /aria-label="退出全屏"/)
    assert.doesNotMatch(html, /disabled=""[^>]*aria-label="退出全屏"/)
    if (state.offline) assert.match(html, /浏览器当前离线/)
  }
})

test('fullscreen no-path observations retain a way to open their directional details', () => {
  const html = renderToStaticMarkup(createElement(FullscreenTopology, {
    connections: [{ ...connection, current_path: null }], networkName: 'Test network', showStale: true,
    onShowStaleChange() {}, onSelect() {},
  }))
  assert.match(html, /无路径观测/)
  assert.match(html, /<button[^>]*><strong>Device A → Device B<\/strong>/)
})

function pageClient(t, offset = 0, total = 1, items = [connection]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  t.after(() => client.clear())
  const key = ['connections', 'table', '', '', '', '', '', '', offset]
  client.setQueryData(key, { total, offset, limit: 25, items })
  client.setQueryData(['connections', 'networks'], { pages: [{ total: 1, offset: 0, limit: 100, items: [{ id: 'n', name: 'Test network' }] }], pageParams: [0] })
  return { client, key }
}

test('workspace introduces the task before its labelled navigation and scoped list', (t) => {
  const { client } = pageClient(t)
  const html = renderPage(client, '/connections?tab=all', ConnectionWorkspace)
  assert.match(html, /<h2[^>]*>连接排障<\/h2>/)
  assert.match(html, /<nav[^>]*aria-label="连接排障视图"/)
  assert.ok(html.indexOf('查看设备之间的连接路径') < html.indexOf('aria-label="连接排障视图"'))
  assert.match(html, /aria-current="page"[^>]*class="active"[^>]*>.*?全部观测/)
  for (const label of ['搜索连接', '按网络过滤', '按路径过滤', '按观测新鲜度过滤']) assert.ok(html.includes(`aria-label="${label}"`))
})

test('tab entry preserves fixed positioning and cancels for reduced motion or cleanup', () => {
  const listeners = new Set()
  const preference = {
    matches: false,
    addEventListener(type, listener) { assert.equal(type, 'change'); listeners.add(listener) },
    removeEventListener(type, listener) { assert.equal(type, 'change'); listeners.delete(listener) },
  }
  let cancelled = 0
  let entered = 0
  const surface = { animate(frames, options) {
    entered += 1
    assert.ok(frames.every((frame) => Object.keys(frame).every((key) => key === 'opacity')), 'A transformed ancestor breaks the fixed fullscreen graph')
    assert.equal(options.duration, 200)
    assert.equal(options.fill, undefined, 'Do not retain an opacity stacking context after entry')
    return { cancel() { cancelled += 1 } }
  } }
  const cleanup = enterConnectionView(surface, preference)
  assert.equal(entered, 1)
  preference.matches = true
  listeners.forEach((listener) => listener())
  assert.equal(cancelled, 1)
  cleanup()
  assert.equal(cancelled, 2)
  assert.equal(listeners.size, 0)
  assert.equal(enterConnectionView(surface, preference), undefined)
  assert.equal(entered, 1, 'Reduced motion must show the final view immediately')
  assert.equal(enterConnectionView(null, preference), undefined)
})

test('direction rows group path and freshness without repeating internal network identifiers', (t) => {
  const { client } = pageClient(t, 0, 1, [{ ...connection, network_id: 'internal-network-uuid' }])
  const html = renderPage(client)
  const row = html.match(/<tbody>(.*?)<\/tbody>/s)?.[1]
  assert.ok(row)
  assert.match(row, /aria-label="连接详情: Device A → Device B"/)
  assert.match(row, /Test network/)
  assert.doesNotMatch(row, /internal-network-uuid/)
  assert.match(row, /connection-path-cell.*?直连.*?新鲜/s)
  assert.equal((html.match(/<th>/g) ?? []).length, 7)
})

test('background errors keep the last list visible while explicitly labelling the cache', async (t) => {
  const { client, key } = pageClient(t)
  await assert.rejects(client.fetchQuery({ queryKey: key, staleTime: 0, queryFn: () => Promise.reject(new Error('Test outage')) }))
  const html = renderPage(client)
  assert.match(html, /Device A/)
  assert.match(html, /刷新失败/)
  assert.match(html, /缓存快照/)
})

test('a directory snapshot cannot replace the connection snapshot update time', (t) => {
  const { client, key } = pageClient(t)
  const oldDirectory = new Date('2024-01-02T03:04:05Z').getTime()
  const newConnection = new Date('2025-06-07T08:09:10Z').getTime()
  client.getQueryCache().find({ queryKey: ['connections', 'networks'], exact: true }).setState({ dataUpdatedAt: oldDirectory })
  client.getQueryCache().find({ queryKey: key, exact: true }).setState({ dataUpdatedAt: newConnection })
  const html = renderPage(client)
  // HTML attribute names are case-insensitive; React's real SSR serializer
  // currently emits dateTime. Compare the complete values, not its spelling.
  const timestamps = [...html.matchAll(/<time\b[^>]*\bdatetime="([^"]+)"/gi)].map((match) => match[1])
  assert.deepEqual(timestamps, [new Date(newConnection).toISOString()])
  assert.equal(timestamps.includes(new Date(oldDirectory).toISOString()), false)
})

test('offline polling retains the list and displays a paused snapshot warning', (t) => {
  const { client, key } = pageClient(t)
  onlineManager.setOnline(false)
  const observer = new QueryObserver(client, { queryKey: key, staleTime: 0, queryFn: () => Promise.resolve({}) })
  const unsubscribe = observer.subscribe(() => {})
  t.after(() => { unsubscribe(); onlineManager.setOnline(true) })
  assert.equal(observer.getCurrentResult().fetchStatus, 'paused')
  const html = renderPage(client)
  assert.match(html, /Device A/)
  assert.match(html, /当前离线，更新已暂停/)
  assert.match(html, /缓存快照/)
})

test('a shrinking result never renders an inverted page range or false empty result', (t) => {
  const { client } = pageClient(t, 25, 24, [])
  const html = renderPage(client, '/connections?page=2')
  assert.match(html, /正在调整分页/)
  assert.doesNotMatch(html, /26.*–.*24/)
  assert.doesNotMatch(html, /当前筛选条件下没有符合条件/)
})
