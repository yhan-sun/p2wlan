import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import test from 'node:test'
import { build } from 'esbuild'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { CONNECTION_PAGE_SIZE, lastAvailableConnectionPage, readConnectionSearch, selectConnectionSearch, updateConnectionSearch } from '../src/connectionNavigation.ts'

const require = createRequire(import.meta.url)
// Share the CJS contexts used by the in-memory compiled component.
const { MemoryRouter } = require('react-router-dom')
const { QueryClient, QueryClientProvider, QueryObserver, onlineManager } = require('@tanstack/react-query')

async function compileSource(entry) {
  const output = await build({
    absWorkingDir: new URL('..', import.meta.url).pathname,
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    write: false,
    external: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query', '@xyflow/react'],
    loader: { '.css': 'empty' },
  })
  const module = { exports: {} }
  new Function('module', 'exports', 'require', output.outputFiles[0].text)(module, module.exports, (name) => name.endsWith('.css') ? {} : require(name))
  return module.exports
}

const { ConnectionsPage } = await compileSource('src/ConnectionsPage.tsx')
const { ConnectionTopology } = await compileSource('src/ConnectionTopology.tsx')

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

function renderPage(client, url = '/connections') {
  return renderToStaticMarkup(createElement(QueryClientProvider, { client },
    createElement(MemoryRouter, { initialEntries: [url] }, createElement(ConnectionsPage))))
}

function pageClient(t, offset = 0, total = 1, items = [connection]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  t.after(() => client.clear())
  const key = ['connections', 'table', '', '', '', '', '', '', offset]
  client.setQueryData(key, { total, offset, limit: 25, items })
  client.setQueryData(['connections', 'networks'], { pages: [{ total: 1, offset: 0, limit: 100, items: [{ id: 'n', name: 'Test network' }] }], pageParams: [0] })
  return { client, key }
}

test('background errors keep the last list visible while explicitly labelling the cache', async (t) => {
  const { client, key } = pageClient(t)
  await assert.rejects(client.fetchQuery({ queryKey: key, staleTime: 0, queryFn: () => Promise.reject(new Error('Test outage')) }))
  const html = renderPage(client)
  assert.match(html, /Device A/)
  assert.match(html, /刷新失败/)
  assert.match(html, /缓存快照/)
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
