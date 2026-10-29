import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import test from 'node:test'
import { build } from 'esbuild'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

const require = createRequire(import.meta.url)
const { MemoryRouter } = require('react-router-dom')
const { QueryClient, QueryClientProvider } = require('@tanstack/react-query')
const output = await build({
  stdin: {
    contents: "export { AccountsPage } from './features/accounts/AccountsPage'; export { DevicesPage } from './features/devices/DevicesPage'; export { NetworksPage } from './features/networks/NetworksPage'",
    resolveDir: new URL('../src', import.meta.url).pathname,
    loader: 'tsx',
  },
  bundle: true, platform: 'node', format: 'cjs', write: false,
  external: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query'],
})
const exported = { exports: {} }
new Function('module', 'exports', 'require', output.outputFiles[0].text)(exported, exported.exports, require)

function renderResource(t, kind, url, data, props = {}) {
  const location = new URL(url, 'https://example.test')
  const p = location.searchParams
  const q = p.get('q') || ''
  const cursor = p.get('cursor') || ''
  const account = props.accountScope?.id || p.get('account_id') || ''
  const tab = props.fixedTab || (p.get('tab') === 'rooms' ? 'rooms' : 'networks')
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  t.after(() => client.clear())
  const key = kind === 'accounts' ? ['accounts', 'cursor', q, cursor]
    : kind === 'devices' ? ['devices', 'cursor', account, q, p.get('status') || 'all', cursor]
      : [tab, 'snapshot', tab, account, q, cursor]
  client.setQueryData(key, { generated_at: 1700000000, total: data.items.length, ...data })
  const component = exported.exports[`${kind[0].toUpperCase()}${kind.slice(1)}Page`]
  return renderToStaticMarkup(createElement(QueryClientProvider, { client }, createElement(MemoryRouter, { initialEntries: [location.pathname + location.search] }, createElement(component, props))))
}

const account = { id: 'account-a', username: 'Alice', email: 'alice@example.test', online_devices: 1, device_count: 2, network_count: 1, room_count: 0, last_seen: 1700000000, created_at: 1700000000 }
const device = { id: 'device-a', device_name: 'Workstation', owner_id: 'account-a', username: 'Alice', network_id: 'default', network_name: 'Personal', online: true, virtual_ip: '10.20.0.2', platform: 'linux', nat_type: 'unknown', last_seen: 1700000000 }
const network = { id: 'network-a', name: 'Office', owner_id: 'account-a', owner_username: 'Alice', cidr: '10.20.0.0/16', member_count: 1, device_count: 1, online_devices: 1, is_room: false }

test('resource headings stay separate from filters and each list has its own count and export action', (t) => {
  for (const [kind, item, title, search] of [
    ['accounts', account, '账号列表', '搜索用户名或邮箱'],
    ['devices', device, '设备列表', '搜索设备、账号、IP 或网络'],
    ['networks', network, '网络列表', '搜索名称、ID、网段或房间码'],
  ]) {
    const html = renderResource(t, kind, `/${kind}`, { items: [item], total: 7 })
    const header = html.match(/<header class="console-page-header">([\s\S]*?)<\/header>/)?.[1]
    assert.ok(header)
    assert.doesNotMatch(header, /<input|<select|role="search"/)
    assert.match(html, new RegExp(`${title} · 7`))
    assert.match(html, /class="resource-list-toolbar" role="search"/)
    assert.ok(html.includes(search))
    assert.match(html, /导出已加载记录/)
  }
})

test('an empty deployment explains where resources originate and hides export and zero-result pagination', (t) => {
  for (const [kind, message, guidance] of [
    ['accounts', '暂无账号', '账号注册后会显示在这里'],
    ['devices', '尚无设备', '设备通过 P2WLAN 客户端注册后显示在这里'],
    ['networks', '暂无网络', '已创建或加入的网络会显示在这里'],
  ]) {
    const html = renderResource(t, kind, `/${kind}`, { items: [], total: 0 })
    assert.ok(html.includes(message))
    assert.ok(html.includes(guidance))
    assert.doesNotMatch(html, /没有符合条件|class="pagination-v2"|导出已加载记录/)
    assert.match(html, /resource-empty-state[\s\S]*href="\/(?:system|accounts|devices)"/)
  }
})

test('filtered empty lists offer clearing filters without pretending the deployment has no resources', (t) => {
  for (const kind of ['accounts', 'devices', 'networks']) {
    const html = renderResource(t, kind, `/${kind}?q=no-match`, { items: [], total: 0 })
    assert.match(html, /没有符合条件/)
    assert.match(html, /请调整筛选条件/)
    assert.match(html, /清除筛选/)
    assert.doesNotMatch(html, /class="pagination-v2"/)
  }
})

test('an empty cursor page retains first-page recovery instead of presenting a false empty deployment', (t) => {
  for (const kind of ['accounts', 'devices', 'networks']) {
    const html = renderResource(t, kind, `/${kind}?cursor=old-cursor&page=2&q=office`, { items: [], total: 0 })
    assert.match(html, /当前页没有记录/)
    assert.match(html, /重新从首页加载/)
    assert.doesNotMatch(html, /class="pagination-v2"/)
  }
})

test('room tab keeps its tabpanel identity and distinguishes missing rooms from missing networks', (t) => {
  const html = renderResource(t, 'networks', '/networks?tab=rooms', { items: [], total: 0 })
  assert.match(html, /房间列表 · 0/)
  assert.match(html, /暂无房间/)
  assert.match(html, /房间需在 P2WLAN 客户端中创建或加入/)
  assert.match(html, /role="tabpanel" id="network-resources-panel" aria-labelledby="network-resources-rooms"/)
})
