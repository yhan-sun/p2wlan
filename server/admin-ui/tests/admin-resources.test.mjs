import assert from 'node:assert/strict'
import test from 'node:test'
import { build } from 'esbuild'
import { createRequire } from 'node:module'
import { summarizeNetworks, topologyForNetwork } from '../src/relationships.ts'
import { withPageParams, connectionLink, relationshipLink } from '../src/pageState.ts'

const fixture = {
  nodes: [
    { id: 'account:a', kind: 'account', account_id: 'a', label: 'Alice' },
    { id: 'account:b', kind: 'account', account_id: 'b', label: 'Bob' },
    { id: 'device:a', kind: 'device', account_id: 'a', network_id: 'default', label: 'Alice laptop', online: true },
    { id: 'device:b', kind: 'device', account_id: 'b', network_id: 'default', label: 'Bob laptop', online: false },
  ],
  edges: [
    { id: 'a', kind: 'attachment', role: 'private-default', source: 'account:a', target: 'device:a' },
    { id: 'b', kind: 'attachment', role: 'private-default', source: 'account:b', target: 'device:b' },
  ],
}

test('default private devices remain visible and never form a cross-account default network', () => {
  const groups = summarizeNetworks(fixture)
  assert.deepEqual(groups.map(({ id, deviceCount, onlineCount }) => ({ id, deviceCount, onlineCount })), [
    { id: 'personal:a', deviceCount: 1, onlineCount: 1 },
    { id: 'personal:b', deviceCount: 1, onlineCount: 0 },
  ])
  const alice = topologyForNetwork(fixture, groups[0].node)
  assert.deepEqual(alice.nodes.map(({ id }) => id), ['account:a', 'device:a'])
  assert.equal(alice.edges.length, 1)
  assert.equal(fixture.nodes.length, 4)
})

test('shared network summaries follow actual attachments rather than a device primary network field', () => {
  const data = {
    ...fixture,
    nodes: [...fixture.nodes, { id: 'network:room', kind: 'room', network_id: 'room', label: 'Shared room', owner_id: 'a' }],
    edges: [...fixture.edges,
      { id: 'm-a', kind: 'membership', role: 'owner', source: 'account:a', target: 'network:room' },
      { id: 'm-b', kind: 'membership', role: 'member', source: 'account:b', target: 'network:room' },
      { id: 'room-device', kind: 'attachment', source: 'network:room', target: 'device:b' },
    ],
  }
  const room = summarizeNetworks(data).find(({ id }) => id === 'room')
  assert.equal(room.deviceCount, 1)
  assert.equal(room.memberCount, 2)
  assert.equal(room.owner, 'Alice')
  assert.equal(room.searchText.includes('bob laptop'), true)
  assert.deepEqual(topologyForNetwork(data, room.node).nodes.map(({ id }) => id), ['account:a', 'account:b', 'device:b', 'network:room'])
})

test('index search and detail search are independent and survive a shareable URL roundtrip', () => {
  const initial = new URLSearchParams({ q: 'Home Lab', account_id: 'a' })
  const selected = withPageParams(initial, { network_id: 'home', resource_q: '' })
  assert.equal(selected.get('q'), 'Home Lab')
  assert.equal(selected.get('resource_q'), null)
  const searched = withPageParams(selected, { resource_q: 'laptop' })
  assert.equal(new URLSearchParams(searched.toString()).get('resource_q'), 'laptop')
  const returned = withPageParams(searched, { network_id: '', resource_q: '' })
  assert.equal(returned.toString(), initial.toString())
})

test('diagnostic links encode identifiers and retain private-default account scope', () => {
  const link = new URL(connectionLink({ deviceId: 'a/b? c', accountId: 'owner&1' }), 'https://example.test')
  assert.equal(link.searchParams.get('device_id'), 'a/b? c')
  assert.equal(link.searchParams.get('account_id'), 'owner&1')
  const personal = new URL(relationshipLink('default', 'owner&1'), 'https://example.test')
  assert.equal(personal.searchParams.get('network_id'), 'personal:owner&1')
  assert.equal(personal.searchParams.get('account_id'), 'owner&1')
})

const built = await build({ entryPoints: ['src/refresh.tsx'], bundle: true, platform: 'node', format: 'cjs', write: false, loader: { '.css': 'empty' } })
const exported = { exports: {} }
new Function('module', 'exports', 'require', built.outputFiles[0].text)(exported, exported.exports, createRequire(import.meta.url))

test('offline and failed background refreshes are recognized even with retained successful data', () => {
  const { queryFreshness } = exported.exports
  assert.deepEqual(queryFreshness([
    { dataUpdatedAt: 2000, fetchStatus: 'paused', error: null },
    { dataUpdatedAt: 1000, fetchStatus: 'idle', error: null },
  ]), { paused: true, failed: false, fetching: false, updatedAt: 1000 })
  assert.deepEqual(queryFreshness([{ dataUpdatedAt: 1000, fetchStatus: 'idle', error: new Error('unavailable') }]), {
    paused: false, failed: true, fetching: false, updatedAt: 1000,
  })
  assert.equal(queryFreshness([{ dataUpdatedAt: 0, fetchStatus: 'paused' }]).updatedAt, 0)
})
