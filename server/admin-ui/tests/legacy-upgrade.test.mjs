import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { runInNewContext } from 'node:vm'
import { recoverAssetLoad } from '../src/assetRecovery.ts'

const source = readFileSync(new URL('../../admin/legacy_chunks.go', import.meta.url), 'utf8')
const bridge = source.match(/fmt\.Sprintf\(`([\s\S]*?)`, export\)/)?.[1]?.replace('export function %s()', 'function LegacyView()')
assert.ok(bridge, 'legacy upgrade module is missing')

test('legacy and hashed assets share one automatic reload budget', () => {
  const values = new Map()
  const storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) }
  let reloads = 0
  const reload = () => { reloads++ }
  const execute = (now, online = true, sessionStorage = storage) => {
    assert.throws(() => runInNewContext(bridge, { Date: { now: () => now }, navigator: { onLine: online }, sessionStorage, window: { location: { reload } } }), /console was updated/)
  }
  execute(100_000)
  assert.equal(reloads, 1)
  assert.equal(recoverAssetLoad({ storage, reload, now: 100_001, online: true }), false)
  execute(110_000)
  assert.equal(reloads, 1)
  execute(160_000)
  assert.equal(reloads, 2)
  execute(230_000, false)
  assert.equal(reloads, 2)
  execute(230_000, true, { getItem: () => { throw new Error('blocked') }, setItem() {} })
  assert.equal(reloads, 2)
})
