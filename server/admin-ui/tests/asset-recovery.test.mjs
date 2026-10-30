import assert from 'node:assert/strict'
import test from 'node:test'
import { recoverAssetLoad, installAssetRecovery } from '../src/assetRecovery.ts'

test('asset recovery reloads once per window while preserving the existing session', () => {
  const values = new Map([['admin-token', 'existing-session']])
  const storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) }
  let reloads = 0
  const environment = { storage, reload: () => reloads++, now: 1_000_000, online: true }
  assert.equal(recoverAssetLoad(environment), true)
  assert.equal(recoverAssetLoad(environment), false)
  assert.equal(recoverAssetLoad({ ...environment, now: environment.now + 59_999 }), false)
  assert.equal(reloads, 1)
  assert.equal(values.get('admin-token'), 'existing-session')
  assert.equal(values.size, 2)
  assert.equal(recoverAssetLoad({ ...environment, now: environment.now + 60_001 }), true)
})

test('offline or inaccessible storage leaves the error boundary available without a reload loop', () => {
  const blocked = { getItem() { throw new Error('blocked') }, setItem() { throw new Error('blocked') } }
  const environment = { storage: blocked, reload: () => assert.fail('must not reload'), now: 1_000_000, online: true }
  assert.equal(recoverAssetLoad(environment), false)
  assert.equal(recoverAssetLoad({ ...environment, online: false }), false)
})

test('Vite failed-preload event reloads the current URL once and then exposes the original error', (t) => {
  const originals = new Map(['window', 'navigator'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  const window = new EventTarget()
  const values = new Map()
  const href = 'https://example.test/admin/connections?network_id=office&view=topology#direction'
  let reloadedUrl
  window.location = { href, reload: () => { reloadedUrl = window.location.href } }
  window.sessionStorage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) }
  Object.defineProperty(globalThis, 'window', { configurable: true, value: window })
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { onLine: true } })
  t.after(() => {
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor)
      else Reflect.deleteProperty(globalThis, key)
    }
  })
  installAssetRecovery()
  const first = new Event('vite:preloadError', { cancelable: true })
  window.dispatchEvent(first)
  assert.equal(first.defaultPrevented, true)
  assert.equal(reloadedUrl, href)
  const repeated = new Event('vite:preloadError', { cancelable: true })
  window.dispatchEvent(repeated)
  assert.equal(repeated.defaultPrevented, false)
})
