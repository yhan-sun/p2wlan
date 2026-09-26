import assert from 'node:assert/strict'
import { test } from 'node:test'
import { adminApi, api, clearAdminToken, getAdminToken, setAdminToken } from '../src/api.ts'

function setup(t) {
  const originals = new Map(['window', 'sessionStorage', 'fetch'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  const values = new Map()
  const events = new EventTarget()
  let unauthorized = 0
  events.addEventListener('p2wlan:unauthorized', () => { unauthorized += 1 })
  Object.defineProperty(globalThis, 'window', { configurable: true, value: events })
  Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  } })
  t.after(() => {
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor)
      else Reflect.deleteProperty(globalThis, key)
    }
  })
  return { unauthorized: () => unauthorized }
}

test('a 401 from an older session cannot sign out a newer session', async (t) => {
  const state = setup(t)
  const request = Promise.withResolvers()
  globalThis.fetch = () => request.promise
  setAdminToken('old-token')
  const pending = api('/runtime')
  clearAdminToken()
  setAdminToken('new-token')
  request.resolve(new Response(JSON.stringify({ error: 'rejected' }), { status: 401 }))
  await assert.rejects(pending, { name: 'AbortError' })
  assert.equal(getAdminToken(), 'new-token')
  assert.equal(state.unauthorized(), 0)
})

test('a repeated login using the same token still fences old requests', async (t) => {
  const state = setup(t)
  const request = Promise.withResolvers()
  globalThis.fetch = () => request.promise
  setAdminToken('same-token')
  const pending = api('/runtime')
  clearAdminToken()
  setAdminToken('same-token')
  request.resolve(new Response('{}', { status: 401 }))
  await assert.rejects(pending, { name: 'AbortError' })
  assert.equal(getAdminToken(), 'same-token')
  assert.equal(state.unauthorized(), 0)
})

test('session identity is rechecked after asynchronously parsing a 401 body', async (t) => {
  const state = setup(t)
  const body = Promise.withResolvers()
  const parsing = Promise.withResolvers()
  globalThis.fetch = async () => ({ ok: false, status: 401, json: () => { parsing.resolve(); return body.promise } })
  setAdminToken('old-token')
  const pending = api('/runtime')
  await parsing.promise
  setAdminToken('new-token')
  body.resolve({ error: 'rejected' })
  await assert.rejects(pending, { name: 'AbortError' })
  assert.equal(getAdminToken(), 'new-token')
  assert.equal(state.unauthorized(), 0)
})

test('a successful payload from an older session is not returned after body parsing', async (t) => {
  setup(t)
  const body = Promise.withResolvers()
  const parsing = Promise.withResolvers()
  globalThis.fetch = async () => ({ ok: true, status: 200, json: () => { parsing.resolve(); return body.promise } })
  setAdminToken('old-token')
  const pending = api('/runtime')
  await parsing.promise
  setAdminToken('new-token')
  body.resolve({ private: 'old-session-data' })
  await assert.rejects(pending, { name: 'AbortError' })
})

test('a 401 from the active session clears its token and emits unauthorized once', async (t) => {
  const state = setup(t)
  globalThis.fetch = async () => new Response(JSON.stringify({ error: 'rejected' }), { status: 401 })
  setAdminToken('active-token')
  await assert.rejects(api('/runtime'), { status: 401, message: 'rejected' })
  assert.equal(getAdminToken(), '')
  assert.equal(state.unauthorized(), 1)
})

test('a cancelled request cannot clear the active session', async (t) => {
  const state = setup(t)
  const request = Promise.withResolvers()
  globalThis.fetch = () => request.promise
  setAdminToken('active-token')
  const controller = new AbortController()
  const pending = api('/runtime', controller.signal)
  controller.abort()
  request.resolve(new Response('{}', { status: 401 }))
  await assert.rejects(pending, { name: 'AbortError' })
  assert.equal(getAdminToken(), 'active-token')
  assert.equal(state.unauthorized(), 0)
})

test('cursor, connection, history, and network queries forward cancellation signals', async (t) => {
  setup(t)
  const controller = new AbortController()
  const requests = []
  globalThis.fetch = async (path, options) => {
    requests.push({ path, options })
    return new Response(JSON.stringify({ items: [] }))
  }
  setAdminToken('active-token')
  await adminApi.accountsCursor('alice', 'next', 25, controller.signal)
  await adminApi.connections({ networkId: 'network' }, 1, 0, controller.signal)
  await adminApi.connectionTransitions('from', 'to', 'network', 50, '', controller.signal)
  await adminApi.networks(100, 0, controller.signal)
  assert.equal(requests.length, 4)
  for (const { options } of requests) assert.equal(options.signal, controller.signal)
  assert.match(requests[0].path, /q=alice.*cursor=next/)
  assert.match(requests[2].path, /limit=50/)
})
