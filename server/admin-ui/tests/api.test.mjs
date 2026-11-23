import assert from 'node:assert/strict'
import { test } from 'node:test'
import { adminApi, api, clearAdminToken, getAdminToken, openAdminSession, setAdminToken, supportsPasswordLogin, verifyAdminToken } from '../src/api.ts'

test('account login sends UTF-8 credentials only to the session endpoint and returns a separate bearer', async t => {
  setup(t)
  const signal = new AbortController().signal
  globalThis.fetch = async (url, init) => {
    assert.equal(init.signal, signal)
    assert.equal(init.cache, 'no-store')
    if (url.endsWith('/login-methods')) return Response.json({password: true})
    assert.equal(url, '/admin/api/v1/session')
    assert.equal(init.method, 'POST')
    assert.equal(init.redirect, 'error')
    assert.equal(Buffer.from(init.headers.Authorization.slice(6), 'base64').toString(), 'ops:  示例 password  ')
    return Response.json({access_token: 'scoped-session'})
  }
  assert.equal(await supportsPasswordLogin(signal), true)
  assert.equal(await openAdminSession('ops', '  示例 password  ', signal), 'scoped-session')
  assert.equal(getAdminToken(), '')
})

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

test('blocked session storage reads do not crash the login screen', (t) => {
  setup(t)
  setAdminToken('existing-token')
  Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, get: () => { throw new DOMException('Blocked', 'SecurityError') } })
  assert.equal(getAdminToken(), '')
})

test('a failed session write leaves login revoked and reports a usable error', (t) => {
  setup(t)
  clearAdminToken()
  sessionStorage.setItem = () => { throw new DOMException('Blocked', 'SecurityError') }
  assert.throws(() => setAdminToken('new-token'), /浏览器无法保存登录会话/)
  assert.equal(getAdminToken(), '')
})

test('revocation fences in-flight responses even when browser storage removal fails', async (t) => {
  setup(t)
  const response = Promise.withResolvers()
  globalThis.fetch = () => response.promise
  setAdminToken('old-token')
  const pending = api('/runtime')
  sessionStorage.removeItem = () => { throw new DOMException('Blocked', 'SecurityError') }
  clearAdminToken()
  assert.equal(getAdminToken(), '')
  response.resolve(new Response('{}'))
  await assert.rejects(pending, { name: 'AbortError' })
  setAdminToken('new-token')
  assert.equal(getAdminToken(), 'new-token')
})

test('login verification forwards cancellation without creating a session', async (t) => {
  setup(t)
  clearAdminToken()
  const controller = new AbortController()
  globalThis.fetch = async (_path, options) => {
    assert.equal(options.signal, controller.signal)
    throw new DOMException('Cancelled', 'AbortError')
  }
  await assert.rejects(verifyAdminToken('candidate-token', controller.signal), { name: 'AbortError' })
  assert.equal(getAdminToken(), '')
})


test('snapshot queries preserve scope, opaque cursors, and cancellation while legacy APIs remain separate', async (t) => {
  setup(t)
  setAdminToken('snapshot-session')
  const controller = new AbortController()
  const calls = []
  globalThis.fetch = async (url, init) => { calls.push([new URL(url, 'https://example.test'), init]); return new Response('{}') }
  await adminApi.accountsSnapshot('name & value', 'opaque+/=', 25, controller.signal)
  await adminApi.devicesSnapshot('laptop', 'online', 'device-cursor', 25, controller.signal, 'owner/a')
  await adminApi.networksSnapshot({ query: 'room & 1', accountId: 'owner/a' }, 'network-cursor', 25, controller.signal)
  await adminApi.roomsSnapshot({ query: 'room & 1', accountId: 'owner/a' }, 'room-cursor', 25, controller.signal)
  await adminApi.topologySnapshot('owner/a', 'full', 'topology-cursor', 100, controller.signal)
  assert.equal(calls[0][0].pathname, '/admin/api/v1/accounts')
  assert.equal(calls[0][0].searchParams.get('q'), 'name & value')
  assert.equal(calls[0][0].searchParams.get('cursor'), 'opaque+/=')
  for (const [url, init] of calls) assert.equal(init.signal, controller.signal)
  for (const [url] of calls.slice(0, 4)) assert.equal(url.searchParams.get('pagination'), 'cursor')
  for (const [url] of calls.slice(1, 4)) assert.equal(url.searchParams.get('account_id'), 'owner/a')
  assert.equal(calls[4][0].pathname, '/admin/api/v1/accounts/owner%2Fa/topology')
  assert.equal(calls[4][0].searchParams.get('view'), 'full')
})
