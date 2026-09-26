import assert from 'node:assert/strict'
import { test } from 'node:test'
import { adminApi, setAdminToken } from '../src/api.ts'

function setup(t, fetch) {
  const originals = new Map(['sessionStorage', 'fetch'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  const values = new Map()
  Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  } })
  globalThis.fetch = fetch
  setAdminToken('test-account-scope-token')
  t.after(() => {
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor)
      else Reflect.deleteProperty(globalThis, key)
    }
  })
}

test('the first account page uses the cursor endpoint without an offset or empty cursor', async (t) => {
  const page = { total: 76, limit: 25, next_cursor: 'user-025', items: [{ id: 'user-001', username: 'first' }] }
  setup(t, async (path) => {
    assert.equal(path, '/admin/api/v1/accounts/cursor?q=&limit=25')
    return Response.json(page)
  })
  assert.deepEqual(await adminApi.accountsCursor(), page)
})

test('account search and opaque cursors survive URL encoding without changing the requested page size', async (t) => {
  const search = '张 工+&%@example.test'
  const cursor = 'user:/?+&=#尾页'
  const page = { total: 1, limit: 25, items: [{ id: 'user-076', username: search }] }
  setup(t, async (path) => {
    const url = new URL(path, 'https://control.example.test')
    assert.equal(url.pathname, '/admin/api/v1/accounts/cursor')
    assert.equal(url.searchParams.get('q'), search)
    assert.equal(url.searchParams.get('cursor'), cursor)
    assert.equal(url.searchParams.get('limit'), '25')
    assert.equal(url.searchParams.has('offset'), false)
    return Response.json(page)
  })
  const result = await adminApi.accountsCursor(search, cursor, 25)
  assert.deepEqual(result, page)
  assert.equal(result.next_cursor, undefined)
})

test('changing the account search can cancel its outstanding request', async (t) => {
  const controller = new AbortController()
  let started = false
  setup(t, (_path, options) => {
    assert.equal(options.signal, controller.signal)
    started = true
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new DOMException('Cancelled', 'AbortError')), { once: true })
    })
  })
  const pending = adminApi.accountsCursor('previous search', 'user-050', 25, controller.signal)
  assert.equal(started, true)
  controller.abort()
  await assert.rejects(pending, { name: 'AbortError' })
})

test('an already cancelled account search never starts a request', async (t) => {
  setup(t, () => assert.fail('a cancelled search must not fetch'))
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(adminApi.accountsCursor('old search', '', 25, controller.signal), { name: 'AbortError' })
})
