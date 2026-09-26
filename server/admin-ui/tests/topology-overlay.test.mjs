import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { getNodesBounds, getViewportForBounds } from '@xyflow/react'

const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(new URL('../package.json', import.meta.url))

async function compileSource(entry, plugins = []) {
  const result = await build({
    absWorkingDir: projectRoot,
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    write: false,
    loader: { '.css': 'empty' },
    plugins,
  })
  const module = { exports: {} }
  new Function('module', 'exports', 'require', result.outputFiles[0].text)(module, module.exports, require)
  return module.exports
}

// Export private pure functions only in the test build, preserving the public
// component API and testing the implementation used by the actual application.
const graph = await compileSource('src/TopologyCanvas.tsx', [{
  name: 'test-layout-functions',
  setup(builder) {
    builder.onLoad({ filter: /TopologyCanvas\.tsx$/ }, ({ path: filename }) => ({
      contents: `${readFileSync(filename, 'utf8')}\nexport { buildGraph, filterTopology };`,
      loader: 'tsx',
      resolveDir: path.dirname(filename),
    }))
  },
}])

function topologyFixture() {
  return {
    nodes: [
      { id: 'account:a', kind: 'account', label: 'Alice', account_id: 'a' },
      { id: 'network:n', kind: 'network', label: 'Network', network_id: 'n' },
      ...Array.from({ length: 12 }, (_, index) => ({
        id: `device:${index}`,
        kind: 'device',
        label: `Laptop-${index}`,
        account_id: 'a',
        online: index !== 11,
      })),
    ],
    edges: [
      { id: 'member:a:n', kind: 'membership', source: 'account:a', target: 'network:n' },
      ...Array.from({ length: 12 }, (_, index) => ({
        id: `attach:${index}`,
        kind: 'attachment',
        source: 'network:n',
        target: `device:${index}`,
      })),
    ],
  }
}

test('desktop layout converts center coordinates once and keeps nodes apart', () => {
  const { nodes } = graph.buildGraph(topologyFixture())
  assert.equal(Math.min(...nodes.map((node) => node.position.x)), 36)
  assert.ok(Math.min(...nodes.map((node) => node.position.y)) >= 34)
  for (const [index, left] of nodes.entries()) {
    for (const right of nodes.slice(index + 1)) {
      const separated = left.position.x + left.width <= right.position.x
        || right.position.x + right.width <= left.position.x
        || left.position.y + left.height <= right.position.y
        || right.position.y + right.height <= left.position.y
      assert.ok(separated, `${left.id} overlaps ${right.id}`)
    }
  }
})

test('mobile search relays out only matches and their direct context', () => {
  const filtered = graph.filterTopology(topologyFixture(), { showOffline: true, showSignals: false }, 'Laptop-10')
  const { nodes } = graph.buildGraph(filtered, true)
  assert.deepEqual(new Set(nodes.map((node) => node.id)), new Set(['device:10', 'network:n']))
  assert.equal(Math.min(...nodes.map((node) => node.position.y)), 36)
  assert.ok(Math.max(...nodes.map((node) => node.position.y + node.height)) < 240)
  assert.ok(nodes.every((node) => node.targetPosition === 'right'))
})

test('hidden offline devices cannot reappear through a search context', () => {
  const filtered = graph.filterTopology(topologyFixture(), { showOffline: false, showSignals: false }, 'Laptop-11')
  assert.equal(filtered.nodes.length, 0)
  assert.equal(filtered.edges.length, 0)
})

test('mobile fullscreen fits tall graphs below the former minimum zoom', () => {
  const { nodes } = graph.buildGraph(topologyFixture(), true)
  const bounds = getNodesBounds(nodes)
  const viewport = getViewportForBounds(bounds, 370, 824, 0.08, 0.92, 0.1)
  assert.ok(viewport.zoom < 0.68)
  assert.ok(bounds.height * viewport.zoom < 824)
  assert.ok(bounds.width * viewport.zoom < 370)
})

test('telemetry-only node changes preserve layout geometry', () => {
  const fixture = topologyFixture()
  const before = graph.buildGraph(fixture)
  const after = graph.buildGraph({
    ...fixture,
    nodes: fixture.nodes.map((node) => ({ ...node, online: true, relay_rtt_ms: 84 })),
  })
  const positions = (layout) => layout.nodes.map(({ id, position, width, height }) => ({ id, position, width, height }))
  assert.deepEqual(positions(before), positions(after))
})

async function withOverlayHarness(run) {
  const globalKeys = ['window', 'document', '__p2wlanOverlayTestEffects']
  const previous = new Map(globalKeys.map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  const styles = new Map([['overflow', ['scroll', 'important']]])
  const listeners = new Map()
  const effects = []
  try {
    globalThis.__p2wlanOverlayTestEffects = effects
    globalThis.document = { body: { style: {
      getPropertyValue: (key) => styles.get(key)?.[0] ?? '',
      getPropertyPriority: (key) => styles.get(key)?.[1] ?? '',
      setProperty: (key, value, priority = '') => styles.set(key, [value, priority]),
      removeProperty: (key) => styles.delete(key),
    } } }
    globalThis.window = {
      addEventListener: (key, listener) => listeners.set(key, listener),
      removeEventListener: (key, listener) => {
        if (listeners.get(key) === listener) listeners.delete(key)
      },
    }
    // The shim executes registration and cleanup without a DOM. It validates
    // stack ownership, not React scheduling, focus management or browser input.
    // Fullscreen centering and dialog focus still require browser verification.
    const { useOverlay } = await compileSource('src/useOverlay.ts', [{
      name: 'hook-effect-lifecycle',
      setup(builder) {
        builder.onResolve({ filter: /^react$/ }, () => ({ path: 'react', namespace: 'test-hooks' }))
        builder.onLoad({ filter: /.*/, namespace: 'test-hooks' }, () => ({
          contents: 'export const useRef = current => ({current}); export const useEffect = fn => globalThis.__p2wlanOverlayTestEffects.push(fn());',
        }))
      },
    }])
    const escape = (overrides = {}) => listeners.get('keydown')?.({
      key: 'Escape',
      preventDefault() {},
      stopImmediatePropagation() {},
      ...overrides,
    })
    await run({ useOverlay, styles, listeners, effects, escape })
  } finally {
    for (const cleanup of effects.reverse()) cleanup?.()
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor)
      else delete globalThis[key]
    }
  }
}

test('Escape closes the top layer and preserves the outer scroll lock', async () => {
  await withOverlayHarness(({ useOverlay, styles, listeners, effects, escape }) => {
    let fullscreenClosed = 0
    let drawerClosed = 0
    useOverlay(true, () => fullscreenClosed++)
    useOverlay(true, () => drawerClosed++)
    assert.equal(styles.get('overflow')[0], 'hidden')
    escape({ repeat: true })
    escape({ isComposing: true })
    assert.equal(drawerClosed, 0)
    escape()
    assert.equal(fullscreenClosed, 0)
    assert.equal(drawerClosed, 1)
    effects.pop()()
    assert.equal(styles.get('overflow')[0], 'hidden')
    effects.pop()()
    assert.deepEqual(styles.get('overflow'), ['scroll', 'important'])
    assert.equal(listeners.size, 0)
  })
})

test('out-of-order cleanup restores overflow only after every lock is released', async () => {
  await withOverlayHarness(({ useOverlay, styles, listeners, effects }) => {
    useOverlay(true, () => {})
    useOverlay(true, () => {})
    const [outerCleanup, innerCleanup] = effects.splice(0)
    outerCleanup()
    assert.equal(styles.get('overflow')[0], 'hidden')
    innerCleanup()
    assert.deepEqual(styles.get('overflow'), ['scroll', 'important'])
    assert.equal(listeners.size, 0)
  })
})

test('nonmodal panels participate in Escape without locking page scrolling', async () => {
  await withOverlayHarness(({ useOverlay, styles, listeners, effects, escape }) => {
    let closed = 0
    useOverlay(true, () => closed++, { lockScroll: false })
    assert.deepEqual(styles.get('overflow'), ['scroll', 'important'])
    escape()
    assert.equal(closed, 1)
    effects.pop()()
    assert.equal(listeners.size, 0)
    useOverlay(false, () => assert.fail('inactive overlays must not close'))
    assert.equal(listeners.size, 0)
  })
})
