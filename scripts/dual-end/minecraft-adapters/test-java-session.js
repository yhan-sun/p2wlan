'use strict'
const test = require('node:test')
const assert = require('node:assert/strict')
const { EventEmitter } = require('node:events')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { Vec3 } = require('vec3')
const { fixture } = require('./fixture-input')
const { validate } = require('./java-input')
const { Session, changes } = require('./java-session')

function setup (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mc-session-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const f = fixture(dir); const input = validate(f.envelope, f.configPath)
  input.round.requests[0].planned_offset_ns = 0
  const events = []; let now = 0
  const session = new Session(input, value => events.push(value), () => now)
  const action = input.actions[0]; const request = input.round.requests[0]
  const client = new EventEmitter(); client.write = () => {}
  const bot = { _client: client, inventory: { slots: Array(46) }, entity: { position: new Vec3(1, 65, 2) },
    blockAt: p => ({ stateId: p.y === 64 ? 1 : 0, position: p }), setQuickBarSlot () {}, end () {} }
  bot.inventory.slots[36] = { name: 'stone', count: 64 }
  const packet = { location: action.reference, direction: 1, hand: 0 }
  bot._genericPlace = async () => client.write('block_place', packet)
  session.attach(bot); t.after(() => session.dispose())
  return { session, input, events, action, request, bot, packet, setNow: n => { now = n },
    ack: () => session.observe('block_change', { location: action.reference, type: 1 }),
    confirm: state => session.observe('block_change', { location: action.target, type: state ?? 1 }) }
}
test('only post-write reference then exact target packet confirms once', async t => {
  const s = setup(t); s.confirm(); const done = s.session.perform(s.request, s.action)
  s.confirm(); assert.equal(s.events.length, 1)
  s.ack(); s.session.observe('block_change', { location: { x: 9, y: 65, z: 1 }, type: 1 })
  assert.equal(s.events.length, 1)
  s.setNow(10); s.confirm(); s.confirm(); await done
  assert.equal(s.events.length, 2); assert.equal(s.events[1].event.kind, 'action_confirmed')
  assert.equal(s.events[1].event.wire_request_id, null); assert.equal(s.events[1].event.offset_ns, 10)
})
test('placement promise and optimistic local world update cannot confirm', async t => {
  const s = setup(t); const done = s.session.perform(s.request, s.action)
  s.bot._client.emit('local_block_update', { location: s.action.target, type: 1 })
  await Promise.resolve(); assert.equal(s.events.length, 1)
  s.session.close('interrupted'); await done
  assert.equal(s.events.at(-1).event.kind, 'action_cancelled')
})
test('wrong final state/disconnect are terminal and late reply cannot resurrect', async t => {
  for (const failure of ['state', 'disconnect']) {
    const s = setup(t); const done = s.session.perform(s.request, s.action)
    if (failure === 'state') { s.ack(); s.confirm(0) } else s.session.close('disconnected')
    s.ack(); s.confirm(); await done
    assert.equal(s.events.filter(x => x.event.kind === 'action_confirmed').length, 0)
    assert.equal(s.events.at(-1).event.kind, failure === 'state' ? 'action_failed' : 'session_closed')
  }
})
test('original deadline fences asynchronous late placement and confirmation', async t => {
  const s = setup(t); let send
  s.bot._genericPlace = () => new Promise(resolve => { send = () => { assert.throws(() => s.bot._client.write('block_place', s.packet), /ownership/); resolve() } })
  const done = s.session.perform(s.request, s.action)
  s.setNow(s.request.timeout_ns); send(); s.ack(); s.confirm()
  assert.equal(s.events.length, 1)
  s.session.close('interrupted'); await done
  assert.equal(s.events.filter(x => x.event.kind === 'action_confirmed').length, 0)
})
test('actual timer expiry preserves same clock deadline and single flight', async t => {
  const s = setup(t); s.request.timeout_ns = 1000000
  const start = process.hrtime.bigint(); s.session.now = () => Number(process.hrtime.bigint() - start)
  const done = s.session.perform(s.request, s.action)
  await assert.rejects(s.session.perform(s.request, s.action), /schedule/)
  await done; s.confirm()
  assert.equal(s.events.length, 1); assert.equal(s.session.active, null)
})
test('multi block codec coordinates preserve negative sections and reject oversized updates', () => {
  assert.deepEqual(changes('multi_block_change', { chunkCoordinates: { x: -1, y: -1, z: 0 }, records: [(1 << 12) | (15 << 8) | 15] }),
    [{ position: { x: -1, y: -1, z: 0 }, state: 1 }])
  assert.throws(() => changes('multi_block_change', { records: Array(4097) }))
})

test('one server update batch confirms regardless of reference record order', async t => {
  for (const targetFirst of [true, false]) {
    const s = setup(t); const done = s.session.perform(s.request, s.action)
    const reference = (1 << 12) | (1 << 8) | (1 << 4)
    const target = reference | 1
    s.session.observe('multi_block_change', { chunkCoordinates: { x: 0, y: 4, z: 0 },
      records: targetFirst ? [target, reference] : [reference, target] })
    assert.equal(s.events.at(-1).event.kind, 'action_confirmed')
    await done
    assert.equal(s.events.filter(x => x.event.kind === 'action_confirmed').length, 1)
  }
})
test('conflicting target states in one server batch cannot confirm', async t => {
  const s = setup(t); const done = s.session.perform(s.request, s.action)
  const reference = (1 << 12) | (1 << 8) | (1 << 4)
  s.session.observe('multi_block_change', { chunkCoordinates: { x: 0, y: 4, z: 0 },
    records: [reference, reference | 1, (1 << 8) | (1 << 4) | 1] })
  assert.equal(s.events.at(-1).event.kind, 'action_failed')
  await done
  assert.equal(s.events.filter(x => x.event.kind === 'action_confirmed').length, 0)
})
