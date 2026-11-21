'use strict'
const test = require('node:test'); const assert = require('node:assert/strict')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { fixture } = require('./fixture-input'); const { validate } = require('./bedrock-input')
const { Session } = require('./bedrock-session'); const { Transport } = require('./bedrock-transport')
const { startGame, item, update } = require('./fixture-server')
function setup (t, delayed = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bedrock-session-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const f = fixture(dir); const input = validate(f.envelope, f.configPath)
  const rows = []; const sent = []; const outputs = []; let now = 2000000000
  const session = new Session(input, row => rows.push(row), () => now)
  const client = { encryptionEnabled: true, status: 4, connection: { connected: true }, sendQ: [], sendIds: [],
    sendMCPE (buffer) { sent.push(buffer) }, onEncryptedPacket (buffer) { this.sendMCPE(buffer) },
    sendEncryptedBatch (buffer) {
      if (delayed) {
        outputs.push(buffer)
        if (delayed === 'flush-control-on-action' && buffer.name === 'inventory_transaction') this.onEncryptedPacket(outputs.shift())
      } else this.onEncryptedPacket(buffer)
    },
    write (name, packet) { this.sendEncryptedBatch({ name, packet }) }, queue () {}, close () { this.status = 0 } }
  client.connection.sendReliable = (buffer, immediate, owner) => {
    if (owner?.gameplay) assert.equal(session.beginSend(owner.action), true)
    sent.push(buffer)
    if (owner?.gameplay) assert.equal(session.completeSend(owner.action), true)
  }
  session.transport = new Transport(client, session)
  session.startGame(startGame('single'))
  session.observe('inventory_content', { window_id: 'inventory', input: [item()] })
  const action = input.actions[0]; const request = input.round.requests[0]
  session.observe('update_block', update(action.reference, action.reference_state_id))
  session.observe('update_block', update(action.target, action.before_state_id))
  t.after(() => session.close())
  return { session, input, rows, sent, outputs, client, action, request, time: value => { now = value },
    flush: () => { while (outputs.length) client.onEncryptedPacket(outputs.shift()) } }
}
test('only original sent action and exact raw layer-zero target transition confirms once', async t => {
  const f = setup(t); const pending = f.session.perform(f.request, f.action)
  assert.equal(f.sent.filter(row => row.name === 'inventory_transaction').length, 1)
  f.session.observe('update_block', update({ ...f.action.target, x: 9 }, f.action.after_state_id))
  f.session.observe('update_block', update(f.action.target, f.action.after_state_id, 1))
  assert.equal(f.rows.filter(row => row.event.kind === 'action_confirmed').length, 0)
  f.session.observe('update_block', update(f.action.target, f.action.after_state_id))
  f.session.observe('update_block', update(f.action.target, f.action.after_state_id))
  await pending
  const confirmations = f.rows.filter(row => row.event.kind === 'action_confirmed')
  assert.equal(confirmations.length, 1); assert.equal(confirmations[0].event.wire_request_id, null)
})
test('wrong server state is an action failure, never success', async t => {
  const f = setup(t); const pending = f.session.perform(f.request, f.action)
  f.session.observe('update_block', update(f.action.target, f.action.before_state_id))
  await pending; assert.equal(f.rows.at(-1).event.reason, 'action_rejected')
})
test('delayed encryption output after deadline cannot transmit original gameplay', async t => {
  const f = setup(t, true); const pending = f.session.perform(f.request, f.action)
  f.time(2600000000); f.flush(); await pending
  assert.equal(f.session.closed, true)
  assert.equal(f.sent.filter(row => row.name === 'inventory_transaction').length, 0)
  assert.equal(f.rows.some(row => row.event.kind === 'action_confirmed'), false)
})
test('cancellation fences every delayed encryption output and later callback', async t => {
  const f = setup(t, true); const pending = f.session.perform(f.request, f.action)
  f.session.close('interrupted'); f.flush(); await pending
  assert.equal(f.sent.length, 0); assert.equal(f.rows.at(-1).event.kind, 'action_cancelled')
})
test('before state changed before delayed handoff fails ownership recheck', async t => {
  const f = setup(t, true); const pending = f.session.perform(f.request, f.action)
  f.session.observe('update_block', update(f.action.target, f.action.after_state_id))
  f.flush(); await pending
  assert.equal(f.session.closed, true)
  assert.equal(f.sent.filter(row => row.name === 'inventory_transaction').length, 0)
})
test('stale target observation before transmit cannot earn success', async t => {
  const f = setup(t, true); const pending = f.session.perform(f.request, f.action)
  f.session.observe('update_block', update({ ...f.action.target, x: 9 }, f.action.after_state_id))
  f.flush()
  assert.equal(f.rows.filter(row => row.event.kind === 'action_confirmed').length, 0)
  f.session.close('disconnected'); await pending
  assert.equal(f.rows.at(-1).event.kind, 'session_closed')
})
test('unknown cipher output and queue overflow fail closed', t => {
  const first = setup(t, true); first.client.onEncryptedPacket(Buffer.alloc(0)); assert.equal(first.session.closed, true)
  const second = setup(t, true); second.client.sendQ = Array(128).fill(Buffer.alloc(0))
  second.client.queue('tick_sync', {}); assert.equal(second.session.closed, true)
})
test('missing raw prerequisites and unsupported server profile cannot send', async t => {
  const f = setup(t); f.session.blocks.clear()
  await f.session.perform(f.request, f.action)
  assert.equal(f.sent.length, 0); assert.equal(f.rows.at(-1).event.reason, 'action_failed')
  assert.throws(() => { f.session.game = false; f.session.startGame(startGame('unsupported-profile')) }, /profile/)
})

test('control cipher output flushed during a new action write keeps its original non-action owner', async t => {
  const f = setup(t, 'flush-control-on-action'); const pending = f.session.perform(f.request, f.action)
  assert.equal(f.sent.length, 1); assert.equal(f.sent[0].name, 'mob_equipment')
  assert.equal(f.session.active.sent, false)
  f.flush(); assert.equal(f.sent[1].name, 'inventory_transaction')
  f.session.observe('update_block', update(f.action.target, f.action.after_state_id)); await pending
  assert.equal(f.rows.at(-1).event.kind, 'action_confirmed')
})

test('full original held-item snapshot fences delayed count, metadata, stack and nested extra changes', async t => {
  for (const mutate of [item => { item.count = 1 }, item => { item.metadata = 1 },
    item => { item.has_stack_id = 1; item.stack_id = 8 }, item => { item.extra.nbt = { type: 'compound', value: { changed: true } } },
    item => { item.extra.can_place_on = ['minecraft:stone'] }, item => { item.network_id++ }]) {
    const f = setup(t, true); const pending = f.session.perform(f.request, f.action)
    const changed = structuredClone(f.session.inventory.get(f.action.hotbar_slot)); mutate(changed)
    f.session.observe('inventory_slot', { window_id: 'inventory', slot: f.action.hotbar_slot, item: changed })
    f.flush(); await pending
    assert.equal(f.session.closed, true)
    assert.equal(f.sent.length, 0)
    assert.equal(f.rows.some(row => row.event.kind === 'action_confirmed'), false)
  }
})

test('native send completion alone enables confirmation; cancelled or late completions cannot', async t => {
  for (const mode of ['complete', 'cancel', 'late', 'error']) {
    const f = setup(t); let original
    f.client.connection.sendReliable = (buffer, immediate, owner) => {
      if (owner?.gameplay) { original = owner.action; assert.equal(f.session.beginSend(original), true) }
      f.sent.push(buffer)
    }
    const pending = f.session.perform(f.request, f.action)
    assert.equal(f.session.active.sent, false)
    // A raw update while native completion is pending can never be credited.
    f.session.observe('update_block', update(f.action.target, f.action.before_state_id))
    assert.equal(f.rows.some(row => row.event.kind === 'action_confirmed'), false)
    if (mode === 'cancel') f.session.close('interrupted')
    else if (mode === 'late') f.time(2600000000)
    else if (mode === 'error') f.session.close('adapter_error')
    const completed = f.session.completeSend(original)
    assert.equal(completed, mode === 'complete')
    if (mode !== 'complete') f.session.close('adapter_error')
    f.session.observe('update_block', update(f.action.target, f.action.after_state_id))
    await pending
    assert.equal(f.rows.some(row => row.event.kind === 'action_confirmed'), mode === 'complete')
  }
})
