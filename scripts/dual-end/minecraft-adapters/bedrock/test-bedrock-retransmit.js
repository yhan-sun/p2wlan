'use strict'
const nodeTest = require('node:test'); const assert = require('node:assert/strict')
const test = (name, fn) => nodeTest(name, { timeout: 2000 }, fn)
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path'); const vm = require('node:vm')
const { EventEmitter } = require('node:events')
const { fixture } = require('./fixture-input'); const { validate } = require('./bedrock-input')
const { Session } = require('./bedrock-session'); const { startGame, item, update } = require('./fixture-server')
const { EncapsulatedPacket, Reliability } = require('jsp-raknet')

// Execute the unchanged production sendBuffer wrapper with a socket that only
// saves fixed buffers/callbacks. No UDP binding, connection or wire NACK occurs.
class FixedSocket extends EventEmitter {
  constructor () { super(); this.sends = [] }
  connect () { this.emit('connect') }
  send (buffer, callback) { this.sends.push({ buffer, finish: (error = null, bytes = buffer.length) => callback(error, bytes) }) }
}
class FixedRaknet extends EventEmitter {
  constructor () {
    super(); this.running = true; this.socket = new FixedSocket()
    this.connection = { state: 1, mtuSize: 1492, update () {}, sendConnectedPing () {},
      addEncapsulatedToQueue: packet => { this.connection.beforeSend?.(); this.sendBuffer(packet.buffer) } }
  }
  handle () {}
  sendConnectionRequest () { this.sendBuffer(Buffer.from('fixed-handshake')) }
  close () { this.running = false; this.socket.closed = true; clearInterval(this.int) }
}
function setup (t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bedrock-retransmit-unit-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const f = fixture(directory, 19132, 2); const input = validate(f.envelope, f.configPath)
  const events = []; let now = 2000000000; let completions = 0
  const session = new Session(input, row => events.push(row.event), () => now)
  const complete = session.completeSend.bind(session)
  session.completeSend = action => { completions++; return complete(action) }
  session.startGame(startGame('single'))
  session.observe('inventory_content', { window_id: 'inventory', input: [item()] })
  for (const action of input.actions) {
    session.observe('update_block', update(action.reference, action.reference_state_id))
    session.observe('update_block', update(action.target, action.before_state_id))
  }
  const sandbox = { module: { exports: {} }, setInterval, clearInterval, Buffer,
    require: name => name === 'jsp-raknet' ? { Client: FixedRaknet, EncapsulatedPacket, Reliability } : require(name) }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'bedrock-raknet.js'), 'utf8'), sandbox, { filename: 'bedrock-raknet.js' })
  const transport = { onConnected () {}, onEncapsulated () {}, onCloseConnection () {} }
  const client = { options: { host: '127.0.0.1', port: 19132 }, connection: transport }
  sandbox.module.exports.singleHandshake(client, session)
  session.transport = { write () {}, close: () => transport.close() }
  transport.connect()
  const raknet = transport.raknet; const socket = raknet.socket
  socket.sends.shift().finish() // finish the ownerless fixed startup datagram
  t.after(() => { session.close(); assert.equal(socket.closed, true); assert.equal(raknet.running, false) })
  const begin = index => {
    const pending = session.perform(input.round.requests[index], input.actions[index])
    const owner = Object.freeze({ action: session.active, gameplay: true })
    return { pending, owner }
  }
  return { session, events, input, transport, raknet, socket, begin,
    time: value => { now = value }, completions: () => completions,
    send: (buffer, owner) => transport.sendReliable(buffer, true, owner),
    confirm: index => session.observe('update_block', update(input.actions[index].target, input.actions[index].after_state_id)) }
}

test('same original datagram retransmits while current and completes once in either callback order', async t => {
  for (const order of [[0, 1], [1, 0]]) {
    const f = setup(t); const action = f.begin(0); const buffer = Buffer.from('original-action')
    f.send(buffer, action.owner); f.raknet.sendBuffer(buffer)
    assert.equal(f.socket.sends.length, 2); assert.equal(f.session.active.sent, false)
    f.socket.sends[order[0]].finish(); assert.equal(f.session.active.sent, true)
    f.confirm(0); await action.pending
    f.socket.sends[order[1]].finish()
    assert.equal(f.completions(), 1); assert.equal(f.session.closed, false)
    assert.equal(f.events.filter(row => row.kind === 'action_confirmed').length, 1)
  }
})
test('original held item changed before saved-buffer retransmission closes without another send', async t => {
  const f = setup(t); const action = f.begin(0); const buffer = Buffer.from('original-action')
  f.send(buffer, action.owner); f.socket.sends[0].finish()
  f.session.observe('inventory_slot', { window_id: 'inventory', slot: 0, item: { ...item(), count: 1 } })
  f.raknet.sendBuffer(buffer)
  const sends = f.socket.sends.length; const closed = f.session.closed
  f.session.close(); await action.pending
  assert.equal(sends, 1); assert.equal(closed, true)
  assert.equal(f.events.some(row => row.kind === 'action_confirmed'), false)
})
test('original deadline and cancellation fence saved-buffer retransmission and late completion', async t => {
  for (const mode of ['deadline', 'cancel']) {
    const f = setup(t); const action = f.begin(0); const buffer = Buffer.from('original-action')
    f.send(buffer, action.owner)
    if (mode === 'deadline') f.time(action.owner.action.deadline)
    else f.session.close('interrupted')
    f.raknet.sendBuffer(buffer); f.socket.sends[0].finish(); await action.pending
    assert.equal(f.socket.sends.length, 1); assert.equal(f.session.closed, true); assert.equal(f.completions(), 0)
    assert.equal(f.events.some(row => row.kind === 'action_confirmed'), false)
  }
})
test('a settled original datagram cannot inherit another action temporary origin', async t => {
  const f = setup(t); const first = f.begin(0); const old = Buffer.from('first-action')
  f.send(old, first.owner); f.socket.sends[0].finish(); f.confirm(0); await first.pending
  f.time(2800000000); const second = f.begin(1)
  f.raknet.connection.beforeSend = () => f.raknet.sendBuffer(old)
  f.send(Buffer.from('second-action'), second.owner)
  const sends = f.socket.sends.length; const closed = f.session.closed
  f.session.close(); await second.pending
  assert.equal(sends, 1); assert.equal(closed, true); assert.equal(f.completions(), 1)
  assert.equal(f.events.filter(row => row.kind === 'action_confirmed').length, 1)
})
test('previous control buffer keeps its owner during gameplay write and cannot consume or grant gameplay completion', async t => {
  const f = setup(t); const control = Buffer.from('original-control')
  f.send(control, null); f.socket.sends[0].finish()
  const action = f.begin(0)
  f.raknet.connection.beforeSend = () => f.raknet.sendBuffer(control)
  f.send(Buffer.from('original-action'), action.owner)
  assert.equal(f.socket.sends.length, 3)
  f.socket.sends[1].finish(); assert.equal(f.session.active.sent, false); assert.equal(f.completions(), 0)
  f.socket.sends[2].finish(); f.confirm(0); await action.pending
  assert.equal(f.completions(), 1); assert.equal(f.session.closed, false)
})
test('native errors and short completions fail closed before or after another original-datagram success', async t => {
  for (const order of [[0, 1], [1, 0]]) for (const firstSucceeds of [false, true]) for (const failure of ['error', 'short']) {
    const f = setup(t); const action = f.begin(0); const buffer = Buffer.from('original-action')
    f.send(buffer, action.owner); f.raknet.sendBuffer(buffer)
    const success = index => f.socket.sends[index].finish()
    const fail = index => f.socket.sends[index].finish(failure === 'error' ? new Error('fixed native failure') : null, 0)
    if (firstSucceeds) { success(order[0]); fail(order[1]) } else { fail(order[0]); success(order[1]) }
    await action.pending
    assert.equal(f.session.closed, true); assert.equal(f.completions(), firstSucceeds ? 1 : 0)
    assert.equal(f.events.some(row => row.kind === 'action_confirmed'), false)
  }
})
test('raw update before all held native completions cannot be revived by a retransmission callback', async t => {
  const f = setup(t); const action = f.begin(0); const buffer = Buffer.from('original-action')
  f.send(buffer, action.owner); f.raknet.sendBuffer(buffer)
  f.confirm(0); assert.equal(f.events.some(row => row.kind === 'action_confirmed'), false)
  f.socket.sends[1].finish(); f.socket.sends[0].finish(); await action.pending
  assert.equal(f.session.closed, true); assert.equal(f.events.some(row => row.kind === 'action_confirmed'), false)
})
test('saved buffer mutation is rejected at retransmission and native completion', async t => {
  for (const mode of ['resend', 'completion']) {
    const f = setup(t); const action = f.begin(0); const buffer = Buffer.from('original-action')
    f.send(buffer, action.owner); buffer[0] ^= 1
    if (mode === 'resend') f.raknet.sendBuffer(buffer)
    f.socket.sends[0].finish(); await action.pending
    assert.equal(f.socket.sends.length, 1); assert.equal(f.session.closed, true); assert.equal(f.completions(), 0)
  }
})
test('two distinct gameplay datagrams in one temporary origin cannot grant partial completion', async t => {
  const f = setup(t); const action = f.begin(0)
  f.raknet.connection.beforeSend = () => f.raknet.sendBuffer(Buffer.from('unexpected-first-part'))
  f.send(Buffer.from('unexpected-second-part'), action.owner)
  assert.equal(f.socket.sends.length, 1); f.socket.sends[0].finish(); await action.pending
  assert.equal(f.session.closed, true); assert.equal(f.completions(), 0)
})
test('pending native callback bound remains 128 and closes the owned fixed socket', t => {
  const f = setup(t)
  for (let i = 0; i < 129; i++) f.raknet.sendBuffer(Buffer.from('control-' + i))
  assert.equal(f.socket.sends.length, 128); assert.equal(f.session.closed, true)
  for (const pending of f.socket.sends) pending.finish()
  assert.equal(f.completions(), 0)
})
