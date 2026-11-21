'use strict'
const test = require('node:test'); const assert = require('node:assert/strict')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { spawnSync } = require('node:child_process')
const { fixture } = require('./fixture-input'); const { validate } = require('./bedrock-input')
const { serverFixture, item, update } = require('./fixture-server')
const { Client } = require('bedrock-protocol'); const { run } = require('./bedrock-adapter')

async function execute (t, mode) {
  const remote = await serverFixture('single'); t.after(() => remote.close())
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bedrock-fence-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const positive = ['immediate-udp', 'control-interleave'].includes(mode)
  const f = fixture(directory, remote.port, positive ? 1 : 2)
  const rows = []; const held = []; const observations = { mode, scope: 'encrypted_loopback_codec_not_game_world', held_queue_calls: 0 }
  const controller = new AbortController()
  let output; let hold = false; let writing; let completion; let nativeActionSends = 0
  const originalInit = Client.prototype.init
  Client.prototype.init = function () {
    const client = this; output = this.onEncryptedPacket.bind(this)
    this.onEncryptedPacket = buffer => {
      if (!hold) return output(buffer)
      held.push(buffer)
      if (mode === 'control-interleave' && writing === 'network_stack_latency') {
        output(held.shift()) // original equipment output during a new control write
        observations.control_flushed_original_equipment = true
      }
    }
    const write = this.write.bind(this)
    this.write = (name, packet) => {
      writing = name
      try {
        const result = write(name, packet)
        if (name === 'inventory_transaction') {
          if (mode === 'pre-send-update') {
            remote.clients[0].write('update_block', update(f.actions[0].target, f.actions[0].after_state_id))
          } else if (mode === 'stale-item') {
            remote.clients[0].write('inventory_slot', { window_id: 'inventory', slot: 0, item: { ...item(), count: 1 } })
          } else if (mode === 'cipher-cancel') controller.abort()
          else if (mode === 'control-interleave') {
            remote.clients[0].write('network_stack_latency', { timestamp: 7n, needs_response: true })
          }
        }
        return result
      } finally { writing = null }
    }
    const flush = () => { hold = false; while (held.length) output(held.shift()) }
    this.on('update_block', packet => {
      if (packet.position.x !== f.actions[0].target.x || packet.position.y !== f.actions[0].target.y ||
          packet.position.z !== f.actions[0].target.z || packet.block_runtime_id !== f.actions[0].after_state_id) return
      if (mode === 'pre-send-update') flush()
      if (mode === 'completion-held') { observations.update_before_completion = true; completion?.() }
    })
    this.once('inventory_slot', packet => { observations.current_item_count = packet.item.count; if (mode === 'stale-item') flush() })
    this.on('network_stack_latency', packet => { if (!packet.needs_response) return; if (mode === 'control-interleave') flush() })
    this.once('spawn', () => {
      const connection = this.connection.raknet.connection
      if (mode === 'immediate-udp') {
        connection.sendQueue(); connection.sendQueue = () => { observations.held_queue_calls++ }
      }
      if (['pre-send-update', 'stale-item', 'cipher-cancel', 'cipher-expiry', 'control-interleave'].includes(mode)) hold = true
      const sendReliable = this.connection.sendReliable.bind(this.connection)
      this.connection.sendReliable = (buffer, immediate, origin) => {
        if (!origin?.gameplay) return sendReliable(buffer, immediate, origin)
        const socket = this.connection.raknet.socket; const send = socket.send.bind(socket)
        socket.send = (buffer, callback) => {
          if (mode === 'socket-error') { callback(new Error('injected native send failure')); return }
          if (mode === 'short-completion') { callback(null, 0); return }
          nativeActionSends++
          return send(buffer, (error, bytes) => {
            if (mode === 'completion-held') completion = () => callback(error, bytes)
            else callback(error, bytes)
          })
        }
        try { return sendReliable(buffer, immediate, origin) } finally { socket.send = send }
      }
      observations.connected_udp = client.connection.raknet.socket.remoteAddress().address === '127.0.0.1'
    })
    return originalInit.call(this)
  }
  try {
    await run(validate(f.envelope, f.configPath), row => rows.push(row), controller.signal)
    // Late native/cipher callbacks retain their original identity and cannot
    // resurrect cancellation/expiry or transmit a never-started second action.
    while (held.length) output(held.shift())
    completion?.()
  } finally { Client.prototype.init = originalInit }
  observations.native_action_send_calls = nativeActionSends
  observations.server_received_placements = remote.placements.length
  const report = { schema_version: 1, manifest_sha256: f.envelope.manifest_sha256, round_nonce: f.envelope.round_nonce,
    events: rows.filter(row => row.type === 'event').map(row => row.event), ...rows.at(-1) }
  delete report.type
  fs.writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report))
  const reduced = spawnSync('python3', [path.resolve(__dirname, '../../minecraft_interaction_summary.py'), '--manifest', f.config.manifest_path,
    '--report', path.join(directory, 'report.json'), '--output', path.join(directory, 'summary.json')], { encoding: 'utf8' })
  assert.equal(reduced.status, 0, reduced.stderr)
  const summary = JSON.parse(fs.readFileSync(path.join(directory, 'summary.json')))
  assert.equal(summary.reported_successes, positive ? 1 : 0)
  assert.equal(summary.prescheduled_requests, positive ? 1 : 2)
  assert.equal(summary.execution_kind, 'adapter_fixture'); assert.equal(summary.application_interaction_ms, null)
  assert.equal(observations.connected_udp, true); assert.deepEqual(remote.errors, [])
  assert.equal(remote.placements.length, positive || mode === 'completion-held' ? 1 : 0)
  if (!positive) assert.equal(summary.status_counts.not_started, 1)
  if (mode === 'cipher-expiry') assert.equal(summary.status_counts.timeout, 1)
  if (mode === 'immediate-udp') assert.ok(observations.held_queue_calls > 0)
  if (mode === 'stale-item') assert.equal(observations.current_item_count, 1)
  if (mode === 'control-interleave') assert.equal(observations.control_flushed_original_equipment, true)
  if (mode === 'completion-held') assert.equal(observations.update_before_completion, true)
  observations.reported_successes = summary.reported_successes
  if (process.env.P2WLAN_BEDROCK_FIXTURE_EVIDENCE_DIR) {
    const destination = path.resolve(process.env.P2WLAN_BEDROCK_FIXTURE_EVIDENCE_DIR, 'boundary-' + mode)
    fs.mkdirSync(destination, { mode: 0o700 })
    for (const name of ['manifest.json', 'config.json', 'scenario.json', 'report.json', 'summary.json']) {
      fs.writeFileSync(path.join(destination, name), fs.readFileSync(path.join(directory, name)), { flag: 'wx', mode: 0o600 })
    }
    fs.writeFileSync(path.join(destination, 'protocol-observations.json'), JSON.stringify(observations, null, 2), { flag: 'wx', mode: 0o600 })
  }
}
for (const mode of ['immediate-udp', 'pre-send-update', 'stale-item', 'cipher-cancel', 'cipher-expiry', 'control-interleave', 'socket-error', 'short-completion', 'completion-held']) {
  test(`native socket action fence: ${mode}`, { timeout: 8000 }, t => execute(t, mode))
}
