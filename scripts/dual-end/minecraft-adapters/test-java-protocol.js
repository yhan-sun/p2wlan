'use strict'

// A small loopback protocol server with static chunk/inventory state. This is
// not a Minecraft server/world simulation or an application performance test.
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { once } = require('node:events')
const { spawn } = require('node:child_process')
const protocol = require('minecraft-protocol')
const data = require('minecraft-data')('1.20.4')
const Chunk = require('prismarine-chunk')('1.20.4')
const { Vec3 } = require('vec3')
const { fixture } = require('./fixture-input')

async function serverFixture (t, mode) {
  const server = protocol.createServer({ host: '127.0.0.1', port: 0, version: '1.20.4',
    'online-mode': false, keepAlive: false, registryCodec: data.loginPacket.dimensionCodec })
  const clients = []; const placements = []; const errors = []
  server.on('error', error => errors.push(error.message))
  server.on('playerJoin', client => {
    clients.push(client); client.on('error', error => errors.push(error.message))
    client.write('login', { ...data.loginPacket, entityId: 1, gameMode: 0, viewDistance: 2, simulationDistance: 2 })
    const chunk = new Chunk({ minY: -64, worldHeight: 384 })
    chunk.setBlockStateId(new Vec3(1, 64, 1), 1)
    chunk.setBlockStateId(new Vec3(2, 64, 1), 1)
    client.write('map_chunk', { x: 0, z: 0, heightmaps: { type: 'compound', value: {} }, chunkData: chunk.dump(),
      blockEntities: [], skyLightMask: [], blockLightMask: [], emptySkyLightMask: [], emptyBlockLightMask: [], skyLight: [], blockLight: [] })
    const items = Array.from({ length: 46 }, () => ({ present: false }))
    items[36] = { present: true, itemId: 1, itemCount: 64, nbtData: undefined }
    client.write('window_items', { windowId: 0, stateId: 1, items, carriedItem: { present: false } })
    client.write('position', { x: 1.5, y: 65, z: 2.5, yaw: 0, pitch: 0, flags: 0, teleportId: 1 })
    if (mode !== 'never-ready') client.write('update_health', { health: 20, food: 20, foodSaturation: 5 })
    client.on('block_place', packet => {
      placements.push(packet)
      server.emit('fixture_placement')
      if (mode === 'disconnect') { client.end('fixture disconnect'); return }
      if (mode === 'timeout' || mode === 'cancel') return
      const reference = packet.location
      const target = { x: reference.x, y: reference.y + 1, z: reference.z }
      if (mode.startsWith('multi-batched-')) {
        const referenceRecord = (1 << 12) | (reference.x << 8) | (reference.z << 4) | (reference.y & 15)
        const targetRecord = (1 << 12) | (target.x << 8) | (target.z << 4) | (target.y & 15)
        client.write('multi_block_change', { chunkCoordinates: { x: 0, y: 4, z: 0 },
          records: mode === 'multi-batched-target-first' ? [targetRecord, referenceRecord] : [referenceRecord, targetRecord] })
        return
      }
      // Stale target before reference acknowledgement cannot earn success.
      client.write('block_change', { location: target, type: 1 })
      client.write('block_change', { location: reference, type: 1 })
      if (mode === 'stale-only') return
      const state = mode === 'wrong-state' ? 0 : 1
      if (mode === 'multi') {
        client.write('multi_block_change', { chunkCoordinates: { x: 0, y: 4, z: 0 }, records: [(state << 12) | (1 << 8) | (1 << 4) | 1] })
      } else client.write('block_change', { location: target, type: state })
    })
  })
  await once(server, 'listening')
  t.after(() => { for (const client of clients) client.socket.destroy(); server.close() })
  return { server, placements, errors, port: server.socketServer.address().port }
}

async function execute (t, mode) {
  const remote = await serverFixture(t, mode)
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mc-codec-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const count = mode === 'two-actions' ? 2 : 1
  const f = fixture(directory, remote.port, count)
  if (mode === 'never-ready') {
    f.plan.rounds[0].duration_ns = 300000000
    f.plan.rounds[0].requests[0].planned_offset_ns = 0
    f.plan.rounds[0].requests[0].timeout_ns = 100000000
    f.save()
  }
  const child = spawn(process.execPath, [path.join(__dirname, 'java-adapter.js'), '--config', f.configPath],
    { stdio: ['pipe', 'pipe', 'pipe'] })
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL') })
  const output = []; const diagnostic = []
  child.stdout.on('data', b => output.push(b)); child.stderr.on('data', b => diagnostic.push(b))
  if (mode === 'cancel') remote.server.once('fixture_placement', () => child.kill('SIGTERM'))
  child.stdin.end(JSON.stringify(f.envelope))
  const deadline = setTimeout(() => child.kill('SIGKILL'), 8000)
  const [code, signal] = await once(child, 'exit'); clearTimeout(deadline)
  assert.equal(signal, null, Buffer.concat(diagnostic).toString())
  assert.equal(code, 0, Buffer.concat(diagnostic).toString())
  assert.deepEqual(remote.errors, [])
  const events = Buffer.concat(output).toString().trim().split('\n').map(line => JSON.parse(line))
  assert.equal(events.at(-1).type, 'finish')
  assert.equal(remote.placements.length, mode === 'never-ready' ? 0 : count, JSON.stringify(events))
  if (remote.placements.length) {
    assert.deepEqual(remote.placements[0].location, { x: 1, y: 64, z: 1 })
    assert.equal(remote.placements[0].direction, 1)
    assert.equal(remote.placements[0].hand, 0)
  }
  // Reuse the existing authoritative reducer against actual emitted NDJSON.
  const report = { schema_version: 1, manifest_sha256: f.envelope.manifest_sha256, round_nonce: f.envelope.round_nonce,
    events: events.filter(x => x.type === 'event').map(x => x.event), ...events.at(-1) }
  delete report.type
  fs.writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report))
  const { spawnSync } = require('node:child_process')
  const python = spawnSync('python3', [path.resolve(__dirname, '../minecraft_interaction_summary.py'),
    '--manifest', f.config.manifest_path, '--report', path.join(directory, 'report.json'), '--output', path.join(directory, 'summary.json')], { encoding: 'utf8' })
  assert.equal(python.status, 0, python.stderr)
  const summary = JSON.parse(fs.readFileSync(path.join(directory, 'summary.json')))
  assert.equal(summary.prescheduled_requests, count)
  assert.equal(summary.application_interaction_ms, null)
  assert.equal(summary.execution_kind, 'adapter_fixture')
  if (process.env.P2WLAN_MC_FIXTURE_EVIDENCE_DIR) {
    const destination = path.resolve(process.env.P2WLAN_MC_FIXTURE_EVIDENCE_DIR, mode)
    fs.mkdirSync(destination, { mode: 0o700 })
    for (const name of ['manifest.json', 'scenario.json', 'config.json', 'report.json', 'summary.json']) {
      fs.writeFileSync(path.join(destination, name), fs.readFileSync(path.join(directory, name)), { flag: 'wx', mode: 0o600 })
    }
    fs.writeFileSync(path.join(destination, 'protocol-observations.json'), JSON.stringify({
      scope: 'loopback_protocol_fixture_not_game_world', version: '1.20.4', placements: remote.placements, ndjson: events
    }, null, 2), { flag: 'wx', mode: 0o600 })
  }
  return { events, summary }
}

for (const mode of ['single', 'multi', 'multi-batched-target-first', 'multi-batched-reference-first']) test(`loopback protocol fixture: real Mineflayer placement and ${mode} packet confirmation`, { timeout: 10000 }, async t => {
  const { summary } = await execute(t, mode)
  assert.equal(summary.reported_successes, 1)
  assert.equal(summary.fixture_latency_ms.sample_count, 1)
})
test('loopback protocol fixture: two scheduled targets each transmit once and complete', { timeout: 10000 }, async t => {
  const { summary, events } = await execute(t, 'two-actions')
  assert.equal(summary.reported_successes, 2)
  const starts = events.filter(row => row.event?.kind === 'action_started')
  assert.equal(new Set(starts.map(row => row.event.request_nonce)).size, 2)
})
for (const mode of ['wrong-state', 'timeout', 'disconnect', 'stale-only', 'cancel', 'never-ready']) test(`loopback protocol fixture: ${mode} retains failed request`, { timeout: 10000 }, async t => {
  const { summary } = await execute(t, mode)
  assert.equal(summary.reported_successes, 0)
  const statuses = { 'wrong-state': 'action_error', timeout: 'timeout', disconnect: 'disconnected',
    'stale-only': 'timeout', cancel: 'cancelled', 'never-ready': 'not_started' }
  assert.equal(summary.status_counts[statuses[mode]], 1)
})
