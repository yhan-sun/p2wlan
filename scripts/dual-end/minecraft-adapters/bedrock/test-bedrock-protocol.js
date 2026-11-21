'use strict'
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { once } = require('node:events')
const { spawn, spawnSync } = require('node:child_process')
const { fixture } = require('./fixture-input')
const { serverFixture, data } = require('./fixture-server')

async function execute (t, mode) {
  const remote = await serverFixture(mode)
  t.after(() => remote.close())
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bedrock-codec-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const count = mode === 'two-actions' || mode === 'timeout' ? 2 : 1
  const f = fixture(directory, remote.port, count)
  if (mode === 'never-ready') {
    f.plan.rounds[0].duration_ns = 500000000
    f.plan.rounds[0].requests[0].planned_offset_ns = 0
    f.plan.rounds[0].requests[0].timeout_ns = 100000000
    f.save()
  }
  const child = spawn(process.execPath, [path.join(__dirname, 'bedrock-adapter.js'), '--config', f.configPath],
    { stdio: ['pipe', 'pipe', 'pipe'] })
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL') })
  const output = []; const diagnostics = []
  child.stdout.on('data', b => output.push(b)); child.stderr.on('data', b => diagnostics.push(b))
  if (mode === 'cancel') remote.server.once('fixture_placement', () => child.kill('SIGTERM'))
  child.stdin.end(JSON.stringify(f.envelope))
  const timer = setTimeout(() => child.kill('SIGKILL'), 8000)
  const [code, signal] = await once(child, 'exit'); clearTimeout(timer)
  assert.equal(signal, null, Buffer.concat(diagnostics).toString())
  assert.equal(code, 0, Buffer.concat(diagnostics).toString())
  assert.deepEqual(remote.errors, [])
  const rows = Buffer.concat(output).toString().trim().split('\n').map(line => JSON.parse(line))
  assert.equal(rows.at(-1).type, 'finish')
  const expectedSends = ['never-ready', 'missing-before', 'unsupported-profile'].includes(mode) ? 0 : mode === 'two-actions' ? 2 : 1
  assert.equal(remote.placements.length, expectedSends, JSON.stringify(rows))
  for (const packet of remote.placements) {
    assert.equal(packet.transaction.transaction_type, 'item_use')
    assert.equal(packet.transaction.transaction_data.action_type, 'click_block')
    assert.equal(packet.transaction.transaction_data.face, 1)
    assert.equal(packet.transaction.transaction_data.held_item.network_id, data.itemsByName.stone.id)
  }
  const report = { schema_version: 1, manifest_sha256: f.envelope.manifest_sha256, round_nonce: f.envelope.round_nonce,
    events: rows.filter(x => x.type === 'event').map(x => x.event), ...rows.at(-1) }
  delete report.type
  fs.writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report))
  const result = spawnSync('python3', [path.resolve(__dirname, '../../minecraft_interaction_summary.py'),
    '--manifest', f.config.manifest_path, '--report', path.join(directory, 'report.json'), '--output', path.join(directory, 'summary.json')], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const summary = JSON.parse(fs.readFileSync(path.join(directory, 'summary.json')))
  assert.equal(summary.prescheduled_requests, count)
  assert.equal(summary.execution_kind, 'adapter_fixture')
  assert.equal(summary.application_interaction_ms, null)
  if (process.env.P2WLAN_BEDROCK_FIXTURE_EVIDENCE_DIR) {
    const destination = path.resolve(process.env.P2WLAN_BEDROCK_FIXTURE_EVIDENCE_DIR, mode)
    fs.mkdirSync(destination, { mode: 0o700 })
    for (const name of ['manifest.json', 'config.json', 'scenario.json', 'report.json', 'summary.json']) {
      fs.writeFileSync(path.join(destination, name), fs.readFileSync(path.join(directory, name)), { flag: 'wx', mode: 0o600 })
    }
    fs.writeFileSync(path.join(destination, 'protocol-observations.json'), JSON.stringify({
      scope: 'loopback_encrypted_raknet_protocol_fixture_not_game_world', version: '1.18.30',
      protocol: 503, raknet: 10, placements: remote.placements, ndjson: rows
    }, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2), { flag: 'wx', mode: 0o600 })
  }
  return { summary, rows }
}
for (const mode of ['single', 'duplicate', 'two-actions']) test(`encrypted RakNet codec fixture: ${mode}`, { timeout: 10000 }, async t => {
  const { summary } = await execute(t, mode)
  assert.equal(summary.reported_successes, mode === 'two-actions' ? 2 : 1)
  assert.equal(summary.fixture_latency_ms.sample_count, mode === 'two-actions' ? 2 : 1)
})
for (const mode of ['wrong-state', 'wrong-target', 'wrong-layer', 'timeout', 'disconnect', 'cancel', 'missing-before', 'unsupported-profile', 'never-ready']) {
  test(`encrypted RakNet codec fixture rejects ${mode}`, { timeout: 10000 }, async t => {
    const { summary } = await execute(t, mode)
    assert.equal(summary.reported_successes, 0)
    const status = { 'wrong-state': 'action_error', 'wrong-target': 'timeout', 'wrong-layer': 'timeout', timeout: 'timeout',
      disconnect: 'disconnected', cancel: 'cancelled', 'missing-before': 'action_error', 'unsupported-profile': 'not_started', 'never-ready': 'not_started' }[mode]
    assert.equal(summary.status_counts[status], 1)
    if (mode === 'timeout') assert.equal(summary.status_counts.not_started, 1)
  })
}
