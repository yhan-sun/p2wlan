'use strict'
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { fixture } = require('./fixture-input')
const { validate, parseStrict } = require('./java-input')

function temp (t) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mc-input-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir }
test('raw original manifest identity accepts formatting and binds all scenario requests', t => {
  const f = fixture(temp(t), 25565, 2)
  const input = validate(f.envelope, f.configPath)
  assert.equal(input.actions.length, 2)
  assert.equal(input.plan.execution_kind, 'adapter_fixture')
  assert.notEqual(JSON.stringify(f.plan), fs.readFileSync(f.config.manifest_path, 'utf8'))
})
test('strict input rejects duplicates, nonfinite, malformed UTF8 and deep data', () => {
  for (const raw of ['{"x":1,"x":2}', '{"x":1e999}', '['.repeat(34) + '0' + ']'.repeat(34)]) assert.throws(() => parseStrict(Buffer.from(raw)))
  assert.throws(() => parseStrict(Buffer.from([255])))
})
test('hash drift in original file, envelope, source, lock or scenario fails before connection', t => {
  const f = fixture(temp(t))
  fs.appendFileSync(f.config.manifest_path, ' ')
  assert.throws(() => validate(f.envelope, f.configPath), /manifest/)
  f.save(); f.envelope = structuredClone(f.envelope); f.envelope.manifest.variant = 'candidate'
  assert.throws(() => validate(f.envelope, f.configPath), /manifest/)
  for (const name of ['adapter_sha256', 'adapter_lock_sha256', 'scenario_sha256', 'configuration_sha256']) {
    f.save(); f.plan.identity[name] = '0'.repeat(64)
    fs.writeFileSync(f.config.manifest_path, JSON.stringify(f.plan))
    f.envelope.manifest_sha256 = require('./java-input').sha(fs.readFileSync(f.config.manifest_path))
    assert.throws(() => validate(f.envelope, f.configPath), /identity/)
  }
})
test('every prescheduled mapping and fixed runtime/version is validated', t => {
  const mutations = [f => { f.actions[1].target.x++ }, f => { f.actions[1].after_state_id = 2 },
    f => { f.actions[1].request_nonce = f.actions[0].request_nonce }, f => { f.actions[1].face.y = 0 },
    f => { f.actions[1].hotbar_slot = 9 }, f => { f.plan.identity.runtime_version = 'node-22.0.0' },
    f => { f.plan.identity.game_server_version = '1.20.1' }, f => { f.config.auth = 'microsoft' },
    f => { f.config.host = 'example.invalid' }, f => { f.plan.rounds[0].requests[1].timeout_ns = 0 },
    f => { f.plan.rounds[0].requests[1].request_nonce = f.plan.rounds[0].requests[0].request_nonce }]
  for (const mutate of mutations) { const f = fixture(temp(t), 25565, 2); mutate(f); f.save(); assert.throws(() => validate(f.envelope, f.configPath)) }
})

test('no-op state cannot become a scheduled block transition', t => {
  const f = fixture(temp(t))
  f.actions[0].after_state_id = f.actions[0].before_state_id
  f.actions[0].item_name = 'air'
  f.plan.rounds[0].requests[0].after_state_sha256 = f.plan.rounds[0].requests[0].before_state_sha256
  f.save()
  assert.throws(() => validate(f.envelope, f.configPath), /actual block transition/)
})
