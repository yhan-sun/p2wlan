'use strict'
const test = require('node:test'); const assert = require('node:assert/strict')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { fixture } = require('./fixture-input')
const { validate, parseStrict } = require('./bedrock-input')
function setup (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bedrock-input-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return fixture(dir, 19132, 2)
}
test('freezes the entire original denominator; raw whitespace bytes matter', t => {
  const f = setup(t); const input = validate(f.envelope, f.configPath)
  assert.equal(input.round.requests.length, 2)
  assert.throws(() => { input.round.requests.pop() }, TypeError)
  fs.appendFileSync(f.config.manifest_path, '\n')
  assert.throws(() => validate(f.envelope, f.configPath), /manifest bytes/)
})
test('parsed envelope mismatch is rejected even with the correct raw digest', t => {
  const f = setup(t); const envelope = structuredClone(f.envelope)
  envelope.manifest.rounds[0].requests.pop()
  assert.throws(() => validate(envelope, f.configPath), /manifest bytes/)
})
test('unknown future scheduled actions fail before any connection', t => {
  const f = setup(t); f.scenario.rounds[0].actions.pop(); f.save()
  assert.throws(() => validate(f.envelope, f.configPath), /scenario round/)
})
test('duplicate target, identity, and no-op state fail frozen validation', t => {
  for (const mutate of [f => { f.plan.rounds[0].requests[1].request_nonce = f.plan.rounds[0].requests[0].request_nonce },
    f => { f.scenario.rounds[0].actions[1].target = f.actions[0].target },
    f => { f.actions[0].after_state_id = f.actions[0].before_state_id }]) {
    const f = setup(t); mutate(f); f.save(); assert.throws(() => validate(f.envelope, f.configPath))
  }
})
test('remote endpoint needs explicit opt-in and version cannot auto-discover', t => {
  const f = setup(t); f.config.host = '192.0.2.1'; f.save()
  assert.throws(() => validate(f.envelope, f.configPath), /opt-in/)
  f.config.allow_remote_endpoint = true; f.save(); assert.equal(validate(f.envelope, f.configPath).config.host, '192.0.2.1')
  f.config.version = '1.20.80'; f.save(); assert.throws(() => validate(f.envelope, f.configPath), /configuration/)
})
test('palette/source/runtime/digest mismatches fail', t => {
  for (const mutate of [f => { f.scenario.block_palette_sha256 = '0'.repeat(64) },
    f => { f.plan.identity.runtime_version = 'node-0.0.0' },
    f => { f.plan.identity.protocol_version = '671' }]) {
    const f = setup(t); mutate(f); f.save(); assert.throws(() => validate(f.envelope, f.configPath))
  }
  const f = setup(t); f.envelope.manifest_sha256 = '0'.repeat(64)
  assert.throws(() => validate(f.envelope, f.configPath), /manifest bytes/)
})
test('recorded mode remains accepted with declared game identity, no authentication upgrade', t => {
  const f = setup(t); f.plan.execution_kind = 'recorded_game_session'; f.save()
  assert.equal(validate(f.envelope, f.configPath).plan.execution_kind, 'recorded_game_session')
})
test('strict input rejects duplicate JSON fields, depth and byte floods', () => {
  assert.throws(() => parseStrict(Buffer.from('{"a":1,"a":2}')), /duplicate/)
  assert.throws(() => parseStrict(Buffer.from('['.repeat(34) + '0' + ']'.repeat(34))), /depth/)
  assert.throws(() => parseStrict(Buffer.alloc(16 * 1024 * 1024 + 1)), /byte/)
})
