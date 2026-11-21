'use strict'

// All inputs are frozen before createBot. Server/world/build identity fields
// remain declarations: this tool can check local source/config bytes, not prove
// that a remote game world, binary or P2WLAN path has the declared identity.
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const net = require('node:net')
const { isDeepStrictEqual } = require('node:util')
const VERSION = '1.20.4'
const MAX_BYTES = 16 * 1024 * 1024
const SOURCE_FILES = ['java-input.js', 'java-session.js', 'java-adapter.js', 'package.json']
const sha = data => crypto.createHash('sha256').update(data).digest('hex')
const fail = message => { throw new Error(message) }
function keys (value, names) {
  if (!value || Array.isArray(value) || typeof value !== 'object' ||
      Object.keys(value).sort().join(',') !== names.slice().sort().join(',')) fail('unsupported or missing fields')
}
function integer (value, low, high) {
  if (!Number.isSafeInteger(value) || value < low || value > high) fail('integer outside bound')
}
function hex (value, length) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length}}$`).test(value)) fail('invalid digest/nonce')
}
function parseStrict (raw) {
  if (raw.length > MAX_BYTES) fail('input byte limit')
  const text = new TextDecoder('utf-8', { fatal: true }).decode(raw)
  // JSON.parse checks grammar; this bounded recursive token walk additionally
  // rejects duplicate object keys rather than allowing silent last-key wins.
  const value = JSON.parse(text)
  const tokens = text.match(/"(?:\\.|[^"\\])*"|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}[\],:]/g) || []
  let i = 0
  function walk (depth) {
    if (depth > 32) fail('JSON depth limit')
    const token = tokens[i++]
    if (token === '{') {
      const seen = new Set()
      while (tokens[i] !== '}') {
        const name = JSON.parse(tokens[i++])
        if (seen.has(name)) fail('duplicate JSON key')
        seen.add(name); i++; walk(depth + 1)
        if (tokens[i] === ',') i++
      }
      i++
    } else if (token === '[') {
      while (tokens[i] !== ']') { walk(depth + 1); if (tokens[i] === ',') i++ }
      i++
    } else if (token && /^-?\d/.test(token) && !Number.isFinite(Number(token))) fail('non-finite JSON number')
  }
  walk(0)
  return value
}
function read (filename) {
  if (!path.isAbsolute(filename)) fail('input paths must be absolute')
  const fd = fs.openSync(filename, 'r')
  try {
    if (!fs.fstatSync(fd).isFile()) fail('regular input file required')
    const data = Buffer.alloc(MAX_BYTES + 1)
    const length = fs.readSync(fd, data, 0, data.length, 0)
    if (length > MAX_BYTES) fail('input byte limit')
    const raw = data.subarray(0, length)
    return { raw, value: parseStrict(raw) }
  } finally { fs.closeSync(fd) }
}
function adapterHash () {
  return sha(SOURCE_FILES.map(name => `${name}\0${sha(fs.readFileSync(path.join(__dirname, name)))}\n`).join(''))
}
function position (p) {
  keys(p, ['x', 'y', 'z'])
  integer(p.x, -30000000, 30000000); integer(p.z, -30000000, 30000000); integer(p.y, -64, 319)
}
const targetHash = p => sha(`java:${VERSION}:block-position:${p.x},${p.y},${p.z}`)
const stateHash = state => sha(`java:${VERSION}:block-state:${state}`)

function validate (envelope, configPath) {
  keys(envelope, ['schema_version', 'manifest_sha256', 'manifest', 'round_nonce'])
  if (envelope.schema_version !== 1) fail('envelope version')
  hex(envelope.manifest_sha256, 64); hex(envelope.round_nonce, 32)
  const configInput = read(configPath); const config = configInput.value
  keys(config, ['schema_version', 'manifest_path', 'scenario_path', 'host', 'port', 'username', 'auth', 'version', 'connect_timeout_ms'])
  if (config.schema_version !== 1 || config.auth !== 'offline' || config.version !== VERSION ||
      !net.isIP(config.host) || !/^[A-Za-z0-9_]{3,16}$/.test(config.username)) fail('explicit offline numeric-address configuration required')
  integer(config.port, 1, 65535); integer(config.connect_timeout_ms, 1, 10000)
  const input = read(config.manifest_path); const plan = input.value
  if (sha(input.raw) !== envelope.manifest_sha256 || !isDeepStrictEqual(plan, envelope.manifest)) fail('original manifest bytes/envelope mismatch')
  keys(plan, ['schema_version', 'scope', 'contract_sha256', 'run_nonce', 'execution_kind', 'edition', 'transport', 'variant', 'identity', 'rounds'])
  const contractRaw = fs.readFileSync(path.resolve(__dirname, '../../../contracts/minecraft_interaction.json'))
  const contract = JSON.parse(contractRaw)
  if (plan.schema_version !== 1 || plan.scope !== contract.scope || plan.contract_sha256 !== sha(contractRaw) ||
      !contract.execution_kinds.includes(plan.execution_kind) || plan.edition !== 'java' || plan.transport !== 'tcp' ||
      !['baseline', 'candidate'].includes(plan.variant)) fail('manifest contract/edition mismatch')
  hex(plan.run_nonce, 32)
  const identity = plan.identity
  const hashes = ['p2wlan_client_binary', 'p2wlan_server_binary', 'p2wlan_patch', 'configuration', 'adapter',
    'adapter_lock', 'scenario', 'game_client_binary', 'game_server_binary', 'world_snapshot', 'game_settings', 'mods'].map(x => x + '_sha256')
  const labels = ['game_client_version', 'game_server_version', 'protocol_version', 'server_implementation', 'runtime_version', 'platform', 'scenario_version']
  keys(identity, [...hashes, ...labels, 'p2wlan_client_commit', 'p2wlan_server_commit'])
  for (const name of hashes) hex(identity[name], 64)
  for (const name of ['p2wlan_client_commit', 'p2wlan_server_commit']) hex(identity[name], 40)
  for (const name of labels) {
    if (typeof identity[name] !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,95}$/.test(identity[name])) fail('invalid identity label')
    if (name.includes('version') && ['latest', 'current', 'auto', 'default'].includes(identity[name].toLowerCase())) fail('fixed versions required')
  }
  const scenarioInput = read(config.scenario_path); const scenario = scenarioInput.value
  if (identity.configuration_sha256 !== sha(configInput.raw) || identity.scenario_sha256 !== sha(scenarioInput.raw) ||
      identity.adapter_sha256 !== adapterHash() || identity.adapter_lock_sha256 !== sha(fs.readFileSync(path.join(__dirname, 'package-lock.json'))) ||
      identity.runtime_version !== `node-${process.versions.node}` || identity.game_client_version !== VERSION ||
      identity.game_server_version !== VERSION || identity.protocol_version !== '765') fail('fixed version or local byte identity mismatch')
  keys(scenario, ['schema_version', 'edition', 'version', 'isolated_world', 'rounds'])
  if (scenario.schema_version !== 1 || scenario.edition !== 'java' || scenario.version !== VERSION || scenario.isolated_world !== true) fail('isolated fixed scenario required')
  if (!Array.isArray(plan.rounds) || !Array.isArray(scenario.rounds)) fail('round arrays required')
  integer(plan.rounds.length, 1, contract.max_rounds)
  if (scenario.rounds.length !== plan.rounds.length) fail('scenario must cover all scheduled rounds')
  const data = require('minecraft-data')(VERSION)
  const seenRounds = new Set(); const seenRequests = new Set(); const seenSessions = new Set()
  for (let r = 0; r < plan.rounds.length; r++) {
    const round = plan.rounds[r]; const scene = scenario.rounds[r]
    keys(round, ['round_nonce', 'adapter_nonce', 'session_nonce', 'clock_nonce', 'duration_ns', 'world_reset_sha256', 'requests'])
    for (const name of ['round_nonce', 'adapter_nonce', 'session_nonce', 'clock_nonce']) hex(round[name], 32)
    hex(round.world_reset_sha256, 64); integer(round.duration_ns, 1, contract.max_duration_ns)
    const session = `${round.adapter_nonce}:${round.session_nonce}`
    if (seenRounds.has(round.round_nonce) || seenSessions.has(session)) fail('reused round/session')
    seenRounds.add(round.round_nonce); seenSessions.add(session)
    keys(scene, ['round_nonce', 'world_reset_sha256', 'actions'])
    if (scene.round_nonce !== round.round_nonce || scene.world_reset_sha256 !== round.world_reset_sha256 ||
        !Array.isArray(scene.actions) || !Array.isArray(round.requests) || scene.actions.length !== round.requests.length) fail('scenario round mismatch')
    integer(round.requests.length, 1, contract.max_requests_per_round)
    const targets = new Set(); let previous = -1
    round.requests.forEach((request, index) => {
      keys(request, ['ordinal', 'request_nonce', 'planned_offset_ns', 'timeout_ns', 'action', 'target_sha256', 'before_state_sha256', 'after_state_sha256'])
      hex(request.request_nonce, 32)
      integer(request.ordinal, index, index); integer(request.timeout_ns, 1, contract.max_request_timeout_ns)
      integer(request.planned_offset_ns, previous + 1, round.duration_ns - request.timeout_ns); previous = request.planned_offset_ns
      if (request.action !== 'block_place' || seenRequests.has(request.request_nonce)) fail('action/retry identity mismatch')
      seenRequests.add(request.request_nonce)
      const action = scene.actions[index]
      keys(action, ['request_nonce', 'target', 'reference', 'face', 'hotbar_slot', 'item_name', 'before_state_id', 'after_state_id', 'reference_state_id'])
      if (action.request_nonce !== request.request_nonce) fail('scenario action identity mismatch')
      position(action.target); position(action.reference); keys(action.face, ['x', 'y', 'z'])
      for (const axis of ['x', 'y', 'z']) {
        integer(action.face[axis], -1, 1)
        if (action.target[axis] !== action.reference[axis] + action.face[axis]) fail('reference face does not reach target')
      }
      if (Object.values(action.face).reduce((sum, n) => sum + Math.abs(n), 0) !== 1) fail('one reference face required')
      integer(action.hotbar_slot, 0, 8)
      for (const name of ['before_state_id', 'after_state_id', 'reference_state_id']) {
        integer(action[name], 0, data.blocksArray.at(-1).maxStateId)
        if (!data.blocksByStateId[action[name]]) fail('unknown block state')
      }
      if (action.before_state_id === action.after_state_id) fail('placement requires actual block transition')
      if (data.blocksByStateId[action.before_state_id].name !== 'air' ||
          data.blocksByStateId[action.reference_state_id].boundingBox !== 'block' ||
          data.blocksByStateId[action.after_state_id].name !== action.item_name || !data.itemsByName[action.item_name]) fail('unsupported placement precondition')
      const target = targetHash(action.target)
      if (request.target_sha256 !== target || request.before_state_sha256 !== stateHash(action.before_state_id) ||
          request.after_state_sha256 !== stateHash(action.after_state_id) || targets.has(target)) fail('scenario target/state digest mismatch')
      targets.add(target)
    })
    if (scene.actions.some(action => targets.has(targetHash(action.reference)))) fail('target/reference overlap breaks isolation')
  }
  const index = plan.rounds.findIndex(r => r.round_nonce === envelope.round_nonce)
  if (index < 0) fail('unknown selected round')
  return { plan, round: plan.rounds[index], actions: scenario.rounds[index].actions, config, contract, data }
}
module.exports = { validate, read, parseStrict, sha, adapterHash, targetHash, stateHash, VERSION, MAX_BYTES }
