'use strict'

// Test-only identities and frozen protocol-fixture files, never game evidence.
const fs = require('node:fs')
const path = require('node:path')
const input = require('./bedrock-input')
const nonce = n => n.toString(16).padStart(32, '0')
function fixture (directory, port = 19132, count = 1) {
  const contractRaw = fs.readFileSync(path.resolve(__dirname, '../../../../contracts/minecraft_interaction.json'))
  const contract = JSON.parse(contractRaw)
  const configPath = path.join(directory, 'config.json')
  const config = { schema_version: 1, manifest_path: path.join(directory, 'manifest.json'),
    scenario_path: path.join(directory, 'scenario.json'), host: '127.0.0.1', port, username: 'fixture_bot',
    auth: 'offline', version: '1.18.30', connect_timeout_ms: 3000, allow_remote_endpoint: false }
  const data = require('minecraft-data')('bedrock_1.18.30')
  const actions = Array.from({ length: count }, (_, i) => ({ request_nonce: nonce(100 + i),
    target: { x: 1 + i, y: 65, z: 1 }, reference: { x: 1 + i, y: 64, z: 1 }, face: { x: 0, y: 1, z: 0 },
    hotbar_slot: 0, item_name: 'stone', before_state_id: data.blocksByName.air.defaultState, after_state_id: data.blocksByName.stone.defaultState, reference_state_id: data.blocksByName.stone.defaultState }))
  const scenario = { schema_version: 1, edition: 'bedrock', version: '1.18.30', isolated_world: true, block_palette_sha256: input.sha(JSON.stringify(data.blockStates)), server_palette_checksum: '1',
    rounds: [{ round_nonce: nonce(2), world_reset_sha256: input.sha('fixture reset assertion'), actions }] }
  const identity = {}
  for (const name of ['p2wlan_client_binary', 'p2wlan_server_binary', 'p2wlan_patch', 'configuration', 'adapter', 'adapter_lock',
    'scenario', 'game_client_binary', 'game_server_binary', 'world_snapshot', 'game_settings', 'mods']) identity[name + '_sha256'] = input.sha('fixture ' + name)
  Object.assign(identity, { p2wlan_client_commit: '1'.repeat(40), p2wlan_server_commit: '2'.repeat(40),
    game_client_version: '1.18.30', game_server_version: '1.18.30', protocol_version: '503',
    server_implementation: 'protocol-fixture', runtime_version: `node-${process.versions.node}`,
    platform: 'loopback-protocol-fixture', scenario_version: 'isolated-block-v1' })
  const plan = { schema_version: 1, scope: contract.scope, contract_sha256: input.sha(contractRaw), run_nonce: nonce(1),
    execution_kind: 'adapter_fixture', edition: 'bedrock', transport: 'raknet_udp', variant: 'baseline', identity,
    rounds: [{ round_nonce: nonce(2), adapter_nonce: nonce(3), session_nonce: nonce(4), clock_nonce: nonce(5),
      duration_ns: 5000000000, world_reset_sha256: scenario.rounds[0].world_reset_sha256,
      requests: actions.map((a, i) => ({ ordinal: i, request_nonce: a.request_nonce, planned_offset_ns: 2000000000 + i * 800000000,
        timeout_ns: 600000000, action: 'block_place', target_sha256: input.targetHash(a.target),
        before_state_sha256: input.stateHash(a.before_state_id), after_state_sha256: input.stateHash(a.after_state_id) })) }] }
  const result = { config, scenario, plan, configPath, actions }
  result.save = () => {
    fs.writeFileSync(configPath, JSON.stringify(config))
    fs.writeFileSync(config.scenario_path, JSON.stringify(scenario))
    identity.configuration_sha256 = input.sha(fs.readFileSync(configPath))
    identity.scenario_sha256 = input.sha(fs.readFileSync(config.scenario_path))
    identity.adapter_sha256 = input.adapterHash()
    identity.adapter_lock_sha256 = input.sha(fs.readFileSync(path.join(__dirname, 'package-lock.json')))
    fs.writeFileSync(config.manifest_path, JSON.stringify(plan, null, 2) + '\n')
    result.envelope = { schema_version: 1, manifest_sha256: input.sha(fs.readFileSync(config.manifest_path)),
      manifest: plan, round_nonce: plan.rounds[0].round_nonce }
    return result
  }
  return result.save()
}
module.exports = { fixture, nonce }
