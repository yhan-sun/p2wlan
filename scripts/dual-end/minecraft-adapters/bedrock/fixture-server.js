'use strict'

// Synthetic protocol fixture only: no world simulator, game server or terrain.
const { Server } = require('bedrock-protocol')
const data = require('minecraft-data')('bedrock_1.18.30')
function defaults (type) {
  if (typeof type === 'string') {
    if (type === 'nbt' || type === 'lnbt') return { type: 'compound', name: '', value: {} }
    if (type === 'uuid') return '00000000-0000-0000-0000-000000000000'
    if (type === 'string') return ''
    if (type === 'bool') return false
    if (type.includes('64')) return 0n
    if (type === 'void') return undefined
    if (data.protocol.types[type] && data.protocol.types[type] !== 'native') return defaults(data.protocol.types[type])
    return 0
  }
  const [kind, args] = type
  if (kind === 'container') return Object.fromEntries(args.filter(field => field.name).map(field => [field.name, defaults(field.type)]))
  if (kind === 'array') return []
  if (kind === 'mapper') return Object.values(args.mappings)[0]
  if (kind === 'bitflags') return {}
  if (kind === 'switch') return defaults(args.default || Object.values(args.fields)[0])
  throw new Error('unsupported fixture type ' + kind)
}
function startGame (mode) {
  return { ...defaults('packet_start_game'), entity_id: 1n, runtime_entity_id: 1n,
    player_gamemode: 'creative', player_position: { x: 1.5, y: 65, z: 2.5 }, dimension: 'overworld',
    world_gamemode: 'creative', game_version: '1.18.30', movement_authority: mode === 'unsupported-profile' ? 'server' : 'client',
    server_authoritative_inventory: false, server_authoritative_block_breaking: false,
    block_pallete_checksum: 1n, itemstates: [{ name: 'minecraft:stone', runtime_id: data.itemsByName.stone.id, component_based: false }] }
}
const item = () => ({ network_id: data.itemsByName.stone.id, count: 64, metadata: 0, has_stack_id: 0,
  block_runtime_id: data.blocksByName.stone.defaultState, extra: { has_nbt: 0, can_place_on: [], can_destroy: [] } })
const update = (position, state, layer = 0) => ({ position, block_runtime_id: state, flags: { network: true }, layer })
async function serverFixture (mode) {
  const server = new Server({ host: '127.0.0.1', port: 0, version: '1.18.30', offline: true,
    transport: 'raknet', raknetBackend: 'jsp-raknet', conLog: null })
  const placements = []; const errors = []; const clients = []
  server.on('error', error => errors.push(error.message))
  server.on('connect', client => {
    clients.push(client); client.on('error', error => errors.push(error.message))
    client.on('join', () => {
      try {
        client.write('start_game', startGame(mode))
        client.write('inventory_content', { window_id: 'inventory', input: [item()] })
        for (const x of [1, 2]) {
          client.write('update_block', update({ x, y: 64, z: 1 }, data.blocksByName.stone.defaultState))
          if (mode !== 'missing-before') client.write('update_block', update({ x, y: 65, z: 1 }, data.blocksByName.air.defaultState))
        }
        if (mode !== 'never-ready') client.write('play_status', { status: 'player_spawn' })
      } catch (error) { errors.push(error.stack); client.close() }
    })
    client.on('inventory_transaction', packet => {
      placements.push(packet); server.emit('fixture_placement')
      if (mode === 'disconnect') { client.disconnect('fixture disconnect'); return }
      if (mode === 'timeout' || mode === 'cancel') return
      const reference = packet.transaction.transaction_data.block_position
      const target = { x: reference.x, y: reference.y + 1, z: reference.z }
      if (mode === 'wrong-target') target.x += 10
      const state = mode === 'wrong-state' ? data.blocksByName.air.defaultState : data.blocksByName.stone.defaultState
      client.write('update_block', update(target, state, mode === 'wrong-layer' ? 1 : 0))
      if (mode === 'duplicate') client.write('update_block', update(target, state))
    })
  })
  await server.listen()
  // Discovery is outside this fixture; upstream 3.60.1 calls a missing JS-backend
  // advertisement setter. No client performs ping or port/version discovery.
  clearInterval(server.serverTimer)
  return { server, placements, errors, clients, port: server.transport.raknet.socket.address().port,
    async close () { for (const client of clients) client.close(); await server.close() } }
}
module.exports = { serverFixture, startGame, item, update, data }
