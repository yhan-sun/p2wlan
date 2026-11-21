'use strict'

const { sha, VERSION } = require('./bedrock-input')
const { isDeepStrictEqual } = require('node:util')
const { serialize, deserialize } = require('node:v8')
const key = p => `${p.x},${p.y},${p.z}`
const faceId = p => p.y < 0 ? 0 : p.y > 0 ? 1 : p.z < 0 ? 2 : p.z > 0 ? 3 : p.x < 0 ? 4 : 5
const finitePosition = p => p && ['x', 'y', 'z'].every(axis => Number.isFinite(p[axis]) && Math.abs(p[axis]) <= 30000000)

class Session {
  constructor (input, emit, now) {
    this.input = input; this.emit = emit; this.now = now; this.sequence = 0; this.packetSequence = 0
    this.closed = false; this.active = null; this.blocks = new Map(); this.inventory = new Map()
    this.positions = new Set(input.actions.flatMap(a => [key(a.target), key(a.reference)]))
    this.source = { run_nonce: input.plan.run_nonce }
    for (const field of ['round_nonce', 'adapter_nonce', 'session_nonce', 'clock_nonce']) this.source[field] = input.round[field]
  }

  event (kind, fields = {}, offset = this.now()) {
    if (this.sequence >= this.input.contract.max_events_per_round) throw new Error('event bound')
    this.emit({ type: 'event', event: { ...this.source, event_seq: this.sequence++,
      offset_ns: Math.min(offset, this.input.round.duration_ns), kind, ...fields } })
  }

  startGame (packet) {
    if (this.game || packet.game_version !== VERSION || packet.dimension !== 'overworld' ||
        packet.player_gamemode !== 'creative' || packet.movement_authority !== 'client' ||
        packet.server_authoritative_inventory !== false || packet.server_authoritative_block_breaking !== false ||
        packet.block_pallete_checksum.toString() !== this.input.paletteChecksum ||
        !Array.isArray(packet.block_properties) || packet.block_properties.length !== 0 || !finitePosition(packet.player_position) ||
        !Array.isArray(packet.itemstates) || packet.itemstates.length > 8192) throw new Error('unsupported server profile')
    this.itemIds = new Map()
    for (const item of packet.itemstates) {
      if (this.itemIds.has(item.name)) throw new Error('duplicate item palette entry')
      this.itemIds.set(item.name, item.runtime_id)
    }
    this.game = true; this.entity = packet.runtime_entity_id; this.position = packet.player_position
  }

  observe (name, packet) {
    if (this.closed) return
    if (++this.packetSequence > 100000) throw new Error('packet bound')
    if (name === 'start_game') return this.startGame(packet)
    if (name === 'move_player' && String(packet.runtime_id) === String(this.entity)) {
      // This batch has no movement/teleport acknowledgement implementation.
      throw new Error('player movement invalidates stationary scenario')
    }
    if (name === 'inventory_content' && packet.window_id === 'inventory') {
      if (!Array.isArray(packet.input) || packet.input.length > 256) throw new Error('inventory bound')
      this.inventory.clear()
      packet.input.slice(0, 9).forEach((item, index) => this.inventory.set(index, item))
    } else if (name === 'inventory_slot' && packet.window_id === 'inventory') {
      if (packet.slot >= 0 && packet.slot < 9) this.inventory.set(packet.slot, packet.item)
    } else if (name === 'update_block') {
      if (packet.layer !== 0) return
      if (!finitePosition(packet.position) || !['x', 'y', 'z'].every(axis => Number.isInteger(packet.position[axis])) ||
          !Number.isInteger(packet.block_runtime_id) || !this.input.data.blocksByStateId[packet.block_runtime_id]) throw new Error('unknown block state')
      const target = key(packet.position)
      if (this.positions.has(target)) this.blocks.set(target, packet.block_runtime_id)
      const active = this.active
      if (!active || !active.sent || this.now() >= active.deadline || target !== key(active.action.target)) return
      if (packet.block_runtime_id !== active.action.after_state_id) {
        this.event('action_failed', { request_nonce: active.request.request_nonce, reason: 'action_rejected' })
      } else {
        this.event('action_confirmed', { request_nonce: active.request.request_nonce,
          confirmation: 'server_block_update', correlation: 'isolated_unique_target_transition', wire_request_id: null,
          target_sha256: active.request.target_sha256, before_state_sha256: active.request.before_state_sha256,
          after_state_sha256: active.request.after_state_sha256,
          observation_sha256: sha(JSON.stringify({ name, position: packet.position, state: packet.block_runtime_id,
            layer: packet.layer, packet_sequence: this.packetSequence })) })
      }
      this.settle()
    }
  }

  precondition (action, originalItem) {
    const item = this.inventory.get(action.hotbar_slot)
    if (!this.game || this.blocks.get(key(action.target)) !== action.before_state_id ||
        this.blocks.get(key(action.reference)) !== action.reference_state_id || !item ||
        item.network_id !== this.itemIds.get('minecraft:' + action.item_name) || !Number.isInteger(item.count) || item.count < 1 ||
        item.metadata !== 0 || item.block_runtime_id !== action.after_state_id || item.extra?.has_nbt !== 0 ||
        item.extra.can_place_on?.length !== 0 || item.extra.can_destroy?.length !== 0 ||
        Math.hypot(...['x', 'y', 'z'].map(axis => this.position[axis] - action.reference[axis])) > 4.5 ||
        (originalItem && !isDeepStrictEqual(item, originalItem))) throw new Error('raw placement precondition missing or changed')
    return item
  }

  validateSend (active) {
    if (this.closed || this.active !== active || this.now() >= active.deadline) return false
    try { this.precondition(active.action, active.heldItem) } catch { return false }
    return true
  }

  beginSend (active) {
    if (active.sent || active.sending || !this.validateSend(active)) return false
    active.sending = true
    return true
  }

  completeSend (active) {
    if (!active.sending || active.sent || !this.validateSend(active)) return false
    active.sending = false; active.sent = true
    return true
  }

  async perform (request, action) {
    const started = this.now()
    if (this.closed || this.active || started < request.planned_offset_ns || started + request.timeout_ns > this.input.round.duration_ns) throw new Error('outside schedule')
    let resolve
    const done = new Promise(finish => { resolve = finish })
    const active = { request, action, deadline: started + request.timeout_ns, sent: false, sending: false, resolve }
    this.active = active
    this.event('action_started', { request_nonce: request.request_nonce }, started)
    const expire = () => {
      if (this.active !== active) return
      const remaining = active.deadline - this.now()
      if (remaining > 0) active.timer = setTimeout(expire, Math.ceil(remaining / 1e6))
      else this.close('adapter_error') // reducer expires the original deadline before cancellation
    }
    active.timer = setTimeout(expire, Math.ceil(request.timeout_ns / 1e6))
    try {
      // Independent full snapshot preserves Buffer/NBT/stack fields without
      // retaining a mutable decoder object; final socket send compares all fields.
      const item = deserialize(serialize(this.precondition(action)))
      active.heldItem = deserialize(serialize(item))
      this.transport.write(active, 'mob_equipment', { runtime_entity_id: this.entity, item,
        slot: action.hotbar_slot, selected_slot: action.hotbar_slot, window_id: 'inventory' })
      this.transport.write(active, 'inventory_transaction', { transaction: {
        legacy: { legacy_request_id: 0 }, transaction_type: 'item_use', actions: [], transaction_data: {
          action_type: 'click_block', block_position: action.reference, face: faceId(action.face), hotbar_slot: action.hotbar_slot,
          held_item: item, player_pos: this.position, click_pos: { x: 0.5 + action.face.x * 0.5,
            y: 0.5 + action.face.y * 0.5, z: 0.5 + action.face.z * 0.5 }, block_runtime_id: action.reference_state_id
        }
      } })
    } catch {
      if (this.active === active && !this.closed) {
        this.event('action_failed', { request_nonce: request.request_nonce, reason: 'action_failed' }); this.settle()
      }
    }
    return done
  }

  settle () {
    const active = this.active
    if (!active) return
    this.active = null; clearTimeout(active.timer); active.resolve()
  }

  close (reason = 'adapter_error') {
    if (this.closed) return
    this.closed = true; this.reason = reason
    if (reason === 'disconnected') this.event('session_closed')
    else if (this.active) this.event('action_cancelled', { request_nonce: this.active.request.request_nonce })
    this.settle(); this.transport?.close(); this.onClose?.()
  }
}
module.exports = { Session, key, faceId }
