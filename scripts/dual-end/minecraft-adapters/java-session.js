'use strict'

// Version-pinned raw game-packet attribution. Local world events and the
// Mineflayer placement promise never count as application acknowledgements.
const { Vec3 } = require('vec3')
const { sha } = require('./java-input')
const same = (a, b) => a && a.x === b.x && a.y === b.y && a.z === b.z
const direction = face => face.y < 0 ? 0 : face.y > 0 ? 1 : face.z < 0 ? 2 : face.z > 0 ? 3 : face.x < 0 ? 4 : 5

function changes (name, packet) {
  if (name === 'block_change') return [{ position: packet.location, state: packet.type }]
  if (name !== 'multi_block_change' || !Array.isArray(packet.records) || packet.records.length > 4096) throw new Error('invalid block update')
  const chunk = packet.chunkCoordinates
  if (!chunk || !['x', 'y', 'z'].every(axis => Number.isSafeInteger(chunk[axis]))) throw new Error('invalid section coordinates')
  return packet.records.map(record => {
    if (!Number.isSafeInteger(record) || record < 0 || record > 0x7fffffff) throw new Error('invalid packed block state')
    return { position: { x: chunk.x * 16 + ((record >> 8) & 15),
      y: chunk.y * 16 + (record & 15), z: chunk.z * 16 + ((record >> 4) & 15) }, state: record >> 12 }
  })
}

class Session {
  constructor (input, emit, now) {
    this.input = input; this.emit = emit; this.now = now
    this.sequence = 0; this.packetSequence = 0; this.active = null; this.closed = false
    this.source = { run_nonce: input.plan.run_nonce }
    for (const name of ['round_nonce', 'adapter_nonce', 'session_nonce', 'clock_nonce']) this.source[name] = input.round[name]
  }

  event (kind, fields = {}, offset = this.now()) {
    if (this.sequence >= this.input.contract.max_events_per_round) throw new Error('event budget exhausted')
    this.emit({ type: 'event', event: { ...this.source, event_seq: this.sequence++,
      offset_ns: Math.min(offset, this.input.round.duration_ns), kind, ...fields } })
  }

  attach (bot) {
    this.bot = bot
    this.originalWrite = bot._client.write
    this.write = (name, packet) => {
      if (name === 'block_place') {
        const active = this.active
        if (this.closed || !active || active.sent || this.now() >= active.deadline ||
            !same(packet.location, active.action.reference) || packet.direction !== direction(active.action.face) ||
            packet.hand !== 0) throw new Error('placement send lost original request ownership')
        active.sent = true
      }
      return this.originalWrite.call(bot._client, name, packet)
    }
    bot._client.write = this.write
    this.listeners = ['block_change', 'multi_block_change'].map(name => {
      const listener = packet => {
        try { this.observe(name, packet) } catch { this.close('adapter_error') }
      }
      bot._client.on(name, listener)
      return [name, listener]
    })
  }

  observe (name, packet) {
    if (++this.packetSequence > 100000) throw new Error('block update budget exhausted')
    const active = this.active
    if (this.closed || !active || !active.sent || this.now() >= active.deadline) return
    const updates = changes(name, packet)
    for (const update of updates) {
      if (!update.position || !['x', 'y', 'z'].every(axis => Number.isSafeInteger(update.position[axis])) ||
          !Number.isSafeInteger(update.state) || !this.input.data.blocksByStateId[update.state]) throw new Error('invalid server block state')
    }
    // One decoded server packet is one observation: record array order is not
    // a separate receive-time ordering. Contradictory state within that same
    // batch must not confirm a transition from its first matching record.
    const references = updates.filter(update => same(update.position, active.action.reference))
    if (references.length) active.referenceAck = references.every(update => update.state === active.action.reference_state_id)
    const targets = updates.filter(update => same(update.position, active.action.target))
    if (!active.referenceAck || !targets.length) return
    if (targets.some(update => update.state !== active.action.after_state_id)) {
      this.event('action_failed', { request_nonce: active.request.request_nonce, reason: 'action_rejected' })
    } else {
      this.event('action_confirmed', { request_nonce: active.request.request_nonce,
        confirmation: 'server_block_update', correlation: 'isolated_unique_target_transition', wire_request_id: null,
        target_sha256: active.request.target_sha256, before_state_sha256: active.request.before_state_sha256,
        after_state_sha256: active.request.after_state_sha256,
        observation_sha256: sha(JSON.stringify({ name, updates, packet_sequence: this.packetSequence })) })
    }
    this.settle()
  }

  settle () {
    const active = this.active
    if (!active) return
    this.active = null; clearTimeout(active.timer); active.resolve()
  }

  async perform (request, action) {
    const started = this.now()
    if (this.closed || this.active || started < request.planned_offset_ns ||
        started + request.timeout_ns > this.input.round.duration_ns) throw new Error('action outside original schedule')
    let resolve
    const done = new Promise(finish => { resolve = finish })
    this.active = { request, action, deadline: started + request.timeout_ns, sent: false, referenceAck: false, resolve }
    const active = this.active
    this.event('action_started', { request_nonce: request.request_nonce }, started)
    const expire = () => {
      if (this.active !== active) return
      const remaining = active.deadline - this.now()
      if (remaining > 0) { active.timer = setTimeout(expire, Math.ceil(remaining / 1e6)); return }
      // No invented timeout event: the next event/finish's same-clock offset
      // lets the strict reducer expire the original request deadline exactly.
      this.settle()
    }
    active.timer = setTimeout(expire, Math.ceil(request.timeout_ns / 1e6))
    try {
      const bot = this.bot
      const target = bot.blockAt(new Vec3(action.target.x, action.target.y, action.target.z))
      const reference = bot.blockAt(new Vec3(action.reference.x, action.reference.y, action.reference.z))
      const item = bot.inventory.slots[36 + action.hotbar_slot]
      if (!target || target.stateId !== action.before_state_id || !reference || reference.stateId !== action.reference_state_id ||
          !item || item.name !== action.item_name || item.count < 1 || bot.entity.position.distanceTo(reference.position) > 4.5) throw new Error('placement precondition not observed')
      bot.setQuickBarSlot(action.hotbar_slot)
      // Mineflayer 4.39.0 _genericPlace sends exactly one placement. The public
      // placeBlock wrapper adds its own 5s world-event promise; that promise is
      // neither our deadline nor a raw server-packet confirmation.
      Promise.resolve(bot._genericPlace(reference, new Vec3(action.face.x, action.face.y, action.face.z), { forceLook: true }))
        .catch(() => this.fail(active))
    } catch { this.fail(active) }
    await done
  }

  fail (active) {
    if (this.active !== active || this.closed) return
    this.event('action_failed', { request_nonce: active.request.request_nonce, reason: 'action_failed' })
    this.settle()
  }

  close (reason = 'adapter_error') {
    if (this.closed) return
    this.closed = true; this.reason = reason
    if (reason === 'disconnected') this.event('session_closed')
    else if (this.active) this.event('action_cancelled', { request_nonce: this.active.request.request_nonce })
    this.settle()
  }

  dispose () {
    this.close()
    for (const [name, listener] of this.listeners || []) this.bot._client.removeListener(name, listener)
    // Keep the fencing wrapper until the client is destroyed: an outstanding
    // lookAt promise must never regain an unfenced write after cancellation.
    this.bot?._client.socket?.destroy()
    this.bot?.end()
  }
}
module.exports = { Session, changes, direction }
