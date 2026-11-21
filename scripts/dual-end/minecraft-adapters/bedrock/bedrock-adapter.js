#!/usr/bin/env node
'use strict'

// Fixed offline 1.18.30 adapter. Server/world identity and raw observations are
// self-reported, never authentication of genuine Minecraft, TUN or Direct.
const { Client } = require('bedrock-protocol')
const { validate, parseStrict, MAX_BYTES } = require('./bedrock-input')
const { Session } = require('./bedrock-session')
const { Transport } = require('./bedrock-transport')
const { singleHandshake } = require('./bedrock-raknet')

async function run (input, emit, signal) {
  const epoch = process.hrtime.bigint()
  const now = () => Number(process.hrtime.bigint() - epoch)
  const session = new Session(input, emit, now)
  let totalTimer; let connectTimer; let wake; let readyResolve
  const wait = ms => new Promise(resolve => {
    const timer = setTimeout(() => { wake = null; resolve() }, ms)
    wake = () => { clearTimeout(timer); wake = null; resolve() }
  })
  session.onClose = () => { wake?.(); readyResolve?.() }
  const abort = () => session.close('interrupted')
  let termination = 'adapter_error'
  try {
    if (signal?.aborted) { session.close('interrupted'); termination = 'interrupted'; return }
    signal?.addEventListener('abort', abort, { once: true })
    const expire = () => {
      const remaining = input.round.duration_ns - now()
      if (remaining > 0) totalTimer = setTimeout(expire, Math.ceil(remaining / 1e6))
      else session.close('duration_deadline')
    }
    expire()
    const client = new Client({ host: input.config.host, port: input.config.port, username: input.config.username,
      version: input.config.version, offline: true, transport: 'raknet', raknetBackend: 'jsp-raknet',
      useRaknetWorkers: false, delayedInit: true, connectTimeout: input.config.connect_timeout_ms, conLog: null })
    session.transport = new Transport(client, session)
    // Upstream defers inbound parsing to nextTick; close must fence that work too.
    const handle = client.handle.bind(client)
    client.handle = buffer => { if (!session.closed) handle(buffer) }
    const control = (name, packet) => session.transport.write(null, name, packet)
    const safe = fn => packet => { if (!session.closed) { try { fn(packet) } catch { session.close('adapter_error') } } }
    for (const name of ['start_game', 'move_player', 'inventory_content', 'inventory_slot', 'update_block']) {
      client.on(name, safe(packet => session.observe(name, packet)))
    }
    client.on('error', () => session.close('adapter_error'))
    client.on('close', () => session.close('disconnected'))
    client.on('kick', () => session.close('disconnected'))
    client.on('change_dimension', () => session.close('disconnected'))
    client.on('respawn', () => session.close('disconnected'))
    client.on('resource_packs_info', safe(packet => {
      if (packet.must_accept || packet.behaviour_packs.length || packet.texture_packs.length) throw new Error('resource packs unsupported')
      control('resource_pack_client_response', { response_status: 'completed', resourcepackids: [] })
    }))
    client.on('resource_pack_stack', safe(packet => {
      if (packet.must_accept || packet.behavior_packs.length || packet.resource_packs.length) throw new Error('resource packs unsupported')
      control('resource_pack_client_response', { response_status: 'completed', resourcepackids: [] })
      control('client_cache_status', { enabled: false })
      control('request_chunk_radius', { chunk_radius: 1, max_radius: 1 })
    }))
    client.on('network_stack_latency', safe(packet => {
      if (packet.needs_response) control('network_stack_latency', { timestamp: packet.timestamp, needs_response: false })
    }))
    const ready = new Promise(resolve => {
      readyResolve = resolve
      client.once('spawn', safe(() => {
        if (!session.game) throw new Error('start_game missing')
        clearTimeout(connectTimer); session.event('session_ready'); resolve()
      }))
      connectTimer = setTimeout(() => session.close('adapter_error'), input.config.connect_timeout_ms)
    })
    client.once('connect_allowed', safe(() => { singleHandshake(client, session); client.connect() }))
    client.init()
    await ready
    clearTimeout(connectTimer)
    for (let i = 0; i < input.round.requests.length && !session.closed; i++) {
      const request = input.round.requests[i]
      while (now() < request.planned_offset_ns && !session.closed) await wait(Math.ceil((request.planned_offset_ns - now()) / 1e6))
      if (session.closed) break
      if (now() + request.timeout_ns > input.round.duration_ns) {
        while (now() < input.round.duration_ns && !session.closed) await wait(Math.ceil((input.round.duration_ns - now()) / 1e6))
        if (!session.closed) session.close('duration_deadline')
        break
      }
      await session.perform(request, input.actions[i])
    }
    termination = session.closed ? session.reason === 'duration_deadline' ? 'duration_deadline'
      : session.reason === 'interrupted' ? 'interrupted' : 'adapter_error' : 'completed'
  } finally {
    clearTimeout(totalTimer); clearTimeout(connectTimer); wake?.()
    signal?.removeEventListener('abort', abort)
    session.close()
    emit({ type: 'finish', elapsed_ns: Math.min(now(), input.round.duration_ns), termination,
      telemetry: Object.fromEntries(Object.entries(input.contract.telemetry_units).map(([name, unit]) => [name,
        { value: null, unit, reason: 'not_collected', source_sha256: null, clock_nonce: null, start_offset_ns: null, end_offset_ns: null }])) })
  }
}

async function main () {
  if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error('usage: bedrock-adapter.js --config /absolute/config.json')
  let length = 0; const chunks = []
  const inputTimer = setTimeout(() => process.stdin.destroy(new Error('stdin deadline')), 5000)
  try {
    for await (const chunk of process.stdin) {
      length += chunk.length
      if (length > MAX_BYTES) throw new Error('stdin byte limit')
      chunks.push(chunk)
    }
  } finally { clearTimeout(inputTimer) }
  const input = validate(parseStrict(Buffer.concat(chunks)), process.argv[3])
  const controller = new AbortController()
  const cancel = () => controller.abort()
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel)
  // Upstream jsp-raknet logs connection notices; stdout is reserved for NDJSON.
  console.log = () => {}
  let outputBytes = 0
  try {
    await run(input, value => {
      const line = JSON.stringify(value) + '\n'
      outputBytes += Buffer.byteLength(line)
      if (outputBytes > 4 * 1024 * 1024) throw new Error('stdout byte bound')
      process.stdout.write(line)
    }, controller.signal)
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel) }
}
if (require.main === module) main().catch(() => { process.stderr.write('bedrock adapter rejected input or execution failed\n'); process.exitCode = 2 })
module.exports = { run }
