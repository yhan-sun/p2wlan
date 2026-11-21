#!/usr/bin/env node
'use strict'

// Explicit adapter for fixed Java 1.20.4 offline sessions. Invoke with --config
// /absolute/config.json and the supervisor's frozen envelope on stdin. No game
// installation, online authentication, status probe, reconnect or retry occurs.
// Raw server packet observations remain self-reported evidence, never proof of
// genuine game execution, world reset, TUN, Direct or a performance gain.
const mineflayer = require('mineflayer')
const { validate, parseStrict, MAX_BYTES } = require('./java-input')
const { Session } = require('./java-session')

async function run (input, emit, signal, createBot = mineflayer.createBot) {
  const epoch = process.hrtime.bigint()
  const now = () => Number(process.hrtime.bigint() - epoch)
  const session = new Session(input, emit, now)
  let totalTimer; let connectTimer; let bot; let wake; let readyResolve
  const wait = ms => new Promise(resolve => {
    const timer = setTimeout(() => { wake = null; resolve() }, ms)
    wake = () => { clearTimeout(timer); wake = null; resolve() }
  })
  const stop = reason => { session.close(reason); wake?.(); readyResolve?.() }
  const abort = () => stop('interrupted')
  let termination = 'adapter_error'
  try {
    if (signal?.aborted) { stop('interrupted'); termination = 'interrupted'; return }
    signal?.addEventListener('abort', abort, { once: true })
    const expireRound = () => {
      const remaining = input.round.duration_ns - now()
      if (remaining > 0) totalTimer = setTimeout(expireRound, Math.ceil(remaining / 1e6))
      else stop('duration_deadline')
    }
    expireRound()
    bot = createBot({ host: input.config.host, port: input.config.port, username: input.config.username,
      version: input.config.version, auth: 'offline', hideErrors: true, physicsEnabled: false,
      respawn: false, checkTimeoutInterval: input.config.connect_timeout_ms, closeTimeout: 1000 })
    session.attach(bot)
    bot.on('error', () => stop('adapter_error'))
    bot.on('end', () => stop('disconnected'))
    bot.on('kicked', () => stop('disconnected'))
    bot.on('death', () => stop('disconnected'))
    const ready = new Promise(resolve => {
      readyResolve = resolve
      bot.once('spawn', () => { clearTimeout(connectTimer); if (!session.closed) session.event('session_ready'); resolve() })
      connectTimer = setTimeout(() => { stop('adapter_error'); resolve() }, input.config.connect_timeout_ms)
    })
    await ready
    clearTimeout(connectTimer)
    for (let i = 0; i < input.round.requests.length && !session.closed; i++) {
      const request = input.round.requests[i]
      while (now() < request.planned_offset_ns && !session.closed) await wait(Math.ceil((request.planned_offset_ns - now()) / 1e6))
      if (session.closed) break
      if (now() + request.timeout_ns > input.round.duration_ns) {
        while (now() < input.round.duration_ns && !session.closed) await wait(Math.ceil((input.round.duration_ns - now()) / 1e6))
        if (!session.closed) stop('duration_deadline')
        break
      }
      await session.perform(request, input.actions[i])
    }
    termination = session.closed ? session.reason === 'duration_deadline' ? 'duration_deadline'
      : session.reason === 'interrupted' ? 'interrupted' : 'adapter_error' : 'completed'
  } finally {
    clearTimeout(totalTimer); clearTimeout(connectTimer); wake?.()
    signal?.removeEventListener('abort', abort)
    session.dispose()
    const elapsed = Math.min(now(), input.round.duration_ns)
    emit({ type: 'finish', elapsed_ns: elapsed, termination,
      telemetry: Object.fromEntries(Object.entries(input.contract.telemetry_units).map(([name, unit]) => [name,
        { value: null, unit, reason: 'not_collected', source_sha256: null, clock_nonce: null, start_offset_ns: null, end_offset_ns: null }])) })
  }
}

async function main () {
  if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error('usage: java-adapter.js --config /absolute/config.json')
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
  let outputBytes = 0
  try {
    await run(input, value => {
      const line = JSON.stringify(value) + '\n'
      outputBytes += Buffer.byteLength(line)
      if (outputBytes > 4 * 1024 * 1024) throw new Error('stdout byte limit')
      process.stdout.write(line)
    }, controller.signal)
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel) }
}
if (require.main === module) main().catch(() => { process.stderr.write('java adapter rejected input or execution failed\n'); process.exitCode = 2 })
module.exports = { run }
