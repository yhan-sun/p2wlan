'use strict'
const test = require('node:test'); const assert = require('node:assert/strict')
const dgram = require('node:dgram'); const { once } = require('node:events')
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path')
const { spawn } = require('node:child_process')
const { fixture } = require('./fixture-input')
for (const mode of ['connect-timeout', 'startup-cancel', 'long-connect-timeout']) test(`native owned UDP ${mode}: one handshake, no retry or leaked child`, { timeout: 5000 }, async t => {
  const end = performance.now() + 5000
  const socket = dgram.createSocket('udp4'); socket.bind(0, '127.0.0.1'); await once(socket, 'listening')
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bedrock-lifecycle-'))
  let child; let childClosed; let socketClosed = false; let childCloseCollected = false; let timer; let code; let signal
  const cleanupErrors = []
  socket.once('close', () => { socketClosed = true })
  const collect = async (completion, name) => {
    const remaining = end - performance.now()
    if (remaining <= 0) { cleanupErrors.push(name + '_original_test_deadline'); return }
    let deadlineTimer
    try {
      const complete = await Promise.race([completion.then(() => true), new Promise(resolve => {
        deadlineTimer = setTimeout(() => resolve(false), remaining)
      })])
      if (!complete) cleanupErrors.push(name + '_original_test_deadline')
    } catch (error) { cleanupErrors.push(name + ': ' + String(error)) } finally { clearTimeout(deadlineTimer) }
  }
  const cleanup = async () => {
    clearTimeout(timer)
    try { if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL') } catch (error) { cleanupErrors.push('child_kill: ' + String(error)) }
    if (childClosed && !childCloseCollected) await collect(childClosed, 'child_close')
    if (!socketClosed) {
      try {
        const closed = once(socket, 'close'); socket.close(); await collect(closed, 'socket_close')
      } catch (error) { cleanupErrors.push('socket_close: ' + String(error)) }
    }
    try { fs.rmSync(directory, { recursive: true, force: true }) } catch (error) { cleanupErrors.push('fixture_remove: ' + String(error)) }
  }
  t.after(cleanup)
  const f = fixture(directory, socket.address().port)
  f.config.connect_timeout_ms = mode === 'long-connect-timeout' ? 1800 : 100; f.save()
  const entry = mode === 'startup-cancel' ? 'fixture-startup-cancel.js' : 'bedrock-adapter.js'
  child = spawn(process.execPath, [path.join(__dirname, entry), '--config', f.configPath], { stdio: ['pipe', 'pipe', 'pipe'] })
  childClosed = new Promise(resolve => child.once('close', (exitCode, exitSignal) => {
    code = exitCode; signal = exitSignal; childCloseCollected = true; resolve()
  }))
  const datagrams = []; const output = []; const diagnostics = []
  let receivedResolve
  const received = new Promise(resolve => { receivedResolve = resolve })
  socket.on('message', data => { datagrams.push(data); receivedResolve() })
  child.stdout.on('data', b => output.push(b)); child.stderr.on('data', b => diagnostics.push(b))
  child.on('error', error => diagnostics.push(Buffer.from(String(error))))
  child.stdin.end(JSON.stringify(f.envelope))
  let deadlineExpired = false
  const deadline = new Promise(resolve => {
    timer = setTimeout(() => { deadlineExpired = true; if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); resolve() }, 2500)
  })
  try {
    await Promise.race([Promise.all([childClosed, received]), deadline])
    if (!childCloseCollected) await collect(childClosed, 'child_close_body')
  } finally { await cleanup() }
  // Every outcome, including a failed counterfactual, is asserted after the
  // original child was actually collected and the owned socket was closed.
  assert.deepEqual(cleanupErrors, [])
  assert.equal(childCloseCollected, true); assert.equal(socketClosed, true)
  assert.equal(fs.existsSync(directory), false)
  assert.equal(deadlineExpired, false, Buffer.concat(diagnostics).toString())
  assert.equal(signal, null, Buffer.concat(diagnostics).toString()); assert.equal(code, 0, Buffer.concat(diagnostics).toString())
  assert.equal(datagrams.length, 1)
  assert.equal(datagrams[0][0], 5) // actual OpenConnectionRequest1, not a status ping
  const rows = Buffer.concat(output).toString().trim().split('\n').map(JSON.parse)
  assert.equal(rows.length, 1); assert.equal(rows[0].type, 'finish')
  const observed = mode === 'startup-cancel' ? JSON.parse(Buffer.concat(diagnostics).toString()) : null
  assert.equal(rows[0].termination, mode === 'startup-cancel' ? 'interrupted' : 'adapter_error', JSON.stringify({
    child_close_collected: childCloseCollected, child_exit_code: code, child_signal: signal, owned_socket_closed: socketClosed,
    fixture_directory_absent: !fs.existsSync(directory), received_datagrams: datagrams.length, fixture: observed
  }))
  if (mode === 'startup-cancel') {
    assert.equal(observed.scope, 'test_only_native_udp_run_cancellation_not_os_signal')
    assert.equal(observed.native_send_returns, 1); assert.equal(observed.synchronous_cancellations, 1)
    assert.equal(observed.abort_signal_delivered, true)
    assert.equal(observed.original_socket_closed, true); assert.equal(observed.wrappers_restored, true)
  }
})
