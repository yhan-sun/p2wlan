'use strict'

// Test-only startup cancellation of the original run() and native UDP socket.
// This controls AbortController delivery, not operating-system signal delivery.
const dgram = require('node:dgram')
const { run } = require('./bedrock-adapter')
const { validate, parseStrict, MAX_BYTES } = require('./bedrock-input')

async function main () {
  if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error('fixture usage')
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
  const originalSend = dgram.Socket.prototype.send
  const originalEmit = dgram.Socket.prototype.emit
  let socket; let closed; let nativeSendReturns = 0; let cancellations = 0; let socketClosed = false
  dgram.Socket.prototype.send = function (buffer, ...args) {
    const result = originalSend.call(this, buffer, ...args)
    if (Buffer.isBuffer(buffer) && buffer[0] === 5) {
      const address = this.remoteAddress()
      if (address.address !== input.config.host || address.port !== input.config.port || socket) throw new Error('fixture handshake identity')
      socket = this; nativeSendReturns++
      closed = new Promise(resolve => socket.once('close', () => { socketClosed = true; resolve() }))
    }
    return result
  }
  dgram.Socket.prototype.emit = function (name, ...args) {
    const result = originalEmit.call(this, name, ...args)
    if (name === 'connect' && this === socket && nativeSendReturns === 1) {
      // The original connect listener sends Request1 and then installs its tick.
      // Cancel after that listener returns, in this same native event call stack;
      // cancelling inside send() would inject reentry before the tick is owned.
      cancellations++
      controller.abort()
    }
    return result
  }
  console.log = () => {}
  let outputBytes = 0
  try {
    await run(input, value => {
      const line = JSON.stringify(value) + '\n'
      outputBytes += Buffer.byteLength(line)
      if (outputBytes > 4 * 1024 * 1024) throw new Error('stdout byte bound')
      process.stdout.write(line)
    }, controller.signal)
    if (closed) await closed
  } finally {
    dgram.Socket.prototype.send = originalSend
    dgram.Socket.prototype.emit = originalEmit
  }
  process.stderr.write(JSON.stringify({ scope: 'test_only_native_udp_run_cancellation_not_os_signal',
    native_send_returns: nativeSendReturns, synchronous_cancellations: cancellations,
    abort_signal_delivered: controller.signal.aborted, original_socket_closed: socketClosed,
    wrappers_restored: dgram.Socket.prototype.send === originalSend &&
      dgram.Socket.prototype.emit === originalEmit }) + '\n')
}
main().catch(() => { process.stderr.write('startup cancellation fixture failed\n'); process.exitCode = 2 })
