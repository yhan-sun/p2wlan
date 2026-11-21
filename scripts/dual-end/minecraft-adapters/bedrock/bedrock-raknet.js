'use strict'

const { Client: RaknetClient, EncapsulatedPacket, Reliability } = require('jsp-raknet')
const { sha } = require('./bedrock-input')

// jsp-raknet 2.1.3 speaks RakNet 10 and its public connect() retries five times
// across uncancellable sleeps. The fixed Bedrock 1.18.30 profile uses exactly
// one handshake, with listeners installed before the first datagram. This uses
// pinned version internals and must be revalidated before changing dependencies.
function singleHandshake (client, session) {
  const transport = client.connection
  Object.defineProperty(transport, 'connected', { get: () => Boolean(!session.closed &&
    transport.raknet?.running && transport.raknet?.connection?.state === 1) })
  transport.close = () => transport.raknet?.close()
  let origin = null
  transport.sendReliable = (buffer, immediate, owner = null) => {
    const raknet = transport.raknet
    if (session.closed || !transport.connected || !raknet?.connection) return
    const packet = new EncapsulatedPacket()
    packet.reliability = Reliability.ReliableOrdered; packet.buffer = buffer
    // One gameplay ciphertext must have one actual datagram completion. Never
    // grant credit to a partial split; this fixed no-NBT profile is small.
    if (owner?.gameplay && packet.getTotalLength() + 4 > raknet.connection.mtuSize) { session.close('adapter_error'); return }
    if (origin) { session.close('adapter_error'); return }
    origin = { owner, attempted: false }
    try { raknet.connection.addEncapsulatedToQueue(packet, 1) } finally { origin = null }
  }
  transport.connect = () => {
    if (session.closed) return
    const raknet = new RaknetClient(client.options.host, client.options.port)
    transport.raknet = raknet
    const handle = raknet.handle.bind(raknet)
    let received = 0; let pendingSends = 0
    // The pinned recoveryList resends the same Buffer object. Metadata follows
    // that datagram's lifetime, never a later write's temporary origin. Weak keys
    // add no independently retained registry after recovery/socket release.
    const datagrams = new WeakMap()
    raknet.sendBuffer = buffer => {
      if (session.closed || !raknet.running) return
      if (pendingSends >= 128) { session.close('adapter_error'); return }
      const current = origin; let datagram = datagrams.get(buffer)
      const owner = datagram ? datagram.owner : current?.owner
      const changed = datagram && datagram.digest !== sha(buffer)
      const invalidOwner = owner && !session.validateSend(owner.action)
      const firstGameplay = !datagram && owner?.gameplay
      if (changed || invalidOwner || (firstGameplay &&
          (current.attempted || !session.beginSend(owner.action)))) { session.close('adapter_error'); return }
      if (!datagram) {
        datagram = Object.freeze({ owner, digest: sha(buffer), completion: { done: false } })
        datagrams.set(buffer, datagram)
        if (owner?.gameplay) current.attempted = true
      }
      try {
        // Connected UDP has no per-send DNS/implicit bind work. The original
        // action fence is immediately before the native socket side effect.
        pendingSends++
        raknet.socket.send(buffer, (error, bytes) => {
          pendingSends--
          if (session.closed) return
          if (error || bytes !== buffer.length || datagram.digest !== sha(buffer)) { session.close('adapter_error'); return }
          // Any successful original-datagram completion may finish its pending
          // handoff once. Later successes cannot credit a newer action; errors
          // still fail closed even if another native completion arrived first.
          if (owner?.gameplay && !datagram.completion.done) {
            if (!session.completeSend(owner.action)) { session.close('adapter_error'); return }
            datagram.completion.done = true
          }
        })
      } catch { pendingSends--; session.close('adapter_error') }
    }
    raknet.handle = (buffer, address) => {
      if (session.closed) return
      if (++received > 100000 || buffer.length > 65535) { session.close('adapter_error'); return }
      // Ignore foreign UDP sources rather than feeding them to this connection.
      if (address.address !== client.options.host || address.port !== client.options.port) return
      try { handle(buffer, address) } catch { session.close('adapter_error') }
    }
    raknet.on('error', () => session.close('adapter_error'))
    raknet.socket.on('error', () => session.close('adapter_error'))
    raknet.on('connected', () => { if (!session.closed) transport.onConnected() })
    raknet.on('encapsulated', (packet, address) => { if (!session.closed) transport.onEncapsulated(packet, address.hash) })
    raknet.on('disconnect', reason => { if (!session.closed) transport.onCloseConnection(reason) })
    // UDP connect itself emits no packet. Wait for it before the single wire
    // handshake so later native sends have no asynchronous address lookup.
    raknet.socket.once('connect', () => {
      if (session.closed || !raknet.running) return
      raknet.sendConnectionRequest()
      let ticks = 0
      raknet.int = setInterval(() => {
        if (session.closed || !raknet.running) return
        try {
          raknet.connection?.update(Date.now())
          if (++ticks % 100 === 0 && transport.connected) raknet.connection?.sendConnectedPing()
        } catch { session.close('adapter_error') }
      }, 10)
    })
    raknet.socket.connect(client.options.port, client.options.host)
  }
}
module.exports = { singleHandshake }
