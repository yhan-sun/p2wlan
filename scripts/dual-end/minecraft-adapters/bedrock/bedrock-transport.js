'use strict'

// bedrock-protocol 3.60.1 encrypts each batch into one ordered cipher output.
// Bind that output to its originating action before the final send boundary.
// Dropping an expired ciphertext requires closing the stream (counter continuity).
class Transport {
  constructor (client, session) {
    this.client = client; this.session = session; this.pending = []; this.origin = null; this.output = null
    const encryptedBatch = client.sendEncryptedBatch
    const encryptedPacket = client.onEncryptedPacket
    client.sendEncryptedBatch = batch => {
      if (session.closed) return
      if (this.pending.length >= 128) { session.close('adapter_error'); return }
      this.pending.push({ owner: this.origin })
      try { return encryptedBatch.call(client, batch) } catch (error) { session.close('adapter_error'); throw error }
    }
    client.onEncryptedPacket = buffer => {
      const output = this.pending.shift()
      if (session.closed) return
      if (!output) { session.close('adapter_error'); return }
      this.output = output
      try { return encryptedPacket.call(client, buffer) } finally { this.output = null }
    }
    client.sendMCPE = (buffer, immediate) => {
      if (session.closed) return
      if (client.encryptionEnabled && !this.output) { session.close('adapter_error'); return }
      const owner = this.output ? this.output.owner : this.origin
      if (owner && !session.validateSend(owner.action)) { session.close('adapter_error'); return }
      if (client.status === 0 || client.connection?.connected === false) { session.close('disconnected'); return }
      // The pinned instance backend carries this origin to the actual connected
      // UDP send. Queue insertion here is never confirmation eligibility.
      try { return client.connection.sendReliable(buffer, true, owner) } catch { session.close('adapter_error') }
    }
    // Closed sessions cannot accumulate delayed upstream maintenance packets.
    const queue = client.queue
    client.queue = (name, packet) => {
      if (session.closed) return
      if (client.sendQ.length >= 128) { session.close('adapter_error'); return }
      return queue.call(client, name, packet)
    }
  }

  write (owner, name, packet) {
    if (this.session.closed) return
    if (this.origin) throw new Error('nested gameplay write')
    this.origin = owner ? Object.freeze({ action: owner, gameplay: name === 'inventory_transaction' }) : null
    try { this.client.write(name, packet) } finally { this.origin = null }
  }

  close () {
    this.pending.length = 0
    this.client.sendQ = []; this.client.sendIds = []
    this.client.close()
    this.client.cipher?.destroy(); this.client.decipher?.destroy()
  }
}
module.exports = { Transport }
