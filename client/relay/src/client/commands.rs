use super::*;

impl RelayClient {
    /// Send data to a peer via the relay.
    pub async fn send_data(&self, dst: &str, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let queued_at = std::time::Instant::now();
        let queue_remaining_before = self.cmd_tx.capacity();
        let queue_capacity = self.cmd_tx.max_capacity();
        let (completion_tx, completion_rx) = oneshot::channel();
        if let Err(error) = self.cmd_tx.try_send(ClientCommand::SendData {
            dst: dst.to_string(),
            data: data.to_vec(),
            completion: completion_tx,
        }) {
            let (reason_code, relay_error) = match error {
                mpsc::error::TrySendError::Full(_) => {
                    ("relay_command_queue_full", RelayError::CommandQueueFull)
                }
                mpsc::error::TrySendError::Closed(_) => (
                    "relay_writer_stopped_before_accept",
                    RelayError::WriterStoppedBeforeAccept,
                ),
            };
            warn!(
                event = "relay_writer_queue_rejected",
                peer_id = %dst,
                bytes = data_len,
                queue_capacity,
                queue_remaining = queue_remaining_before,
                reason_code,
                "relay writer command was not accepted locally"
            );
            return Err(relay_error);
        }
        debug!(
            event = "relay_writer_queue_accepted",
            peer_id = %dst,
            bytes = data_len,
            queue_capacity,
            queue_remaining = self.cmd_tx.capacity(),
            "relay writer command accepted locally; this is not a peer-delivery acknowledgement"
        );

        match completion_rx.await {
            Ok(result) => {
                debug!(
                    event = "relay_writer_completion_received",
                    peer_id = %dst,
                    bytes = data_len,
                    queue_capacity,
                    queue_wait_ms = queued_at.elapsed().as_millis() as u64,
                    write_succeeded = result.is_ok(),
                    "relay writer completion received; success still means local write_all only"
                );
                result
            }
            Err(_) => {
                warn!(
                    event = "relay_writer_completion_missing",
                    peer_id = %dst,
                    bytes = data_len,
                    queue_capacity,
                    queue_wait_ms = queued_at.elapsed().as_millis() as u64,
                    reason_code = "relay_writer_stopped_before_write",
                    "relay writer command was accepted but no write completion arrived"
                );
                Err(RelayError::WriterStoppedBeforeWrite)
            }
        }
    }

    /// Send a ping to the relay server (to measure latency / keep alive).
    pub async fn ping(&self) -> Result<()> {
        self.cmd_tx
            .try_send(ClientCommand::Ping)
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => RelayError::CommandQueueFull,
                mpsc::error::TrySendError::Closed(_) => RelayError::WriterStoppedBeforeAccept,
            })
    }

    /// Close the connection gracefully.
    pub async fn close(&self) -> Result<()> {
        // A graceful close is still a lifecycle boundary. Sending a Close
        // command through the same queue as data could wait forever behind a
        // blocked write, so wake the writer directly.
        self.abort();
        Ok(())
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        // Do not enqueue Close: the writer may be blocked in write_all and a
        // queued Close would never be observed.  Drop is a hard lifecycle
        // boundary, so wake the writer directly.
        self.abort();
    }
}
