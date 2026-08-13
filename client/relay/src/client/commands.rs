use super::*;

impl RelayClient {
    /// Send data to a peer via the relay.
    pub async fn send_data(&self, dst: &str, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let (completion_tx, completion_rx) = oneshot::channel();
        self.cmd_tx
            .try_send(ClientCommand::SendData {
                dst: dst.to_string(),
                data: data.to_vec(),
                completion: completion_tx,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => RelayError::CommandQueueFull,
                mpsc::error::TrySendError::Closed(_) => RelayError::WriterStoppedBeforeAccept,
            })?;
        debug!(
            event = "relay_writer_queue_accepted",
            peer_id = %dst,
            bytes = data_len,
            "relay writer command accepted locally; this is not a peer-delivery acknowledgement"
        );

        completion_rx
            .await
            .map_err(|_| RelayError::WriterStoppedBeforeWrite)?
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
