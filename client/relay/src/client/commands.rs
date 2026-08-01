use super::*;

impl RelayClient {
    /// Send data to a peer via the relay.
    pub async fn send_data(&mut self, dst: &str, data: &[u8]) -> Result<()> {
        self.cmd_tx
            .try_send(ClientCommand::SendData {
                dst: dst.to_string(),
                data: data.to_vec(),
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    RelayError::Channel("command queue full".into())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    RelayError::Closed("relay write task stopped".into())
                }
            })
    }

    /// Send a ping to the relay server (to measure latency / keep alive).
    pub async fn ping(&mut self) -> Result<()> {
        self.cmd_tx
            .try_send(ClientCommand::Ping)
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    RelayError::Channel("command queue full".into())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    RelayError::Closed("relay write task stopped".into())
                }
            })
    }

    /// Close the connection gracefully.
    pub async fn close(&mut self) -> Result<()> {
        let _ = self.cmd_tx.try_send(ClientCommand::Close);
        Ok(())
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(ClientCommand::Close);
    }
}
