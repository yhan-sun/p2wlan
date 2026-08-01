/// Read and validate the first frame from a new connection.
async fn read_first_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    config: &RelayServerConfig,
    shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    dup_shutdown_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> std::result::Result<Frame, (RelayError, Option<NetworkNodeKey>)> {
    let first_frame_fut = async {
        let mut buf = [0u8; FRAME_HEADER_SIZE + MAX_NODE_ID_LEN];
        reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]).await?;
        if buf[..4] != MAGIC {
            return Err(RelayError::InvalidMagic);
        }
        let version = buf[4];
        if version != VERSION {
            return Err(RelayError::UnsupportedVersion(version));
        }
        let msg_type = buf[5];
        let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        if payload_len > config.max_frame_payload {
            return Err(RelayError::FrameTooLarge(
                payload_len,
                config.max_frame_payload,
            ));
        }

        // For MSG_AUTH_REGISTER, payload could be larger; use a dynamic buffer
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload).await?;
        }
        Ok(Frame::new(msg_type, payload))
    };

    match tokio::select! {
        _ = shutdown_rx.recv() => {
            Err((RelayError::Closed("shutdown".into()), None))
        }
        _ = dup_shutdown_rx => {
            Err((RelayError::Closed("duplicate".into()), None))
        }
        res = tokio::time::timeout(config.register_timeout, first_frame_fut) => match res {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(e)) => Err((e, None)),
            Err(_) => Err((RelayError::Timeout("registration timed out".into()), None)),
        }
    } {
        Ok(frame) => Ok(frame),
        Err((e, key)) => Err((e, key)),
    }
}
