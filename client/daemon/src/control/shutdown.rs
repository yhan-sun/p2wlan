const CONTROL_SHUTDOWN_BUDGET: Duration = Duration::from_secs(3);

struct ControlShutdown {
    requested: watch::Sender<bool>,
    completed: watch::Receiver<bool>,
}

impl ControlShutdown {
    async fn stop(&self) -> Result<()> {
        self.requested.send_replace(true);
        let mut completed = self.completed.clone();
        timeout(CONTROL_SHUTDOWN_BUDGET, async {
            loop {
                if *completed.borrow_and_update() {
                    return Ok(());
                }
                if completed.changed().await.is_err() {
                    return Err(DaemonError::ControlPlane(
                        "control shutdown supervisor exited without confirmation".into(),
                    ));
                }
            }
        })
        .await
        .map_err(|_| {
            DaemonError::ControlPlane(
                "control shutdown exceeded its drain budget; presence lease will expire".into(),
            )
        })?
    }
}

impl Drop for ControlShutdown {
    fn drop(&mut self) {
        self.requested.send_replace(true);
    }
}

async fn control_shutdown_requested(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

struct ControlSupervisor {
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    done_tx: watch::Sender<bool>,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    http: RouteAwareControlHttpClient,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    health: Option<Arc<crate::tasks::HealthState>>,
    state: Arc<RwLock<ClientState>>,
}

struct ControlRuntimeTasks {
    ordinary: tokio::task::JoinHandle<()>,
    critical: tokio::task::JoinHandle<()>,
}

impl Drop for ControlRuntimeTasks {
    fn drop(&mut self) {
        self.ordinary.abort();
        self.critical.abort();
    }
}

impl ControlSupervisor {
    async fn run(mut self, mut tasks: ControlRuntimeTasks) {
        let (ordinary_completed, critical_completed) = tokio::select! {
            biased;
            _ = control_shutdown_requested(&mut self.shutdown_rx) => (false, false),
            _ = &mut tasks.ordinary => (true, false),
            _ = &mut tasks.critical => (false, true),
        };
        let registration_unknown = self.auth_rx.borrow().is_none();
        if !ordinary_completed && registration_unknown {
            let _ = timeout(Duration::from_millis(200), async {
                loop {
                    if self.auth_rx.borrow_and_update().is_some() {
                        break;
                    }
                    if self.auth_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }
        self.shutdown_tx.send_replace(true);
        tasks.ordinary.abort();
        let ordinary_quiesced = ordinary_completed
            || timeout(Duration::from_millis(250), &mut tasks.ordinary)
                .await
                .is_ok();
        let auth = self.auth_rx.borrow().clone();
        let critical_quiesced = critical_completed
            || timeout(Duration::from_millis(750), &mut tasks.critical)
                .await
                .is_ok();
        let quiesced = ordinary_quiesced && critical_quiesced;
        drop(tasks);

        if quiesced {
            if let Some(auth) = auth {
                let release = async {
                    let http = self.http.current()?;
                    release_presence(&http, &auth.base_url, &auth.token, &auth.self_node_id).await
                };
                match timeout(Duration::from_millis(1250), release).await {
                    Ok(Ok(())) => info!(reason_code = "presence_released", "Device presence released"),
                    Ok(Err(error)) => warn!(reason_code = "presence_release_unconfirmed", "Device presence release failed; lease expiry remains the fallback: {error}"),
                    Err(_) => warn!(reason_code = "presence_release_timeout", "Device presence release timed out; lease expiry remains the fallback"),
                }
            }
        } else {
            warn!(
                reason_code = "presence_drain_timeout",
                "Control workers did not quiesce in time; presence lease will expire"
            );
        }
        if let Some(health) = self.health.as_ref() {
            health.set_control_api_reachable(false);
            health.set_device_lease_healthy(false);
        }
        if let Ok(mut state) = timeout(Duration::from_millis(250), self.state.write()).await {
            state.registered = false;
        }
        let _ = self.event_tx.send(ControlEvent::Disconnected);
        self.done_tx.send_replace(true);
    }
}

#[cfg(test)]
mod shutdown_reliability_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn graceful_presence_release_bypasses_a_stalled_roster_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let roster_started = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = roster_started.clone();
        let releases = released.clone();
        let server = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        let started = started.clone();
                        let releases = releases.clone();
                        children.spawn(async move {
                            let mut bytes = Vec::new();
                            let mut chunk = [0u8; 2048];
                            while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                                let n = stream.read(&mut chunk).await.unwrap();
                                if n == 0 { return; }
                                bytes.extend_from_slice(&chunk[..n]);
                            }
                            let request = String::from_utf8_lossy(&bytes);
                            let body = if request.starts_with("POST /api/v1/devices/node-a/offline ") {
                                assert!(request.to_ascii_lowercase().contains("authorization: bearer test-token"));
                                releases.fetch_add(1, Ordering::AcqRel);
                                r#"{"success":true}"#
                            } else if request.starts_with("POST /api/v1/devices ") {
                                r#"{"success":true,"node_id":"node-a","virtual_ip":"10.20.0.1","cidr":"10.20.0.0/16","relay_servers":[]}"#
                            } else if request.starts_with("GET /api/v1/nodes?") {
                                started.notify_one();
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                r#"{"nodes":[]}"#
                            } else {
                                r#"{"success":true,"signals":[],"server_time_ms":0}"#
                            };
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                            let _ = stream.write_all(response.as_bytes()).await;
                        });
                    }
                    Some(_) = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        let mut config = Config::generate_default(&format!("http://{address}"), "net1").unwrap();
        config.control.auth_token = "test-token".into();
        config.node.ed25519_private_key.clear();
        config.node.ed25519_public_key.clear();
        let (client, _events) = ControlClient::new(
            &config,
            true,
            None,
            None,
            ConnectionTimeline::new("test-node", 0),
        );
        timeout(Duration::from_secs(3), roster_started.notified())
            .await
            .unwrap();
        timeout(Duration::from_secs(3), client.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(released.load(Ordering::Acquire), 1);
        client.shutdown().await.unwrap();
        assert_eq!(released.load(Ordering::Acquire), 1);
        assert!(!client.state.read().await.registered);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn shutdown_waits_briefly_for_an_already_accepted_registration_identity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (response_tx, response_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = stream.read(&mut chunk).await.unwrap();
            accepted_tx.send(()).unwrap();
            response_rx.await.unwrap();
            let body = r#"{"success":true,"node_id":"registered-node","virtual_ip":"10.20.0.1","cidr":"10.20.0.0/16","relay_servers":[]}"#;
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            stream.write_all(response.as_bytes()).await.unwrap();
            drop(stream);
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let n = stream.read(&mut chunk).await.unwrap();
                let line = String::from_utf8_lossy(&chunk[..n]);
                if line.starts_with("POST /api/v1/devices/registered-node/offline ") {
                    let body = r#"{"success":true}"#;
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    stream.write_all(response.as_bytes()).await.unwrap();
                    break;
                }
            }
        });
        let mut config = Config::generate_default(&format!("http://{address}"), "net1").unwrap();
        config.control.auth_token = "test-token".into();
        config.node.ed25519_private_key.clear();
        config.node.ed25519_public_key.clear();
        let (client, _events) = ControlClient::new(
            &config, true, None, None, ConnectionTimeline::new("test-node", 0),
        );
        timeout(Duration::from_secs(2), accepted_rx).await.unwrap().unwrap();
        client.shutdown_lifecycle.as_ref().unwrap().requested.send_replace(true);
        tokio::task::yield_now().await;
        response_tx.send(()).unwrap();
        timeout(Duration::from_secs(2), client.shutdown()).await.unwrap().unwrap();
        timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_cancels_registration_without_waiting_for_http_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = Config::generate_default(&format!("http://{address}"), "net1").unwrap();
        config.control.auth_token = "test-token".into();
        let (client, _events) = ControlClient::new(
            &config,
            true,
            None,
            None,
            ConnectionTimeline::new("test-node", 0),
        );
        let (_stream, _) = timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(1), client.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(!client.state.read().await.registered);
    }

    #[tokio::test]
    async fn dropping_last_owner_requests_shutdown_without_a_queue_slot() {
        let (requested, mut receiver) = watch::channel(false);
        let (_done, completed) = watch::channel(false);
        let owner = Arc::new(ControlShutdown {
            requested,
            completed,
        });
        let another = owner.clone();
        drop(owner);
        assert!(!*receiver.borrow());
        drop(another);
        timeout(
            Duration::from_millis(100),
            control_shutdown_requested(&mut receiver),
        )
        .await
        .unwrap();
        assert!(*receiver.borrow());
    }
}
