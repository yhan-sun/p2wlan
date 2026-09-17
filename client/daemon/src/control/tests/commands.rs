// Regression coverage for `control/runtime/commands.rs`.
//
// The command arms used to be spliced straight into the polling loop's
// `select!`, so their only testable surface was their source text. They are now
// one `handle_control_command` function returning a disposition, which lets
// these tests drive each command against a real HTTP client and assert on what
// the daemon actually observed: events, response channels, shared state and the
// loop's next move.

use crate::config::ControlProxyMode;

/// One recorded request line, e.g. `PATCH /api/v1/devices/node-a/endpoint HTTP/1.1`.
type RequestLine = String;

/// A stand-in control plane: it answers the endpoints the ordinary command lane
/// calls and records the request lines it saw.
struct ControlStub {
    base_url: String,
    seen: Arc<std::sync::Mutex<Vec<RequestLine>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ControlStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

impl ControlStub {
    async fn start<F>(respond: F) -> Self
    where
        F: Fn(&str) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("stub control plane must bind a loopback port");
        let address = listener.local_addr().unwrap();
        let seen: Arc<std::sync::Mutex<Vec<RequestLine>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let respond = Arc::new(respond);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let respond = respond.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let Some(request) = read_http_request(&mut stream).await else {
                        return;
                    };
                    recorded.lock().unwrap().push(request.line.clone());
                    let (status, body) = respond(&request.line);
                    let response = format!(
                        "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        reason_phrase(status),
                        body.len(),
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self {
            base_url: format!("http://{address}"),
            seen,
            task,
        }
    }

    fn requests(&self) -> Vec<RequestLine> {
        self.seen.lock().unwrap().clone()
    }

    fn saw(&self, method_and_path: &str) -> bool {
        self.requests()
            .iter()
            .any(|line| line.starts_with(method_and_path))
    }
}

/// The command lane's inputs, driven directly instead of through a live
/// registration cycle.
struct CommandHarness {
    http: RouteAwareControlHttpClient,
    base_url: String,
    token: String,
    config: Config,
    self_node_id: String,
    registration_seq: Option<u64>,
    state: Arc<RwLock<ClientState>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    event_rx: mpsc::UnboundedReceiver<ControlEvent>,
    health: Arc<crate::tasks::HealthState>,
    advertised_snapshot: Arc<std::sync::Mutex<AdvertisedEndpointSnapshot>>,
    peer_roster_tick: time::Interval,
    poll_failures: u32,
}

impl CommandHarness {
    fn new(base_url: &str) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            http: route_aware_control_http_clients(ControlProxyMode::Direct, base_url).0,
            base_url: base_url.to_string(),
            token: "dc-test-device".to_string(),
            config: test_config(),
            self_node_id: "node-a".to_string(),
            registration_seq: Some(4),
            state: Arc::new(RwLock::new(ClientState {
                room_authorization: Arc::new(crate::rooms::RoomAuthorization::new("net1")),
                registered: true,
                peers: HashMap::new(),
                virtual_ip: Some("10.20.0.2".to_string()),
                _relay_servers: Vec::new(),
            })),
            event_tx,
            event_rx,
            health: crate::tasks::HealthState::new(),
            advertised_snapshot: Arc::new(std::sync::Mutex::new(
                AdvertisedEndpointSnapshot::default(),
            )),
            peer_roster_tick: time::interval(Duration::from_secs(1)),
            poll_failures: 0,
        }
    }

    async fn invoke(
        &mut self,
        cmd: ControlCommand,
        signal_ws_task: Option<&websocket::SignalWebSocketTask>,
    ) -> ControlCommandDisposition {
        handle_control_command(
            cmd,
            &self.http,
            &self.base_url,
            &self.token,
            &self.config,
            &self.self_node_id,
            self.registration_seq,
            &self.state,
            &self.event_tx,
            Some(&self.health),
            None,
            &self.advertised_snapshot,
            &mut self.peer_roster_tick,
            signal_ws_task,
            &mut self.poll_failures,
        )
        .await
    }

    fn events(&mut self) -> Vec<ControlEvent> {
        let mut drained = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            drained.push(event);
        }
        drained
    }

    async fn device_lease_healthy(&self) -> bool {
        self.health.snapshot(&[]).await.device_lease_healthy
    }

    fn advertised(&self) -> AdvertisedEndpointSnapshot {
        self.advertised_snapshot.lock().unwrap().clone()
    }
}

fn is_disconnected(event: &ControlEvent) -> bool {
    matches!(event, ControlEvent::Disconnected)
}

fn is_reauth_required(event: &ControlEvent) -> bool {
    matches!(event, ControlEvent::ReauthRequired { .. })
}

fn is_control_healthy(event: &ControlEvent) -> bool {
    matches!(event, ControlEvent::ControlHealthy)
}

fn server_error_code(event: &ControlEvent) -> Option<u16> {
    match event {
        ControlEvent::ServerError { code, .. } => Some(*code),
        _ => None,
    }
}

/// A 409 whose `error_code` is one of the registration-lifecycle fencing codes.
fn lifecycle_conflict_body() -> String {
    r#"{"error":"registration sequence conflict","error_code":"registration_conflict","registration_seq":9}"#
        .to_string()
}

#[tokio::test]
async fn poll_peers_now_clears_the_failure_counter_on_success() {
    let stub = ControlStub::start(|_| (200, r#"{"nodes":[]}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    harness.poll_failures = 7;

    let disposition = harness.invoke(ControlCommand::PollPeersNow, None).await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(
        harness.poll_failures == 0,
        "a successful immediate poll must clear the consecutive failure counter"
    );
    assert!(stub.saw("GET /api/v1/nodes?network_id=net1"));
    assert!(harness.events().iter().any(is_control_healthy));
}

#[tokio::test]
async fn poll_peers_now_counts_a_transport_failure_and_keeps_polling() {
    let stub = ControlStub::start(|_| (500, r#"{"error":"boom"}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    harness.poll_failures = 1;

    let disposition = harness.invoke(ControlCommand::PollPeersNow, None).await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert_eq!(
        harness.poll_failures, 2,
        "an immediate poll failure is what drives the re-register threshold"
    );
}

#[tokio::test]
async fn poll_peers_now_exits_on_a_registration_lifecycle_conflict() {
    let stub = ControlStub::start(|_| (409, lifecycle_conflict_body())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    harness.poll_failures = 2;

    let disposition = harness.invoke(ControlCommand::PollPeersNow, None).await;

    assert_eq!(
        disposition,
        ControlCommandDisposition::Exit,
        "a fenced registration must not be retried inside the polling cycle"
    );
    assert_eq!(
        harness.poll_failures, 2,
        "a lifecycle conflict is not a transient poll failure"
    );
    let events = harness.events();
    assert!(events.iter().any(is_reauth_required));
    assert!(events.iter().any(is_disconnected));
    assert!(!harness.device_lease_healthy().await);
}

#[tokio::test]
async fn network_changed_aborts_signaling_and_re_registers() {
    let stub = ControlStub::start(|_| (200, r#"{"nodes":[]}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);

    // A task whose "connected" bit is already set proves the abort reached the
    // signaling transport rather than merely returning a disposition.
    let connected = Arc::new(AtomicBool::new(true));
    let (wake_tx, _wake_rx) = mpsc::channel(4);
    let signal_ws_task = spawn_signal_websocket(
        &stub.base_url,
        "dc-test-device",
        "node-a",
        "net1",
        Some(4),
        wake_tx,
        connected.clone(),
    );

    let disposition = harness
        .invoke(ControlCommand::NetworkChanged, Some(&signal_ws_task))
        .await;

    assert_eq!(
        disposition,
        ControlCommandDisposition::Reregister,
        "an Android network change leaves the polling cycle to re-register"
    );
    assert!(
        !connected.load(Ordering::Acquire),
        "the signaling WebSocket task must be aborted"
    );
}

#[tokio::test]
async fn update_endpoint_publishes_the_snapshot_and_device_lease_health() {
    let stub = ControlStub::start(|_| (200, r#"{"success":true}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::UpdateEndpoint {
                endpoint: "203.0.113.7:41000".to_string(),
                nat_type: "p2v2:m=address_or_port_dependent".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    let response = response_rx.await.expect("the caller must be answered");
    assert!(response.is_ok());
    assert!(stub.saw("PATCH /api/v1/devices/node-a/endpoint"));

    let advertised = harness.advertised();
    assert_eq!(advertised.endpoint, "203.0.113.7:41000");
    assert_eq!(
        advertised.nat_type,
        control_label_with_registration_seq("p2v2:m=address_or_port_dependent", Some(4))
    );
    assert!(
        harness.device_lease_healthy().await,
        "a successful endpoint PATCH is the device lease heartbeat"
    );
    assert!(harness.events().iter().any(is_control_healthy));
}

#[tokio::test]
async fn update_endpoint_failure_clears_the_device_lease_without_touching_the_snapshot() {
    let stub = ControlStub::start(|_| (500, r#"{"error":"lease refused"}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    harness.health.set_device_lease_healthy(true);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::UpdateEndpoint {
                endpoint: "203.0.113.8:41000".to_string(),
                nat_type: "p2v2:m=endpoint_independent".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(response_rx
        .await
        .expect("the caller must be answered")
        .is_err());
    assert!(
        !harness.device_lease_healthy().await,
        "a failed endpoint PATCH must stay visible even though the request answered"
    );
    assert!(
        harness.advertised().endpoint.is_empty(),
        "a rejected publication must not become the advertised endpoint"
    );
    assert!(harness
        .events()
        .iter()
        .any(|event| server_error_code(event) == Some(2000)));
}

#[tokio::test]
async fn update_endpoint_permanent_auth_re_registers_before_answering_the_caller() {
    let stub = ControlStub::start(|_| {
        (
            401,
            r#"{"success":false,"error":"unauthorized"}"#.to_string(),
        )
    })
    .await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::UpdateEndpoint {
                endpoint: "203.0.113.9:41000".to_string(),
                nat_type: "p2v2:m=endpoint_independent".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(
        disposition,
        ControlCommandDisposition::Reregister,
        "a rejected device credential cannot be retried inside this polling cycle"
    );
    assert!(
        response_rx.await.is_err(),
        "the arm left the polling cycle before answering, dropping the response sender"
    );
    assert!(!harness.device_lease_healthy().await);
    assert!(harness
        .events()
        .iter()
        .any(|event| server_error_code(event) == Some(2000)));
}

#[tokio::test]
async fn update_endpoint_lifecycle_conflict_exits_the_control_loop() {
    let stub = ControlStub::start(|_| (409, lifecycle_conflict_body())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::UpdateEndpoint {
                endpoint: "203.0.113.10:41000".to_string(),
                nat_type: "p2v2:m=endpoint_independent".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Exit);
    let response = response_rx
        .await
        .expect("the caller must be answered first");
    assert!(response.is_err());
    let events = harness.events();
    assert!(events.iter().any(is_reauth_required));
    assert!(events.iter().any(is_disconnected));
}

#[tokio::test]
async fn create_tunnel_reports_the_created_tunnel() {
    let stub = ControlStub::start(|_| {
        (
            200,
            r#"{"success":true,"tunnel_id":"tunnel-1","public_endpoint":"198.51.100.4:5000"}"#
                .to_string(),
        )
    })
    .await;
    let mut harness = CommandHarness::new(&stub.base_url);

    let disposition = harness
        .invoke(
            ControlCommand::CreateTunnel {
                protocol: "tcp".to_string(),
                local_port: 8080,
                remote_port: 80,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(stub.saw("POST /api/v1/tunnels"));
    assert!(harness.events().iter().any(|event| matches!(
        event,
        ControlEvent::TunnelCreated { tunnel_id, public_endpoint }
            if tunnel_id == "tunnel-1" && public_endpoint == "198.51.100.4:5000"
    )));
}

#[tokio::test]
async fn create_tunnel_permanent_auth_re_registers() {
    let stub = ControlStub::start(|_| {
        (
            401,
            r#"{"success":false,"error":"unauthorized"}"#.to_string(),
        )
    })
    .await;
    let mut harness = CommandHarness::new(&stub.base_url);

    let disposition = harness
        .invoke(
            ControlCommand::CreateTunnel {
                protocol: "tcp".to_string(),
                local_port: 8080,
                remote_port: 80,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Reregister);
    assert!(harness
        .events()
        .iter()
        .any(|event| server_error_code(event) == Some(401)));
}

#[tokio::test]
async fn send_peer_reflexive_answers_the_caller_and_reports_failures() {
    let ok_stub = ControlStub::start(|_| (200, r#"{"success":true}"#.to_string())).await;
    let mut harness = CommandHarness::new(&ok_stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::SendPeerReflexive {
                to_node_id: "node-b".to_string(),
                observed_endpoint: "203.0.113.20:5555".to_string(),
                punch_at_ms: Some(1_700_000_000_000),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(response_rx
        .await
        .expect("the caller must be answered")
        .is_ok());
    assert!(ok_stub.saw("POST /api/v1/signals"));

    let retry_stub =
        ControlStub::start(|_| (500, r#"{"error":"signal queue full"}"#.to_string())).await;
    let mut retry_harness = CommandHarness::new(&retry_stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = retry_harness
        .invoke(
            ControlCommand::SendPeerReflexive {
                to_node_id: "node-b".to_string(),
                observed_endpoint: "203.0.113.20:5555".to_string(),
                punch_at_ms: None,
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(response_rx
        .await
        .expect("the caller must be answered")
        .is_err());
    assert!(retry_harness
        .events()
        .iter()
        .any(|event| server_error_code(event) == Some(4002)));
}

#[tokio::test]
async fn send_peer_reflexive_lifecycle_conflict_exits_the_control_loop() {
    let stub = ControlStub::start(|_| (409, lifecycle_conflict_body())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::SendPeerReflexive {
                to_node_id: "node-b".to_string(),
                observed_endpoint: "203.0.113.20:5555".to_string(),
                punch_at_ms: None,
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Exit);
    assert!(response_rx.await.expect("answered first").is_err());
    assert!(harness.events().iter().any(is_reauth_required));
}

#[tokio::test]
async fn fetch_relay_ticket_answers_then_exits_on_a_lifecycle_conflict() {
    let stub = ControlStub::start(|_| {
        (
            200,
            r#"{"ticket":"relay-ticket","expires_at":1700000000}"#.to_string(),
        )
    })
    .await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::FetchRelayTicket {
                audience: "relay-a".to_string(),
                region: "cn-east".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(stub.saw("POST /api/v1/relay/tickets"));
    let ticket = response_rx
        .await
        .expect("the caller must be answered")
        .expect("a relay ticket was issued");
    assert_eq!(ticket.ticket, "relay-ticket");
    assert_eq!(ticket.expires_at, 1_700_000_000);

    let conflict_stub = ControlStub::start(|_| (409, lifecycle_conflict_body())).await;
    let mut conflict_harness = CommandHarness::new(&conflict_stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = conflict_harness
        .invoke(
            ControlCommand::FetchRelayTicket {
                audience: "relay-a".to_string(),
                region: "cn-east".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Exit);
    assert!(response_rx.await.expect("answered first").is_err());
    assert!(conflict_harness.events().iter().any(is_reauth_required));
}

#[tokio::test]
async fn fetch_relay_ticket_permanent_auth_is_returned_without_exiting() {
    let stub = ControlStub::start(|_| (401, r#"{"error":"token expired"}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(
            ControlCommand::FetchRelayTicket {
                audience: "relay-a".to_string(),
                region: "cn-east".to_string(),
                response_tx,
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(
        response_rx
            .await
            .expect("the caller must be answered")
            .is_err(),
        "the permanent-auth failure belongs to the caller, not to the loop"
    );
    assert!(
        harness
            .events()
            .iter()
            .all(|event| !is_reauth_required(event)),
        "an ordinary command lane auth failure is not a lifecycle conflict"
    );
}

#[tokio::test]
async fn delete_tunnel_stays_local() {
    let stub = ControlStub::start(|_| (200, r#"{"success":true}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);

    let disposition = harness
        .invoke(
            ControlCommand::DeleteTunnel {
                tunnel_id: "tunnel-1".to_string(),
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Continue);
    assert!(
        stub.requests().is_empty(),
        "tunnel deletion is a local bookkeeping command"
    );
}

#[tokio::test]
async fn shutdown_releases_presence_best_effort_and_exits() {
    let stub = ControlStub::start(|_| (200, r#"{"success":true}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(ControlCommand::Shutdown { response_tx }, None)
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Exit);
    assert!(stub.saw("POST /api/v1/devices/node-a/offline"));
    response_rx
        .await
        .expect("shutdown must acknowledge even though release is best effort");
    assert!(harness.events().iter().any(is_disconnected));
}

#[tokio::test]
async fn shutdown_still_acknowledges_when_presence_release_fails() {
    let stub = ControlStub::start(|_| (500, r#"{"error":"offline refused"}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);
    let (response_tx, response_rx) = oneshot::channel();

    let disposition = harness
        .invoke(ControlCommand::Shutdown { response_tx }, None)
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Exit);
    response_rx
        .await
        .expect("a failed best-effort release must not strand shutdown");
    assert!(harness.events().iter().any(is_disconnected));
}

#[tokio::test]
async fn lifecycle_conflict_command_exits_the_control_loop() {
    let stub = ControlStub::start(|_| (200, r#"{"success":true}"#.to_string())).await;
    let mut harness = CommandHarness::new(&stub.base_url);

    let disposition = harness
        .invoke(
            ControlCommand::LifecycleConflict {
                message: "peer-reflexive signal rejected by the current registration lifecycle"
                    .to_string(),
            },
            None,
        )
        .await;

    assert_eq!(disposition, ControlCommandDisposition::Exit);
    let events = harness.events();
    assert!(events.iter().any(is_reauth_required));
    assert!(events.iter().any(is_disconnected));
    assert!(
        stub.requests().is_empty(),
        "a lifecycle conflict is a terminal local transition"
    );
    assert!(!harness.device_lease_healthy().await);
}
