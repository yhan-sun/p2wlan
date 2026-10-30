//! Actual owned UDP reader + Noise/WG actor provenance. Mock writes below
//! deliberately prove no concrete system-TUN Full and no final owner/once.
use super::*;
use crate::os_request_capture::control::CaptureSetup;
use p2pnet_tun::{MockTunDevice, VirtualInterface};
use serde_json::json;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

const PEER: &str = "peer-b";
const LOCAL: &str = "10.21.1.2";
const REMOTE: &str = "10.21.1.3";

mod system_write_partition;

#[tokio::test]
async fn actual_reader_ingress_peer_metadata_cannot_borrow_new_network_identity() {
    let mut harness = Harness::new(false, true).await;
    let binding = harness.receive(&packet(true)).await;
    harness.close().await;
    // This is a clock/peer metadata control, never a constructed KernelRead.
    let before = Instant::now();
    let original = harness
        .peers
        .try_capture_original_kernel_read_peer(PEER, REMOTE.parse().unwrap(), None)
        .unwrap();
    assert!(original.matches_original_ingress(&binding.source, before));
    let generation = harness
        .peers
        .advance_network_generation("original-ingress-control")
        .await;
    let later_time = Instant::now();
    let later = harness
        .peers
        .try_capture_original_kernel_read_peer(PEER, REMOTE.parse().unwrap(), None)
        .unwrap();
    assert_eq!(later.generation(), generation);
    assert!(!later.matches_original_ingress(&binding.source, later_time));
    assert!(original
        .try_identity_at(&harness.peers, Instant::now())
        .is_err());
    let snapshot = serde_json::to_value(harness.setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["system_tun_full_writes"], json!([]));
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
}

fn packet(request: bool) -> Vec<u8> {
    let mut body = vec![0; 63 + 128];
    body[..8].copy_from_slice(b"P2WUDE1\0");
    body[8] = if request { 0 } else { 1 };
    body[9..25].fill(0x33);
    body[25..41].fill(0x44);
    body[45..61].fill(0x55);
    body[61..63].copy_from_slice(&128u16.to_be_bytes());
    body[63..].fill(0xa5);
    let mut raw = crate::build_udp_overlay_packet(REMOTE, LOCAL, 43210, 32123, &body).unwrap();
    let ip = crate::business_mtu::internet_checksum(&raw[..20]);
    raw[10..12].copy_from_slice(&ip.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&raw[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&raw[24..26]);
    pseudo.extend_from_slice(&raw[20..]);
    let udp = crate::business_mtu::internet_checksum(&pseudo);
    raw[26..28].copy_from_slice(&if udp == 0 { u16::MAX } else { udp }.to_be_bytes());
    assert!(parse_os_udp(&raw).is_ok());
    raw
}

struct Harness {
    setup: CaptureSetup,
    _parent: std::os::unix::net::UnixStream,
    peers: Arc<PeerManager>,
    room: Arc<RoomAuthorization>,
    remote: p2pnet_wireguard::TransportSession,
    socket: tokio::net::UdpSocket,
    destination: std::net::SocketAddr,
    inbound: mpsc::Receiver<InboundPacket>,
    unsourced: Option<mpsc::Sender<crate::transport::ReceivedEncryptedPacket>>,
    stop: watch::Sender<bool>,
    reader: Option<JoinHandle<crate::error::Result<()>>>,
    worker: Option<JoinHandle<crate::error::Result<()>>>,
}

impl Harness {
    async fn new(room_enabled: bool, incoming_request: bool) -> Self {
        let peers = Arc::new(PeerManager::new(
            crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peers
            .add_peer(&crate::control::PeerInfo {
                node_id: PEER.into(),
                public_key: "test-fixture-member".into(),
                endpoint: socket.local_addr().unwrap().to_string(),
                virtual_ip: REMOTE.into(),
                online: true,
                ..Default::default()
            })
            .await;
        let room = Arc::new(RoomAuthorization::new(if room_enabled {
            "room-kernel"
        } else {
            "default"
        }));
        if room_enabled {
            assert!(room.replace(LOCAL, [(PEER.into(), REMOTE.into())], Instant::now(), 3));
        }
        let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
            "producer_scope":"22222222222222222222222222222222","flows":[{
                "protocol":"udp","kind":if incoming_request {"response"} else {"request"},"peer_id":PEER,
                "run_nonce":"33333333333333333333333333333333","round_nonce":"44444444444444444444444444444444",
                "bind_ip":LOCAL,"bind_port":32123,"target_ip":REMOTE,"target_port":43210,"payload_bytes":128,
                "request_nonces":["55555555555555555555555555555555"]}]});
        let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        child.set_nonblocking(true).unwrap();
        let mut encoded = serde_json::to_vec(&value).unwrap();
        encoded.push(b'\n');
        parent.write_all(&encoded).unwrap();
        let setup = CaptureSetup::from_owned_descriptor(child.into(), &peers)
            .await
            .unwrap();
        let a = p2pnet_crypto::NodeIdentity::generate();
        let b = p2pnet_crypto::NodeIdentity::generate();
        let mut initiator = p2pnet_wireguard::HandshakeInitiator::new(a, b.public_key(), None);
        let mut responder = p2pnet_wireguard::HandshakeResponder::new(b, None);
        let initiation = initiator.create_initiation().unwrap();
        let (response, local_keys) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        let remote_keys = initiator.consume_response(&response).unwrap();
        let remote = p2pnet_wireguard::TransportSession::new(remote_keys);
        let (transport, _outbound) = WireGuardTransport::new();
        let transport = transport.with_kernel_capture(setup.session.inbound_runtime(&room));
        transport
            .replace_session_for_lifecycle(
                PEER,
                p2pnet_wireguard::TransportSession::new(local_keys),
                peers.peer_session_generation_sync(PEER).unwrap(),
            )
            .await;
        let udp = crate::udp::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let destination = udp.local_addr().unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
        let (inbound_tx, inbound) = mpsc::channel(4);
        let (stop, stopped) = watch::channel(false);
        let unsourced = Some(encrypted_tx.clone());
        let reader = tokio::spawn(udp.run_original_reader_until_for_test(encrypted_tx, stopped));
        let worker =
            tokio::spawn(async move { transport.run_inbound(encrypted_rx, inbound_tx).await });
        Self {
            setup,
            _parent: parent,
            peers,
            room,
            remote,
            socket,
            destination,
            inbound,
            unsourced,
            stop,
            reader: Some(reader),
            worker: Some(worker),
        }
    }

    async fn receive(&mut self, raw: &[u8]) -> Arc<KernelIngressBinding> {
        let packet = self.receive_packet(raw).await;
        let binding = packet
            .authenticated_ingress
            .unwrap()
            .kernel()
            .unwrap()
            .clone();
        assert!(
            binding.source.original_udp_read().is_some(),
            "only actual original reader can supply the source"
        );
        assert_eq!(
            binding.source.session().original_role(),
            OriginalSessionRole::Active
        );
        binding
    }

    async fn receive_packet(&mut self, raw: &[u8]) -> InboundPacket {
        let wire = self.remote.encrypt_to_bytes(raw).unwrap();
        assert_eq!(
            self.socket.send_to(&wire, self.destination).await.unwrap(),
            wire.len()
        );
        let packet = tokio::time::timeout(Duration::from_secs(2), self.inbound.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.packet, raw);
        packet
    }

    async fn close(&mut self) {
        self.unsourced.take();
        self.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), self.reader.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), self.worker.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn missing_first_native_ingress_cannot_rearm_on_duplicate_after_room_renewal() {
    let mut harness = Harness::new(true, true).await;
    let raw = packet(true);
    // Genuine WG ciphertext and actual decrypt, deliberately missing the
    // native-reader source. This negative input must confer no provenance.
    let wire_bytes = harness.remote.encrypt_to_bytes(&raw).unwrap();
    harness
        .unsourced
        .as_ref()
        .unwrap()
        .send(crate::transport::ReceivedEncryptedPacket {
            source: None,
            local_endpoint: None,
            relay_endpoint: None,
            relay_connection_id: None,
            relay_peer_id: None,
            socket_index: None,
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(harness.peers.current_network_generation_sync()),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes,
            physical_ingress: None,
            original_relay_read: None,
            original_udp_read: None,
        })
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), harness.inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.packet, raw);
    assert!(first.authenticated_ingress.is_none());
    assert!(harness
        .room
        .replace(LOCAL, [(PEER.into(), REMOTE.into())], Instant::now(), 20));
    let later = harness.receive_packet(&raw).await;
    harness.close().await;
    assert!(
        later.authenticated_ingress.is_none(),
        "a later genuine duplicate cannot refill the lost original source"
    );
    let snapshot = serde_json::to_value(harness.setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["incoming_provenance_complete"], false);
    assert_eq!(snapshot["system_tun_full_writes"], json!([]));
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn contended_original_ingress_cannot_rearm_on_duplicate_after_room_renewal() {
    let mut harness = Harness::new(true, true).await;
    let raw = packet(true);
    let scope = harness.setup.session.clone();
    // A separate owned thread holds the test-only contention for at most 5s.
    // No async task holds the mutex across await; the real observer must try
    // and return while receive_packet retains its original 2s bound.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let lock_scope = scope.clone();
    let owner = std::thread::spawn(move || {
        let _held = lock_scope.state.lock().unwrap();
        ready_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
    });
    tokio::time::timeout(Duration::from_secs(2), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let first = harness.receive_packet(&raw).await;
    release_tx.send(()).unwrap();
    owner.join().unwrap();
    assert!(first.authenticated_ingress.is_none());
    assert!(harness
        .room
        .replace(LOCAL, [(PEER.into(), REMOTE.into())], Instant::now(), 20));
    let later = harness.receive_packet(&raw).await;
    harness.close().await;
    assert!(later.authenticated_ingress.is_none());
    let snapshot = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["incoming_provenance_complete"], false);
    assert_eq!(snapshot["system_tun_full_writes"], json!([]));
    let loss = &snapshot["first_original_inbound_loss"];
    assert_eq!(loss["site"], "authenticated_input");
    assert_eq!(loss["original_failure"], "contended");
    assert_eq!(loss["native_os_write_verified"], false);
    assert_eq!(loss["physical_send_verified"], false);
    assert_eq!(loss["canonical_current_owner_verified"], false);
    let refusal = &snapshot["original_authenticated_input_registry_refusal"];
    assert_eq!(
        refusal["scope"],
        "actual_authenticated_input_registry_try_lock_refusal_only"
    );
    assert!(refusal.get("read_ordinal").is_none());
    assert_eq!(refusal["holder"]["release_completion_observed"], true);
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(refusal[key], false);
    }
    assert!(snapshot.get("original_input_registry_refusal").is_none());
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(reader) = &self.reader {
            reader.abort();
        }
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

#[tokio::test]
async fn actual_udp_auth_carriage_and_mock_full_write_never_mint_system_write() {
    let mut harness = Harness::new(false, false).await;
    let raw = packet(false);
    let binding = harness.receive(&raw).await;
    harness.close().await;
    let (mut mock, controller) = MockTunDevice::new_pair("kernel-carriage-control", 1420, LOCAL);
    assert!(
        crate::overlay_requests::RequestSendToken::from_read_context(
            binding.write_context(&harness.peers, &raw).unwrap()
        )
        .is_none()
    );
    assert_eq!(
        mock.write_with_context(&raw, binding.write_context(&harness.peers, &raw).unwrap())
            .await
            .unwrap(),
        raw.len()
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), controller.recv_written())
            .await
            .unwrap()
            .unwrap(),
        raw
    );
    assert!(binding.write.get().is_none());
    let snapshot = serde_json::to_value(harness.setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["system_tun_full_writes"], json!([]));
    assert_eq!(
        snapshot["requests"][0]["incoming_frame_system_write_complete"],
        false
    );
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn actual_auth_carriage_rejects_other_peer_owner_and_changed_write_bytes() {
    let mut harness = Harness::new(false, false).await;
    let raw = packet(false);
    let binding = harness.receive(&raw).await;
    harness.close().await;
    let other = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    assert!(binding.write_context(&other, &raw).is_none());
    let mut changed = raw.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(binding.write_context(&harness.peers, &changed).is_none());
    assert!(binding.write.get().is_none());
}

#[tokio::test]
async fn actual_duplicate_request_keeps_first_room_permit_after_renew_and_reauthorize() {
    let mut harness = Harness::new(true, true).await;
    let raw = packet(true);
    let first = harness.receive(&raw).await;
    let original = first.original_rooms[0]
        .permit
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    assert!(harness
        .room
        .try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL)
        .is_ok());
    assert!(harness
        .room
        .replace(LOCAL, [(PEER.into(), REMOTE.into())], Instant::now(), 20));
    let renewed = harness
        .room
        .try_capture_original_send_permit(PEER, REMOTE, LOCAL)
        .unwrap()
        .unwrap();
    assert_ne!(
        original, renewed,
        "original permit must keep its shorter deadline"
    );
    let duplicate = harness.receive(&raw).await;
    harness.close().await;
    assert!(Arc::ptr_eq(
        &first.original_rooms[0],
        &duplicate.original_rooms[0]
    ));
    assert_eq!(
        duplicate.original_rooms[0]
            .permit
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap(),
        &original
    );
    harness.room.invalidate();
    assert!(harness
        .room
        .replace(LOCAL, [(PEER.into(), REMOTE.into())], Instant::now(), 20));
    assert!(matches!(
        harness
            .room
            .try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::Stale)
    ));
}

#[tokio::test]
async fn actual_auth_carriage_has_no_descriptor_room_or_peer_owner_keeper() {
    let mut harness = Harness::new(true, true).await;
    let binding = harness.receive(&packet(true)).await;
    let scope = Arc::downgrade(&harness.setup.session);
    let room = Arc::downgrade(&harness.room);
    let peers = Arc::downgrade(&harness.peers);
    harness.close().await;
    drop(harness);
    assert!(scope.upgrade().is_none());
    assert!(room.upgrade().is_none());
    assert!(peers.upgrade().is_none());
    assert!(!binding.original_rooms[0]
        .permit
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap()
        .is_valid());
    assert!(binding.write.get().is_none());
}
