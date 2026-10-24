//! Real PeerManager lifecycle/epoch and Noise/WG encryption controls. Calling
//! the metadata collector below does not mint a KernelRead or system-write fact.
use super::*;
use crate::control::PeerInfo;
use crate::os_request_capture::control::CaptureSetup;
use crate::overlay_requests::{OverlayCreditLockSite, OverlayCreditStale};
use serde_json::json;
use std::io::Write;

const PEER: &str = "peer-read-boundary";
const LOCAL: &str = "10.21.1.2";
const TARGET: &str = "10.21.1.3";

mod epoch_trace;
mod scoped_retention;
mod scoped_view;

fn info() -> PeerInfo {
    PeerInfo {
        node_id: PEER.into(),
        public_key: "test-read-peer-member".into(),
        endpoint: "127.0.0.1:44321".into(),
        virtual_ip: TARGET.into(),
        online: true,
        ..Default::default()
    }
}

async fn setup() -> (
    CaptureSetup,
    std::os::unix::net::UnixStream,
    Arc<PeerManager>,
) {
    let peers = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&info()).await;
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[{
            "protocol":"udp","kind":"request","peer_id":PEER,
            "run_nonce":"33333333333333333333333333333333","round_nonce":"44444444444444444444444444444444",
            "bind_ip":LOCAL,"bind_port":32123,"target_ip":TARGET,"target_port":43210,"payload_bytes":128,
            "request_nonces":["55555555555555555555555555555555"]}]});
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let mut encoded = serde_json::to_vec(&value).unwrap();
    encoded.push(b'\n');
    parent.write_all(&encoded).unwrap();
    let setup = CaptureSetup::from_owned_descriptor(child.into(), &peers)
        .await
        .unwrap();
    (setup, parent, peers)
}

fn collect(scope: &CaptureSession) -> Arc<FirstReadPeer> {
    let mut state = scope.state.lock().unwrap();
    scope
        .first_read_peers(&mut state.flows[0], &[0], None)
        .remove(0)
}

fn no_kernel_credit(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["requests"][0]["read_events"], 0);
    assert_eq!(value["requests"][0]["kernel_frame_read_complete"], false);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["canonical_current_owner_verified"], false);
}

async fn encrypted(peers: &Arc<PeerManager>) -> crate::transport::EncryptedOutboundWithSource {
    let a = p2pnet_crypto::NodeIdentity::generate();
    let b = p2pnet_crypto::NodeIdentity::generate();
    let mut initiator = p2pnet_wireguard::HandshakeInitiator::new(a, b.public_key(), None);
    let mut responder = p2pnet_wireguard::HandshakeResponder::new(b, None);
    let initiation = initiator.create_initiation().unwrap();
    let (_response, keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let (transport, _outbound) = crate::transport::WireGuardTransport::new();
    transport
        .replace_session_for_lifecycle(
            PEER,
            p2pnet_wireguard::TransportSession::new(keys),
            peers.peer_session_generation_sync(PEER).unwrap(),
        )
        .await;
    transport
        .encrypt_outbound_with_source(OutboundPacket {
            room_authorization: None,
            peer_id: PEER.into(),
            dst_ip: TARGET.into(),
            packet: crate::build_udp_overlay_packet(LOCAL, TARGET, 32123, 43210, b"source-control")
                .unwrap(),
            trace: None,
        })
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn first_read_peer_matches_actual_crypto_and_rejects_foreign_owner_or_generation() {
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    let expected = first.original.as_ref().unwrap();
    assert!(expected.try_identity_at(&peers, Instant::now()).is_ok());
    let encrypted = encrypted(&peers).await;
    let source = encrypted.source().unwrap();
    let owner = Arc::downgrade(&peers);
    {
        // Physical publication already owns this exact original epoch gate.
        // Its immutable crypto match must work without reacquiring the gate;
        // the route-time observer correctly reports contention in this scope.
        let gate = peers.network_epoch_gate();
        let _held = gate.try_lock().unwrap();
        assert!(expected.matches_original_encryption(&owner, expected.generation(), source));
        assert_eq!(
            expected.try_identity_at(&peers, Instant::now()),
            Err(OverlayCreditOutcome::Contended(
                OverlayCreditLockSite::Epoch
            ))
        );
    }
    assert!(!expected.matches_original_encryption(&owner, expected.generation() + 1, source));
    let foreign = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    assert_eq!(
        expected.try_identity_at(&foreign, Instant::now()),
        Err(OverlayCreditOutcome::Stale(OverlayCreditStale::Identity))
    );
    assert!(!expected.matches_original_encryption(
        &Arc::downgrade(&foreign),
        expected.generation(),
        source
    ));
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_read_peer_generation_change_never_replaces_original_expectation() {
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    let original_generation = first.original.as_ref().unwrap().generation();
    let new = peers
        .advance_network_generation("read-origin-control")
        .await;
    assert_ne!(new, original_generation);
    let duplicate = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &duplicate));
    assert_eq!(
        duplicate.original.as_ref().unwrap().generation(),
        original_generation
    );
    assert_eq!(
        first
            .original
            .as_ref()
            .unwrap()
            .try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Stale(OverlayCreditStale::Generation))
    );
    let later = encrypted(&peers).await;
    assert!(!first
        .original
        .as_ref()
        .unwrap()
        .matches_original_encryption(&Arc::downgrade(&peers), new, later.source().unwrap()));
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_read_peer_same_node_rejoin_never_replaces_original_lifecycle() {
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    let original = first.original.as_ref().unwrap().lifecycle();
    let generation = peers.current_network_generation_sync();
    peers.remove_peer(PEER).await;
    peers.add_peer(&info()).await;
    assert_eq!(generation, peers.current_network_generation_sync());
    assert_ne!(Some(original), peers.peer_session_generation_sync(PEER));
    let duplicate = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &duplicate));
    assert_eq!(duplicate.original.as_ref().unwrap().lifecycle(), original);
    assert_eq!(
        first
            .original
            .as_ref()
            .unwrap()
            .try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Stale(OverlayCreditStale::Lifecycle))
    );
    let later = encrypted(&peers).await;
    assert!(!first
        .original
        .as_ref()
        .unwrap()
        .matches_original_encryption(&Arc::downgrade(&peers), generation, later.source().unwrap()));
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_read_peer_contention_returns_without_waiting_and_cannot_refill() {
    let (setup, _parent, peers) = setup().await;
    let gate = peers.network_epoch_gate();
    let held = gate.try_lock().unwrap();
    let first = collect(&setup.session);
    assert!(matches!(
        first.original,
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    ));
    drop(held);
    let duplicate = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &duplicate));
    assert!(duplicate.original.is_err());
    let target = TARGET.parse().unwrap();
    assert!(peers
        .try_capture_original_kernel_read_peer(PEER, target, None)
        .is_ok());
    peers.with_original_kernel_peer_connections_held_for_test(|| {
        assert!(matches!(
            peers.try_capture_original_kernel_read_peer(PEER, target, None),
            Err(OverlayCreditOutcome::Contended(
                OverlayCreditLockSite::Connections
            ))
        ));
    });
    peers.with_original_kernel_peer_membership_held_for_test(|| {
        assert!(matches!(
            peers.try_capture_original_kernel_read_peer(PEER, target, None),
            Err(OverlayCreditOutcome::Contended(
                OverlayCreditLockSite::Membership
            ))
        ));
    });
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_read_peer_wrong_vip_offline_and_weak_owners_never_grant_credit() {
    let (setup, parent, peers) = setup().await;
    assert!(peers
        .try_capture_original_kernel_read_peer(PEER, "10.21.1.4".parse().unwrap(), None)
        .is_err());
    let first = collect(&setup.session);
    peers.remove_peer(PEER).await;
    assert!(first
        .original
        .as_ref()
        .unwrap()
        .try_identity_at(&peers, Instant::now())
        .is_err());
    let owner = Arc::downgrade(&peers);
    let scope = Arc::downgrade(&setup.session);
    drop(peers);
    drop(setup);
    drop(parent);
    assert!(owner.upgrade().is_none());
    assert!(scope.upgrade().is_none());
    assert!(
        first.original.is_ok(),
        "immutable metadata remains historical only"
    );
}

#[tokio::test]
async fn read_peer_revalidation_diagnostic_distinguishes_actual_try_lock_sites() {
    use FullRetentionLossReason as Reason;
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    assert_eq!(first.current_rejection(&peers, Instant::now()), None);
    {
        let gate = peers.network_epoch_gate();
        let _held = gate.try_lock().unwrap();
        assert_eq!(
            first.current_rejection(&peers, Instant::now()),
            Some(Reason::ReadPeerEpochContended)
        );
    }
    peers.with_original_kernel_peer_connections_held_for_test(|| {
        assert_eq!(
            first.current_rejection(&peers, Instant::now()),
            Some(Reason::ReadPeerConnectionsContended)
        );
    });
    peers.with_original_kernel_peer_membership_held_for_test(|| {
        assert_eq!(
            first.current_rejection(&peers, Instant::now()),
            Some(Reason::ReadPeerMembershipContended)
        );
    });
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn read_peer_revalidation_diagnostic_keeps_identity_generation_and_lifecycle_distinct() {
    use FullRetentionLossReason as Reason;
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    let foreign =
        PeerManager::new(crate::Config::generate_default("http://ctrl.test", "default").unwrap());
    assert_eq!(
        first.current_rejection(&foreign, Instant::now()),
        Some(Reason::ReadPeerIdentityRejected)
    );
    peers
        .advance_network_generation("read-peer-negative-diagnostic")
        .await;
    assert_eq!(
        first.current_rejection(&peers, Instant::now()),
        Some(Reason::ReadPeerGenerationChanged)
    );
    no_kernel_credit(&setup.session);
    let (other, _parent, peers) = self::setup().await;
    let first = collect(&other.session);
    peers.remove_peer(PEER).await;
    peers.add_peer(&info()).await;
    assert_eq!(
        first.current_rejection(&peers, Instant::now()),
        Some(Reason::ReadPeerLifecycleChanged)
    );
    no_kernel_credit(&other.session);
}

#[tokio::test]
async fn read_peer_revalidation_diagnostic_never_refills_first_capture_or_first_loss() {
    use FullRetentionLossReason as Reason;
    let (setup, _parent, peers) = setup().await;
    let gate = peers.network_epoch_gate();
    let held = gate.try_lock().unwrap();
    let first = collect(&setup.session);
    let rejected = first.current_rejection(&peers, Instant::now()).unwrap();
    assert_eq!(rejected, Reason::ReadPeerEpochContended);
    setup.session.original_full_retention_lost(rejected);
    drop(held);
    let same = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &same));
    assert_eq!(
        same.current_rejection(&peers, Instant::now()),
        Some(rejected)
    );
    setup
        .session
        .original_full_retention_lost(Reason::ReadPeerGenerationChanged);
    let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        value["first_original_full_retention_loss"],
        "read_peer_epoch_contended"
    );
    assert_eq!(value["original_full_retention_complete"], false);
    no_kernel_credit(&setup.session);
}
