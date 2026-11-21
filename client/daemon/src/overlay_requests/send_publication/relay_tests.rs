// Genuine original Relay writer facts with explicit synthetic canonical faults.
// These finite qualifiers grant no current-owner, authenticated ACK or credit.
use super::*;
use crate::relay::publication_test_support::{
    closed_rendezvous, cryptographic_fixture, encrypt_existing, genuine_full, sessions,
    synthetic_capture, Budget, Fixture, SyntheticBranch, WriterPath,
};
use crate::relay::{RelayCaptureOutcome, RelaySendCapture};
use crate::request_carriage::test_support::PEER;

#[tokio::test]
async fn b19_zero_all_prewrite_missing_join_error_remain_distinct() {
    let budget = Budget::new();
    for count in [0, 2] {
        let (f, transport, _remote) = cryptographic_fixture(budget, true).await;
        let (packet, prepared) = encrypt_existing(&f, &transport, budget).await;
        let mut publisher = prepared.open().unwrap();
        let relay = closed_rendezvous(f.peers.clone(), count);
        let capture = RelaySendCapture::new(&packet).unwrap();
        assert!(matches!(
            budget
                .step(relay.send_packet_with_origin(&packet, capture.clone()))
                .await,
            Err(crate::error::DaemonError::RelaySend {
                error: p2pnet_relay::RelayError::WriterStoppedBeforeAccept,
                ..
            })
        ));
        assert_eq!(capture.branches().unwrap().len(), count);
        assert!(matches!(
            capture.finish(),
            RelayCaptureOutcome::DefinitelyNotHanded
        ));
        publisher.finish(true);
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::DefinitelyNotHanded
        );
        let (_, next) = encrypt_existing(&f, &transport, budget).await;
        assert!(
            next.open().is_ok(),
            "only all original typed prewrite may reopen"
        );
    }
    for states in [
        vec![SyntheticBranch::Missing, SyntheticBranch::TypedPrewrite],
        vec![SyntheticBranch::Unknown, SyntheticBranch::TypedPrewrite],
        vec![SyntheticBranch::Accepted, SyntheticBranch::TypedPrewrite],
    ] {
        // Missing/JoinError is an explicitly synthetic unresolved ledger
        // representative, not a claim that this control killed a real worker.
        let (f, transport, _remote) = cryptographic_fixture(budget, true).await;
        let (packet, prepared) = encrypt_existing(&f, &transport, budget).await;
        let mut publisher = prepared.open().unwrap();
        assert!(matches!(
            synthetic_capture(&packet, &states).finish(),
            RelayCaptureOutcome::Uncertain
        ));
        publisher.finish(false);
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::CancelledOrUncertain
        );
        let (_, next) = encrypt_existing(&f, &transport, budget).await;
        assert!(matches!(next.open(), Err(PublicationFailure::Occupied)));
    }
}

#[tokio::test]
async fn b19_foreign_wire_reuse_metadata_failure_never_credits_old_full() {
    let budget = Budget::new();
    let (f, transport, _remote) = cryptographic_fixture(budget, true).await;
    let (packet, prepared) = encrypt_existing(&f, &transport, budget).await;
    let mut publisher = prepared.open().unwrap();
    let mut fixture = Fixture::start(WriterPath::General, f.peers.clone(), budget).await;
    // Explicit altered-ciphertext metadata fault; opaque writer fact is still
    // produced by its original full TCP writer, never manufactured in tests.
    let mut foreign = (*packet).clone();
    foreign.wire_bytes[0] ^= 1;
    let fact = genuine_full(&mut fixture, &foreign, budget).await;
    assert!(matches!(
        publisher.publish_relay(fact),
        Err(PublicationFailure::MetadataFailed)
    ));
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::MetadataFailed
    );
    assert!(f.record.physical_publication.record().is_none());
    fixture.finish(budget).await;

    let (g, crypto, _remote) = cryptographic_fixture(budget, true).await;
    let (packet, prepared) = encrypt_existing(&g, &crypto, budget).await;
    let mut publisher = prepared.open().unwrap();
    let mut fixture = Fixture::start(WriterPath::LegacyAddress, g.peers.clone(), budget).await;
    let capture = RelaySendCapture::new(&packet).unwrap();
    budget
        .step(
            fixture
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        )
        .await
        .unwrap();
    fixture.frame(&packet, budget).await;
    let cell = capture.branches().unwrap()[0].clone();
    let original = cell.original().unwrap() as *const p2pnet_relay::OriginalRelayWriteFact;
    budget
        .step(
            fixture
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        )
        .await
        .unwrap();
    fixture.frame(&packet, budget).await;
    assert!(matches!(
        capture.finish(),
        RelayCaptureOutcome::MetadataFailed
    ));
    assert_eq!(
        cell.original().unwrap() as *const p2pnet_relay::OriginalRelayWriteFact,
        original
    );
    publisher.fail_metadata();
    assert_eq!(
        g.record.physical_publication.state(),
        PhysicalPublicationState::MetadataFailed
    );
    assert!(g.record.physical_publication.record().is_none());
    fixture.finish(budget).await;
}

#[tokio::test]
async fn b19_external_terminal_stale_id_never_overwrites_attempt() {
    let budget = Budget::new();
    let (f, transport, _remote) = cryptographic_fixture(budget, true).await;
    let (packet, first) = encrypt_existing(&f, &transport, budget).await;
    let (_, competitor) = encrypt_existing(&f, &transport, budget).await;
    let mut publisher = first.open().unwrap();
    assert!(matches!(
        competitor.open(),
        Err(PublicationFailure::Occupied | PublicationFailure::Contended)
    ));
    let id = publisher.id;
    assert!(f
        .record
        .physical_publication
        .terminal(id, PhysicalPublicationState::CancelledOrUncertain));
    let mut fixture = Fixture::start(WriterPath::General, f.peers.clone(), budget).await;
    let fact = genuine_full(&mut fixture, &packet, budget).await;
    assert!(matches!(
        publisher.publish_relay(fact),
        Err(PublicationFailure::Contended)
    ));
    publisher.fail_metadata();
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::CancelledOrUncertain
    );
    assert!(f.record.physical_publication.record().is_none());
    fixture.finish(budget).await;

    let (g, crypto, _remote) = cryptographic_fixture(budget, true).await;
    let (_, first) = encrypt_existing(&g, &crypto, budget).await;
    let mut old = first.open().unwrap();
    let old_id = old.id;
    old.finish(true);
    let (packet, second) = encrypt_existing(&g, &crypto, budget).await;
    let mut current = second.open().unwrap();
    assert!(current.id > old_id);
    assert!(!g
        .record
        .physical_publication
        .terminal(old_id, PhysicalPublicationState::MetadataFailed));
    let mut fixture = Fixture::start(WriterPath::General, g.peers.clone(), budget).await;
    current
        .publish_relay(genuine_full(&mut fixture, &packet, budget).await)
        .unwrap();
    assert_eq!(
        g.record.physical_publication.record().unwrap().attempt_id(),
        current.id
    );
    assert!(!g
        .record
        .physical_publication
        .terminal(old_id, PhysicalPublicationState::CancelledOrUncertain));
    assert_eq!(
        g.record.physical_publication.state(),
        PhysicalPublicationState::Recorded
    );
    fixture.finish(budget).await;
}

#[tokio::test]
async fn b19_generation_session_and_same_endpoint_retirement_keep_originals() {
    let budget = Budget::new();
    let (f, transport, _remote) = cryptographic_fixture(budget, true).await;
    let (packet, prepared) = encrypt_existing(&f, &transport, budget).await;
    let mut publisher = prepared.open().unwrap();
    let mut fixture = Fixture::start(WriterPath::General, f.peers.clone(), budget).await;
    publisher
        .publish_relay(genuine_full(&mut fixture, &packet, budget).await)
        .unwrap();
    let record = f.record.physical_publication.record().unwrap();
    let original = (
        record.encryption_generation(),
        record.encryption().session_instance(),
        record.encryption().encrypted_at(),
    );
    let old_relay_id = record.relay().unwrap().connection_id();
    let replacement = crate::relay::RelayTransport::connect_for_test(
        "synthetic-replacement",
        fixture.transport().endpoint(),
        f.peers.clone(),
    );
    assert_ne!(replacement.connection_id(), old_relay_id);
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication
    );
    let next_generation = budget
        .step(
            f.peers
                .advance_network_generation("b19 actual generation advance"),
        )
        .await;
    assert!(next_generation > original.0);
    let (next_session, _) = sessions();
    budget
        .step(transport.replace_session_for_lifecycle(
            PEER,
            next_session,
            f.record.expected_target_lifecycle().unwrap(),
        ))
        .await;
    assert_ne!(
        budget
            .step(transport.session_status(PEER))
            .await
            .active_session_instance
            .unwrap(),
        original.1
    );
    assert_eq!(
        (
            record.encryption_generation(),
            record.encryption().session_instance(),
            record.encryption().encrypted_at()
        ),
        original
    );
    // Kept-old source allocation is historical unknown, never current credit.
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication
    );
    assert_eq!(
        record.qualify(
            &f.record,
            f.record.sent_at + crate::OVERLAY_NONCE_TTL + std::time::Duration::from_nanos(1)
        ),
        PhysicalInputQualification::Expired
    );
    assert!(record.udp().is_none());
    assert_eq!(Arc::strong_count(&f.record), 1);
    let weak = fixture.weak_client();
    fixture.finish(budget).await;
    assert!(weak.upgrade().is_none());
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::Retired
    );
    drop(replacement);
}

#[tokio::test]
async fn b19_original_auth_l_unknown_never_refilled_from_target() {
    let budget = Budget::new();
    let (f, transport, _remote) = cryptographic_fixture(budget, false).await;
    let (packet, prepared) = encrypt_existing(&f, &transport, budget).await;
    let mut publisher = prepared.open().unwrap();
    let mut fixture = Fixture::start(WriterPath::General, f.peers.clone(), budget).await;
    publisher
        .publish_relay(genuine_full(&mut fixture, &packet, budget).await)
        .unwrap();
    let record = f.record.physical_publication.record().unwrap();
    assert_eq!(record.encryption().authorized_peer_lifecycle(), None);
    assert!(f.record.expected_target_lifecycle().is_some());
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownOriginalAuthorization
    );
    let (session, _) = sessions();
    budget
        .step(transport.replace_session_for_lifecycle(
            PEER,
            session,
            f.record.expected_target_lifecycle().unwrap(),
        ))
        .await;
    assert_eq!(record.encryption().authorized_peer_lifecycle(), None);
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownOriginalAuthorization
    );
    fixture.finish(budget).await;
}
