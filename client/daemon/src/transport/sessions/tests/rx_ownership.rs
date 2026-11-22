use super::*;
use crate::dataplane_resources::{ResidencyStage, ResourceCapture};
use std::{
    future::{poll_fn, Future},
    task::Poll,
};

fn pair(index: u32) -> (TransportSession, TransportSession) {
    let local = TransportSession::new(p2pnet_wireguard::TransportKeyPair {
        send_key: [1; 32],
        recv_key: [2; 32],
        our_index: index,
        peer_index: index + 1,
    });
    let remote = TransportSession::new(p2pnet_wireguard::TransportKeyPair {
        send_key: [2; 32],
        recv_key: [1; 32],
        our_index: index + 1,
        peer_index: index,
    });
    (remote, local)
}

#[tokio::test]
async fn rx_ownership_parsed_payload_lives_during_original_session_lock_wait() {
    let c = ResourceCapture::new([0xe1; 16]);
    let (t, _out) = WireGuardTransport::new_for_daemon(false, Some(c.clone()));
    let (mut remote, _local) = pair(77);
    let wire = remote.encrypt_to_bytes(b"parsed-wait-owner").unwrap();
    let lock = t.sessions.lock().await;
    let mut future = Box::pin(t.decrypt_inbound_with_source(&wire));
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let s = c.residency_snapshot();
    assert!(s.coherent && s.valid);
    assert_eq!(s.unknown_bits, 0);
    assert_eq!(
        s.stage(ResidencyStage::RxParsedPayload)
            .unwrap()
            .live_buffers,
        1
    );
    assert_eq!(
        s.stage(ResidencyStage::RxParsedPayload).unwrap().len_bytes,
        wire.len() as u64 - 16
    );
    assert_eq!(
        s.stage(ResidencyStage::RxAuthenticatedPlaintext)
            .unwrap()
            .live_buffers,
        0
    );
    drop(future);
    assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
    drop(lock);
}

async fn pending_wait(cancel: bool) {
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    let c = ResourceCapture::new([0xe2; 16]);
    let (t, _out) = WireGuardTransport::new_for_daemon(false, Some(c.clone()));
    let (mut remote, local) = pair(81);
    assert!(matches!(
        t.stage_responder_session("resource-peer", "owner-pending".into(), local)
            .await,
        ResponderSessionStage::Staged { .. }
    ));
    let emit = t.outbound_emit_lock("resource-peer").await;
    let guard = emit.lock().await;
    let plaintext = b"real-authenticated-before-original-promotion";
    let wire = remote.encrypt_to_bytes(plaintext).unwrap();
    let mut future = Box::pin(t.decrypt_inbound_with_source(&wire));
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let s = c.residency_snapshot();
    assert!(s.coherent && s.valid);
    let held = s.stage(ResidencyStage::RxAuthenticatedPlaintext).unwrap();
    assert_eq!(held.live_buffers, 1);
    assert_eq!(held.len_bytes, plaintext.len() as u64);
    assert_eq!(
        s.stage(ResidencyStage::RxParsedPayload)
            .unwrap()
            .live_buffers,
        1
    );
    assert_eq!(s.total.unwrap().live_buffers, 2);
    c.finish();
    assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 2);
    if cancel {
        drop(future);
        assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
        assert!(!t.session_status("resource-peer").await.has_active);
        drop(guard);
    } else {
        drop(guard);
        let result = tokio::time::timeout_at(end, future.as_mut())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.packet.packet, plaintext);
        assert_eq!(result.packet.packet.capacity() as u64, held.capacity_bytes);
        assert_eq!(
            c.residency_snapshot()
                .stage(ResidencyStage::RxParsedPayload)
                .unwrap()
                .live_buffers,
            0
        );
        assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 1);
        drop(result);
        drop(future);
        assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
        assert!(t.session_status("resource-peer").await.has_active);
    }
}

#[tokio::test]
async fn rx_ownership_pending_plaintext_cancel_drains_without_promotion() {
    pending_wait(true).await;
}
#[tokio::test]
async fn rx_ownership_pending_plaintext_original_handoff_keeps_exact_capacity() {
    pending_wait(false).await;
}

#[tokio::test]
async fn rx_ownership_active_and_previous_keys_retain_actual_plaintext_and_reject_replay() {
    for previous in [false, true] {
        let c = ResourceCapture::new([0xe3; 16]);
        let (t, _out) = WireGuardTransport::new_for_daemon(false, Some(c.clone()));
        let (mut remote, local) = pair(91);
        assert!(!t.add_session("resource-peer", local).await);
        if previous {
            let (_, new_local) = pair(101);
            assert!(t.add_session("resource-peer", new_local).await);
        }
        let plaintext = b"exact-original-owner-payload";
        let wire = remote.encrypt_to_bytes(plaintext).unwrap();
        let result = t.decrypt_inbound_with_source(&wire).await.unwrap().unwrap();
        assert_eq!(result.packet.packet, plaintext);
        assert_eq!(result.packet.from_previous_session, previous);
        assert!(result.packet.session_instance.is_some());
        let s = c.residency_snapshot();
        assert!(s.coherent && s.valid);
        assert_eq!(s.unknown_bits, 0);
        let held = s.stage(ResidencyStage::RxAuthenticatedPlaintext).unwrap();
        assert_eq!(held.live_buffers, 1);
        assert_eq!(held.len_bytes, result.packet.packet.len() as u64);
        assert_eq!(held.capacity_bytes, result.packet.packet.capacity() as u64);
        assert_eq!(
            s.stage(ResidencyStage::RxParsedPayload)
                .unwrap()
                .live_buffers,
            0
        );
        assert!(matches!(t.decrypt_inbound_with_source(&wire).await,Err(e)if e.is_replay()));
        assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 1);
        drop(result);
        assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
    }
}

#[tokio::test]
async fn rx_ownership_malformed_and_unknown_receiver_have_no_authenticated_owner() {
    let c = ResourceCapture::new([0xe4; 16]);
    let (t, _out) = WireGuardTransport::new_for_daemon(false, Some(c.clone()));
    assert!(t.decrypt_inbound_with_source(b"bad").await.is_err());
    assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
    let (mut remote, _local) = pair(111);
    let wire = remote.encrypt_to_bytes(b"no-installed-session").unwrap();
    assert!(t
        .decrypt_inbound_with_source(&wire)
        .await
        .unwrap()
        .is_none());
    let s = c.residency_snapshot();
    assert!(s.coherent && s.valid);
    assert_eq!(s.unknown_bits, 0);
    assert_eq!(s.total.unwrap().live_buffers, 0);
    assert!(!s.observed[ResidencyStage::RxAuthenticatedPlaintext as usize]);
}

#[tokio::test]
async fn tcp_reader_peer_is_checked_before_consuming_the_wireguard_counter() {
    let (transport, _) = WireGuardTransport::new();
    let (mut remote, local) = pair(73);
    transport.add_session("session-owner", local).await;
    let wire = remote
        .encrypt_to_bytes(b"ordered application payload")
        .unwrap();
    let mismatched = transport
        .decrypt_inbound_for_peer(&wire, Some("other-reader"))
        .await;
    assert!(!matches!(mismatched, Ok(Some(_))));
    let received = transport
        .decrypt_inbound_for_peer(&wire, Some("session-owner"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.packet.peer_id, "session-owner");
    assert_eq!(received.packet.packet, b"ordered application payload");
    assert!(
        matches!(transport.decrypt_inbound_for_peer(&wire, Some("session-owner")).await, Err(error) if error.is_replay())
    );
}
