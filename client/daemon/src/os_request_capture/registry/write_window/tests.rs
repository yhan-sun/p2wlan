//! Pure input controls; no clock, system read/write, Full or owner is forged.
use super::*;

#[cfg(unix)]
mod expected;
#[cfg(unix)]
mod selection;

fn labels() -> WireWriteWindow {
    serde_json::from_value(serde_json::json!({
        "producer_scope":"abcdefabcdefabcdefabcdefabcdefab", "sequence":0,
        "request_nonce":"ab".repeat(16),
        "boot_id":"11111111-2222-3333-4444-555555555555",
        "original_started_ns":1_000_000_000u64, "original_sent_ns":1_000_000_000u64,
        "original_deadline_ns":2_000_000_000u64, "complete_returned_ns":1_000_000_001u64,
        "frame_bytes":191, "frame_sha256":"a".repeat(64)
    }))
    .unwrap()
}

// Frozen from the unchanged OS tool encode functions, including TCP's actual
// four-byte write_frame prefix. Pure byte vectors are not native I/O facts.
const UDP_REQUESTS: [&str; 8] = [
    "3112ea4c5b2a36e2de4f99fd4140e170673d4b220c857e7d0710b825e408eec6",
    "0d5eabb0225e6ca59eedc3a7471aa60d1959b0ab83f09aa27948b82cd933f383",
    "8ecfe63fa08518e853ffc69d63da7a78f08d6279d6b657b18adc75c32ee539c6",
    "6fe88609a190f263f1f30d2ea9187ff67b19e8aae554fdbf7074428af756c9a8",
    "5434bd1871cf0f075e65198ab4e8022dacba897dde38b50825f6b9d54e59462e",
    "1baa01009717eaed60b0ae4641cae2a67f9c95aa6a239f8dd6e1332ea68be4b7",
    "5405bb370c14cf7fcf2d31576927c66a6a70557b494b9d52070ec91628a7f11a",
    "97de10839d6de064cdac6663f092b9dc3c12ecaa07bac3893ec0eb575d8c3a8d",
];
const TCP_REQUESTS: [&str; 8] = [
    "9ba4a048a07d756abf2a6889fd5353355bcfc2d6b5e7b8f690a3ec5ecd6cd4c6",
    "229f2e8f77d28e9ecebb8d5a092c43578e6b3a60417352daa65970d4eaf56054",
    "9639fb6bd42490052cc0bcad5c4c45034a1687f879ef0bf88839c1e79911ad3a",
    "86fce90c0aa3adbfb0e905d9b05bda35e7adb24a99a7ca807f21816aed09d2bf",
    "9dc72e3c403f5c3d0182e4be6bea57e7dee505aa028c8e7f34ae199dc8e96f96",
    "623ddf8017aa4fe662a9c2fe5921c48b30f503bfb83fbbe53890f7dd569a6035",
    "bcc41c565f2587f2cbf5ce21779e4f5fbba4a66e9f9e018391a7d52f411e87de",
    "888177e98379c842ef47bc4466092ee1dae673521278f5f6312a0883d082cf15",
];

fn registered(protocol: &str, kind: &str) -> RegisteredFlowPlan {
    let value = serde_json::json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[{
            "protocol":protocol,"kind":kind,"peer_id":"window-frame-peer",
            "run_nonce":"33".repeat(16),"round_nonce":"44".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":(1..=8).map(|i|format!("{i:032x}")).collect::<Vec<_>>()}]});
    super::super::super::plan::RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .flows
        .remove(0)
}

#[test]
fn window_registered_validation_preserves_full_original_result_after_post_wait_clock_check() {
    for protocol in ["udp", "tcp"] {
        let plan = Arc::new(registered(protocol, "response"));
        let prepared = OriginalWindowPlan {
            producer: [0x22; 16],
            flow: 0,
            plan,
        };
        let frame_bytes = 191 + usize::from(protocol == "tcp") * 4;
        let expected_nonce = prepared.plan.requests[0].request_nonce;
        for mutation in 0..7 {
            let mut wire = labels();
            wire.frame_bytes = frame_bytes;
            wire.producer_scope = hex::encode(prepared.producer);
            wire.request_nonce = hex::encode(expected_nonce);
            match mutation {
                1 => wire.request_nonce = "00".repeat(16),
                2 => wire.frame_bytes += 1,
                3 => wire.original_deadline_ns += 1,
                4 => wire.frame_sha256 = "A".repeat(64),
                5 => wire.producer_scope = "z".repeat(32),
                6 => wire.boot_id.clear(),
                _ => {}
            }
            for now in [1_000_000_000, 1_000_000_001, 1_999_999_999, 2_000_000_000] {
                let original = wire.validate(now, frame_bytes, &expected_nonce);
                let prepared_result = prepared
                    .validate_registered_wire(&wire, 1_000_000_002)
                    .and_then(|producer| {
                        if now < wire.complete_returned_ns || now >= wire.original_deadline_ns {
                            Err(CaptureFailure::InvalidPlan)
                        } else {
                            Ok(producer)
                        }
                    });
                assert_eq!(format!("{original:?}"), format!("{prepared_result:?}"));
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn window_registered_validation_uses_frozen_plan_without_reacquiring_actual_registry_mutex() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let prepared = setup
        .session
        .original_window_plan([0x22; 16], end)
        .await
        .unwrap();
    let held = setup.session.state.lock().unwrap();
    let mut wire = labels();
    wire.producer_scope = hex::encode(prepared.producer);
    wire.request_nonce = hex::encode(prepared.plan.requests[0].request_nonce);
    assert!(prepared
        .validate_registered_wire(&wire, 1_000_000_002)
        .is_ok());
    assert!(matches!(
        setup.session.state.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    assert!(prepared.is_current(0, &held.flows[0]));
    drop(held);
    digest_no_credit(&setup.session);
}

#[test]
fn original_write_window_digest_matches_tool_requests_in_both_registered_directions() {
    for (protocol, digests) in [("udp", UDP_REQUESTS), ("tcp", TCP_REQUESTS)] {
        for kind in ["request", "response"] {
            let plan = registered(protocol, kind);
            for (slot, digest) in digests.iter().enumerate() {
                let mut wire = labels();
                wire.sequence = slot as u32;
                wire.frame_sha256 = (*digest).into();
                assert!(
                    wire.matches_registered_request_frame(&plan),
                    "{protocol}/{kind}/{slot}"
                );
            }
        }
    }
}

#[test]
fn original_write_window_digest_binds_run_round_full_nonce_sequence_and_protocol() {
    let mut wire = labels();
    wire.frame_sha256 = UDP_REQUESTS[0].into();
    assert!(wire.matches_registered_request_frame(&registered("udp", "request")));
    for index in [0usize, 8, 15] {
        for field in 0..3 {
            let mut plan = registered("udp", "request");
            match field {
                0 => plan.requests[0].run[index] ^= 1,
                1 => plan.requests[0].round[index] ^= 1,
                _ => plan.requests[0].request_nonce[index] ^= 1,
            }
            assert!(!wire.matches_registered_request_frame(&plan));
        }
    }
    assert!(!wire.matches_registered_request_frame(&registered("tcp", "request")));
    wire.sequence = 1;
    assert!(!wire.matches_registered_request_frame(&registered("udp", "request")));
    wire.sequence = 8;
    assert!(!wire.matches_registered_request_frame(&registered("udp", "request")));
}

#[test]
fn original_write_window_digest_rejects_unmatched_bytes_and_payload_contract() {
    let mut wire = labels();
    // A syntactically valid 64-byte digest alone is never an exact frame match.
    assert!(!wire.matches_registered_request_frame(&registered("udp", "request")));
    for digest in [
        "f".repeat(64),
        "0".repeat(64),
        UDP_REQUESTS[7].into(),
        TCP_REQUESTS[0].into(),
    ] {
        wire.frame_sha256 = digest;
        assert!(!wire.matches_registered_request_frame(&registered("udp", "request")));
    }
    wire.frame_sha256 = UDP_REQUESTS[0].into();
    let mut plan = registered("udp", "request");
    plan.payload_bytes = 127;
    assert!(!wire.matches_registered_request_frame(&plan));
}

#[test]
fn original_write_window_keeps_original_half_open_deadline_and_frame_size() {
    let wire = labels();
    assert!(wire.validate(1_000_000_001, 191, &[0xab; 16]).is_ok());
    assert!(wire.validate(1_999_999_999, 191, &[0xab; 16]).is_ok());
    assert!(wire.validate(2_000_000_000, 191, &[0xab; 16]).is_err());
    assert!(wire.validate(1_000_000_000, 191, &[0xab; 16]).is_err());
    assert!(wire.validate(1_000_000_002, 195, &[0xab; 16]).is_err());
}

#[test]
fn original_write_window_rejects_refill_overflow_wrong_sequence_and_digest() {
    let mut wire = labels();
    wire.original_deadline_ns += 1;
    assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
    wire = labels();
    wire.sequence = 1;
    assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
    wire = labels();
    wire.original_started_ns = u64::MAX;
    assert!(wire.validate(u64::MAX, 191, &[0xab; 16]).is_err());
    wire = labels();
    wire.frame_sha256 = "A".repeat(64);
    assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
}

#[test]
fn original_write_window_labels_cannot_deserialize_native_authority() {
    let mut value = serde_json::to_value(serde_json::json!({
        "producer_scope":"abcdefabcdefabcdefabcdefabcdefab", "sequence":0,
        "request_nonce":"ab".repeat(16),
        "boot_id":"11111111-2222-3333-4444-555555555555",
        "original_started_ns":1, "original_sent_ns":1,
        "original_deadline_ns":1_000_000_001u64, "complete_returned_ns":2,
        "frame_bytes":191, "frame_sha256":"a".repeat(64)
    }))
    .unwrap();
    for field in [
        "kernel_read",
        "native_os_write_verified",
        "canonical_current_owner_verified",
    ] {
        value[field] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<WireWriteWindow>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove(field);
    }
}

#[test]
fn original_write_window_matches_all_128_nonce_bits() {
    let mut wire = labels();
    for index in [0usize, 8, 15] {
        let mut nonce = [0xab; 16];
        nonce[index] ^= 1;
        wire.request_nonce = hex::encode(nonce);
        assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
    }
}

// Real descriptor/metadata lock controls only. These expected input plans never
// construct a KernelRead, Full, SystemTun write or current-owner permit.
#[cfg(unix)]
async fn digest_scope() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = super::super::full::tests::descriptor_scope().await;
    setup
        .session
        .register(super::super::super::plan::RegistrationPlan {
            capture_id: setup.session.capture_id,
            producer_scope: [0x22; 16],
            flows: vec![registered("udp", "response")],
        })
        .unwrap();
    (setup, parent)
}

#[cfg(unix)]
fn digest_no_credit(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["historical_full_packets"], serde_json::json!([]));
    assert_eq!(value["system_tun_full_writes"], serde_json::json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[cfg(unix)]
#[tokio::test]
async fn window_digest_unlocked_hash_uses_original_plan_while_real_metadata_mutex_is_held() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let prepared = setup
        .session
        .original_window_plan([0x22; 16], end)
        .await
        .unwrap();
    let mut wire = labels();
    wire.frame_sha256 = UDP_REQUESTS[0].into();
    {
        let held = setup.session.state.try_lock().unwrap();
        assert!(wire.matches_registered_request_frame(&prepared.plan));
        assert!(prepared.is_current(0, &held.flows[0]));
        wire.frame_sha256 = TCP_REQUESTS[0].into();
        assert!(!wire.matches_registered_request_frame(&prepared.plan));
    }
    digest_no_credit(&setup.session);
}

#[cfg(unix)]
#[tokio::test]
async fn window_digest_unlocked_hash_rejects_equal_bytes_replacement_wrong_flow_and_producer() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let prepared = setup
        .session
        .original_window_plan([0x22; 16], end)
        .await
        .unwrap();
    {
        let mut state = setup.session.state.try_lock().unwrap();
        assert!(prepared.is_current(0, &state.flows[0]));
        assert!(!prepared.is_current(1, &state.flows[0]));
        state.flows[0].producer_scope = [0x23; 16];
        assert!(!prepared.is_current(0, &state.flows[0]));
        state.flows[0].producer_scope = [0x22; 16];
        state.flows[0].plan = Arc::new(registered("udp", "response"));
        assert!(!prepared.is_current(0, &state.flows[0]));
        let mut wire = labels();
        wire.frame_sha256 = UDP_REQUESTS[0].into();
        assert!(wire.matches_registered_request_frame(&state.flows[0].plan));
    }
    digest_no_credit(&setup.session);
}

#[cfg(unix)]
#[tokio::test]
async fn window_digest_unlocked_hash_keeps_scope_fixed_eight_and_retirement_guards() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    assert!(matches!(
        setup.session.original_window_plan([0x23; 16], end).await,
        Err(CaptureFailure::InvalidPlan)
    ));
    setup.session.state.lock().unwrap().flows[0].requests.pop();
    assert!(matches!(
        setup.session.original_window_plan([0x22; 16], end).await,
        Err(CaptureFailure::InvalidPlan)
    ));
    setup.session.retire();
    assert!(matches!(
        setup.session.original_window_plan([0x22; 16], end).await,
        Err(CaptureFailure::Expired)
    ));
    digest_no_credit(&setup.session);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn window_digest_unlocked_hash_never_refills_end_while_actual_registry_is_contended() {
    let (setup, _parent) = digest_scope().await;
    let session = setup.session.clone();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let owner = std::thread::spawn(move || {
        let _guard = session.state.lock().unwrap();
        acquired_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    });
    acquired_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    let end = tokio::time::Instant::now() + std::time::Duration::from_millis(20);
    let refused = setup.session.original_window_plan([0x22; 16], end).await;
    release_tx.send(()).unwrap();
    owner.join().unwrap();
    assert!(matches!(refused, Err(CaptureFailure::ControlNotReady)));
    assert!(matches!(
        setup.session.original_window_plan([0x22; 16], end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    digest_no_credit(&setup.session);
}

mod separate_owner;
