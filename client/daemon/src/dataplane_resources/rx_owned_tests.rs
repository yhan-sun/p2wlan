use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct ValueWithDrop {
    bytes: Vec<u8>,
    capture: Arc<ResourceCapture>,
    observed_on_drop: Arc<AtomicU64>,
}
impl RxPayload for ValueWithDrop {
    fn payload(&self) -> &Vec<u8> {
        &self.bytes
    }

    fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}
impl Drop for ValueWithDrop {
    fn drop(&mut self) {
        self.observed_on_drop.store(
            self.capture
                .residency_snapshot()
                .total
                .unwrap()
                .live_buffers,
            Ordering::SeqCst,
        );
    }
}

#[test]
fn rx_ownership_observation_still_exists_during_actual_value_destructor() {
    let c = ResourceCapture::new([0xf6; 16]);
    let seen = Arc::new(AtomicU64::new(0));
    let value = ValueWithDrop {
        bytes: vec![0; 19],
        capture: c.clone(),
        observed_on_drop: seen.clone(),
    };
    let owned = RxOwned::observe(value, Some(&c), ResidencyStage::RxParsedPayload);
    drop(owned);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
}

#[test]
fn rx_ownership_mapping_keeps_same_allocation_and_one_lease() {
    let c = ResourceCapture::new([0xf7; 16]);
    let original = RxOwned::observe(
        vec![0x45; 41],
        Some(&c),
        ResidencyStage::RxAuthenticatedPlaintext,
    );
    let pointer = original.as_ptr();
    let capacity = original.capacity();
    let packet = original.map(|packet| crate::dataplane::InboundPacket {
        peer_id: "same-owner".into(),
        packet,
        session_instance: None,
        from_previous_session: false,
        authenticated_ingress: None,
        trace: None,
    });
    assert_eq!(packet.packet.as_ptr(), pointer);
    assert_eq!(packet.packet.capacity(), capacity);
    let s = c.residency_snapshot();
    assert!(s.coherent && s.valid);
    assert_eq!(s.unknown_bits, 0);
    assert_eq!(s.total.unwrap().live_buffers, 1);
    assert_eq!(s.total.unwrap().capacity_bytes, capacity as u64);
    c.finish();
    drop(packet);
    assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
}

#[test]
fn rx_ownership_public_return_marks_unknown_while_original_bytes_remain_alive() {
    let c = ResourceCapture::new([0xf8; 16]);
    let owned = RxOwned::observe(
        vec![7; 43],
        Some(&c),
        ResidencyStage::RxAuthenticatedPlaintext,
    );
    let raw = owned.into_unobserved();
    assert_eq!(raw, vec![7; 43]);
    let s = c.residency_snapshot();
    assert_eq!(s.total.unwrap().live_buffers, 0);
    assert_ne!(s.unknown_bits & 1, 0);
    assert!(!s.whole_pipeline_bytes_measured);
}

#[test]
fn rx_ownership_rebinding_different_sizes_marks_unobserved_intermediate_capacity() {
    let c = ResourceCapture::new([0xf9; 16]);
    let parts = RxOwned::observe(
        vec![1; 47],
        Some(&c),
        ResidencyStage::RxAuthenticatedPlaintext,
    )
    .into_parts();
    let lease = parts.0;
    let old = parts.1;
    drop(old);
    let rebound = RxOwned::from_parts(vec![2; 53], lease);
    let s = c.residency_snapshot();
    assert!(s.coherent && s.valid);
    assert_ne!(s.unknown_bits & 2, 0);
    assert_eq!(s.total.unwrap().len_bytes, 53);
    drop(rebound);
    assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
}
