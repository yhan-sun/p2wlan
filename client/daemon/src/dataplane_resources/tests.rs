use super::*;

fn destination(len: usize, capacity: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(capacity);
    bytes.resize(len, 7);
    bytes
}

#[test]
fn pure_actual_vec_dimensions_and_copy_units_are_separate() {
    let capture = ResourceCapture::new([1; 16]);
    let bytes = destination(9, 128);
    assert_eq!(
        capture.observe_vec(
            VecSite::UdpWireCopy,
            VecOperation::SliceCopy,
            Some(9),
            &bytes
        ),
        RecordDisposition::Recorded
    );
    let clone = bytes.clone();
    assert_eq!(
        capture.observe_vec(
            VecSite::UdpWireCopy,
            VecOperation::DeepClone,
            Some(bytes.len()),
            &clone,
        ),
        RecordDisposition::Recorded
    );
    let snapshot = capture.snapshot();
    let site = snapshot.vec_site(VecSite::UdpWireCopy);
    assert_eq!(site.materialization_ops, 2);
    assert_eq!(site.copy_ops, 2);
    assert_eq!(site.known_copied_bytes, 18);
    assert_eq!(site.destination_len_observed_sum, 18);
    assert_eq!(
        site.destination_capacity_observed_sum,
        (bytes.capacity() + clone.capacity()) as u64
    );
    assert!(site.copied_bytes_known);
    assert!(snapshot.valid);
    assert!(!snapshot.coherent);
    assert!(snapshot.read_completed >= snapshot.read_started);
    assert!(!snapshot.allocator_alloc_calls_measured);
    assert!(!snapshot.allocator_free_calls_measured);
}

#[test]
fn pure_output_and_fixed_buffer_observations_do_not_invent_copy_bytes() {
    let capture = ResourceCapture::new([2; 16]);
    let outputs = [
        (
            VecSite::RxAuthenticatedPlaintext,
            VecOperation::CryptoOutput,
        ),
        (VecSite::TxSerializedWire, VecOperation::SerializedOutput),
        (VecSite::UdpReaderBuffer, VecOperation::FixedReadBuffer),
    ];
    for (site, kind) in outputs {
        let bytes = destination(23, 64);
        assert_eq!(
            capture.observe_vec(site, kind, None, &bytes),
            RecordDisposition::Recorded
        );
        let observed = capture.snapshot().vec_site(site);
        assert_eq!(observed.materialization_ops, 1);
        assert_eq!(observed.copy_ops, 0);
        assert_eq!(observed.known_copied_bytes, 0);
        assert_eq!(observed.destination_len_observed_sum, bytes.len() as u64);
        assert_eq!(
            observed.destination_capacity_observed_sum,
            bytes.capacity() as u64
        );
        assert!(!observed.copied_bytes_known);
    }
    let snapshot = capture.snapshot();
    assert!(!snapshot.channel_bytes_measured);
    assert!(!snapshot.session_backlog_measured);
    assert!(!snapshot.active_attempt_bytes_measured);
    assert!(!snapshot.overflow_report_bytes_measured);
    assert!(!snapshot.relay_writer_bytes_measured);
    assert!(!snapshot.crypto_temporaries_measured);
    assert!(!snapshot.kernel_bytes_measured);
    assert!(!snapshot.queue_metadata_bytes_measured);
    assert!(!snapshot.total_pipeline_bytes_measured);
}

#[test]
fn pure_partial_output_counter_reads_cannot_claim_known_copy_units() {
    let capture = ResourceCapture::new([10; 16]);
    // A constructed intermediate counter state, not a scheduling experiment.
    // Counts are incoherent; the fixed unit must nevertheless remain unknown.
    for site in [
        VecSite::UdpReaderBuffer,
        VecSite::RxAuthenticatedPlaintext,
        VecSite::TxSerializedWire,
    ] {
        capture.sites[site.index()]
            .materialization_ops
            .store(1, Ordering::Relaxed);
        let snapshot = capture.snapshot();
        assert!(!snapshot.vec_site(site).copied_bytes_known);
        assert!(!snapshot.coherent);
    }
}

#[test]
fn pure_wrong_site_operation_category_is_rejected_with_unknown_coverage() {
    for (site, operation, copied) in [
        (VecSite::TxRetryCopy, VecOperation::CryptoOutput, None),
        (
            VecSite::RxAuthenticatedPlaintext,
            VecOperation::SliceCopy,
            Some(9),
        ),
        (
            VecSite::TxSerializedWire,
            VecOperation::FixedReadBuffer,
            None,
        ),
    ] {
        let capture = ResourceCapture::new([11; 16]);
        let bytes = destination(9, 16);
        assert_eq!(
            capture.observe_vec(site, operation, copied, &bytes),
            RecordDisposition::InvalidObservation
        );
        let snapshot = capture.snapshot();
        assert!(!snapshot.valid);
        assert_eq!(snapshot.vec_site(site).materialization_ops, 0);
        assert!(!snapshot.vec_site(site).copied_bytes_known);
    }
}

#[test]
fn pure_empty_vec_materialization_is_not_an_allocator_measurement() {
    let capture = ResourceCapture::new([3; 16]);
    let empty = Vec::new();
    assert_eq!(
        capture.observe_vec(
            VecSite::TxRoutedPacketCopy,
            VecOperation::SliceCopy,
            Some(0),
            &empty
        ),
        RecordDisposition::Recorded
    );
    let snapshot = capture.snapshot();
    let observed = snapshot.vec_site(VecSite::TxRoutedPacketCopy);
    assert_eq!(observed.materialization_ops, 1);
    assert_eq!(observed.copy_ops, 1);
    assert_eq!(observed.known_copied_bytes, 0);
    assert_eq!(observed.destination_capacity_observed_sum, 0);
    assert!(!snapshot.allocator_alloc_calls_measured);
    assert!(
        !snapshot
            .vec_site(VecSite::RxParsedPayloadCopy)
            .copied_bytes_known
    );
}

#[test]
fn pure_incompatible_copy_claim_invalidates_coverage_without_recording() {
    for (operation, copied) in [
        (VecOperation::SliceCopy, None),
        (VecOperation::DeepClone, Some(8)),
        (VecOperation::CryptoOutput, Some(9)),
    ] {
        let capture = ResourceCapture::new([4; 16]);
        let bytes = destination(9, 32);
        assert_eq!(
            capture.observe_vec(VecSite::TxPreparationCopy, operation, copied, &bytes),
            RecordDisposition::InvalidObservation
        );
        let snapshot = capture.snapshot();
        assert!(!snapshot.valid);
        assert_ne!(snapshot.gap_bits, 0);
        assert_eq!(
            snapshot
                .vec_site(VecSite::TxPreparationCopy)
                .materialization_ops,
            0
        );
        assert!(
            !snapshot
                .vec_site(VecSite::TxPreparationCopy)
                .copied_bytes_known
        );
        assert_eq!(bytes.len(), 9);
    }
}

#[test]
fn pure_counter_exhaustion_keeps_prior_value_and_marks_unknown() {
    let capture = ResourceCapture::new([5; 16]);
    capture.sites[VecSite::TxRetryCopy.index()]
        .materialization_ops
        .store(u64::MAX, Ordering::Relaxed);
    let bytes = destination(7, 16);
    assert_eq!(
        capture.observe_vec(
            VecSite::TxRetryCopy,
            VecOperation::DeepClone,
            Some(7),
            &bytes
        ),
        RecordDisposition::CounterOverflow
    );
    let snapshot = capture.snapshot();
    assert!(!snapshot.valid);
    assert_eq!(
        snapshot.vec_site(VecSite::TxRetryCopy).materialization_ops,
        u64::MAX
    );
    assert_eq!(snapshot.vec_site(VecSite::TxRetryCopy).copy_ops, 0);
    assert!(!snapshot.vec_site(VecSite::TxRetryCopy).copied_bytes_known);
}

#[test]
fn pure_fifo_leases_follow_move_parallel_batches_and_drop_once() {
    let capture = ResourceCapture::new([6; 16]);
    assert!(!capture
        .snapshot()
        .fifo_scope_observed(QueueStage::ActorFifo));
    assert!(!capture
        .snapshot()
        .fifo_scope_observed(QueueStage::TaskOrUnjoinedFifo));
    let first = destination(11, 128);
    let second = destination(5, 64);
    let mut task = QueueAggregateLease::new(capture.clone(), QueueStage::ActorFifo).unwrap();
    assert_eq!(
        task.set_totals(QueueTotals {
            packets: 1,
            plaintext_len: first.len(),
            vec_capacity: first.capacity()
        }),
        RecordDisposition::Recorded
    );
    assert_eq!(
        task.relocate(QueueStage::TaskOrUnjoinedFifo),
        RecordDisposition::Recorded
    );
    let mut actor = QueueAggregateLease::new(capture.clone(), QueueStage::ActorFifo).unwrap();
    actor.set_totals(QueueTotals {
        packets: 1,
        plaintext_len: second.len(),
        vec_capacity: second.capacity(),
    });
    let moved_task = task;
    let snapshot = capture.snapshot();
    assert!(snapshot.fifo_scope_observed(QueueStage::ActorFifo));
    assert!(snapshot.fifo_scope_observed(QueueStage::TaskOrUnjoinedFifo));
    assert_eq!(
        snapshot.fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot {
            live_packets: 1,
            plaintext_len: 11,
            vec_capacity: first.capacity() as u64
        }
    );
    assert_eq!(
        snapshot.fifo(QueueStage::ActorFifo),
        FifoSnapshot {
            live_packets: 1,
            plaintext_len: 5,
            vec_capacity: second.capacity() as u64
        }
    );
    drop(moved_task);
    assert_eq!(
        capture.snapshot().fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot::default()
    );
    assert_eq!(
        capture.snapshot().fifo(QueueStage::ActorFifo).live_packets,
        1
    );
    drop(actor);
    let final_snapshot = capture.snapshot();
    assert_eq!(
        final_snapshot.fifo(QueueStage::ActorFifo),
        FifoSnapshot::default()
    );
    assert_eq!(
        final_snapshot.fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot::default()
    );
    assert!(final_snapshot.valid);
}

#[test]
fn pure_finish_stops_new_observations_but_preserves_existing_lease_lifetime() {
    let capture = ResourceCapture::new([7; 16]);
    let mut lease = QueueAggregateLease::new(capture.clone(), QueueStage::ActorFifo).unwrap();
    lease.set_totals(QueueTotals {
        packets: 2,
        plaintext_len: 12,
        vec_capacity: 32,
    });
    capture.finish();
    assert!(QueueAggregateLease::new(capture.clone(), QueueStage::ActorFifo).is_none());
    let bytes = destination(6, 16);
    assert_eq!(
        capture.observe_vec(
            VecSite::TxRetryCopy,
            VecOperation::DeepClone,
            Some(6),
            &bytes
        ),
        RecordDisposition::Disabled
    );
    assert_eq!(
        capture.snapshot().fifo(QueueStage::ActorFifo).live_packets,
        2
    );
    assert_eq!(
        lease.set_totals(QueueTotals {
            packets: 1,
            plaintext_len: 6,
            vec_capacity: 16
        }),
        RecordDisposition::Recorded
    );
    assert_eq!(
        lease.relocate(QueueStage::TaskOrUnjoinedFifo),
        RecordDisposition::Recorded
    );
    drop(lease);
    capture.finish();
    let snapshot = capture.snapshot();
    assert!(!snapshot.enabled);
    assert!(snapshot.ended);
    assert!(snapshot.valid);
    assert_eq!(
        snapshot.vec_site(VecSite::TxRetryCopy).materialization_ops,
        0
    );
    assert_eq!(
        snapshot.fifo(QueueStage::ActorFifo),
        FifoSnapshot::default()
    );
    assert_eq!(
        snapshot.fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot::default()
    );
}

#[test]
fn pure_invalid_fifo_totals_and_actual_underflow_are_explicit_gaps() {
    let capture = ResourceCapture::new([8; 16]);
    let mut lease = QueueAggregateLease::new(capture.clone(), QueueStage::ActorFifo).unwrap();
    assert_eq!(
        lease.set_totals(QueueTotals {
            packets: 0,
            plaintext_len: 1,
            vec_capacity: 8
        }),
        RecordDisposition::InvalidObservation
    );
    assert_eq!(
        capture.snapshot().fifo(QueueStage::ActorFifo),
        FifoSnapshot::default()
    );
    lease.set_totals(QueueTotals {
        packets: 1,
        plaintext_len: 5,
        vec_capacity: 8,
    });
    // Inject a damaged diagnostic gauge, without changing the queue owner's local total.
    capture.fifo[QueueStage::ActorFifo.index()]
        .plaintext_len
        .store(0, Ordering::Relaxed);
    drop(lease);
    let snapshot = capture.snapshot();
    assert!(!snapshot.valid);
    assert_ne!(
        snapshot.gap_bits & RecordDisposition::GaugeUnderflow.gap_bit(),
        0
    );
    assert_eq!(snapshot.fifo(QueueStage::ActorFifo).plaintext_len, 0);
    assert_eq!(snapshot.fifo(QueueStage::ActorFifo).live_packets, 0);
}

#[test]
fn pure_same_run_label_does_not_join_distinct_capture_owners() {
    let first = ResourceCapture::new([9; 16]);
    let second = ResourceCapture::new([9; 16]);
    assert_eq!(first.snapshot().scope, second.snapshot().scope);
    assert!(!Arc::ptr_eq(&first, &second));
    let mut lease = QueueAggregateLease::new(first.clone(), QueueStage::ActorFifo).unwrap();
    lease.set_totals(QueueTotals {
        packets: 1,
        plaintext_len: 9,
        vec_capacity: 16,
    });
    assert_eq!(
        second.snapshot().fifo(QueueStage::ActorFifo),
        FifoSnapshot::default()
    );
    second.finish();
    assert!(!first.is_finished());
    drop(lease);
    assert!(first.snapshot().valid);
    assert_eq!(
        first.snapshot().fifo(QueueStage::ActorFifo),
        FifoSnapshot::default()
    );
}
