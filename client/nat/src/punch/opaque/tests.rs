use super::*;

#[test]
fn opaque_probe_round_trip_rotates_labels_and_keeps_scoped_authentication() {
    let identity_key = [3; 32];
    let scoped_key = [7; 32];
    let (frame, nonce) = build_opaque_punch_packet_with_nomination(
        "stable-node-a",
        "stable-node-b",
        9,
        true,
        &identity_key,
        &scoped_key,
    );
    assert!(!frame
        .windows(13)
        .any(|bytes| bytes == b"stable-node-a" || bytes == b"stable-node-b"));
    let identity = peek_authenticated_punch_identity(&frame).unwrap();
    assert_eq!(identity.version, OPAQUE_PUNCH_VERSION);
    assert_eq!(
        identity.source_node_id,
        opaque_probe_identity(&identity_key, "stable-node-a")
    );
    assert_ne!(
        identity.source_node_id,
        opaque_probe_identity(&[4; 32], "stable-node-a")
    );
    assert!(decode_authenticated_punch_packet(&frame, &identity_key).is_none());
    let packet = decode_authenticated_punch_packet(&frame, &scoped_key).unwrap();
    assert!(packet.authenticated && packet.use_candidate);
    let ack = build_authenticated_punch_ack_for_received(
        &packet,
        "stable-node-b",
        "stable-node-a",
        10,
        &scoped_key,
    )
    .unwrap();
    let ack = decode_authenticated_punch_packet(&ack, &scoped_key).unwrap();
    assert_eq!(ack.version, OPAQUE_PUNCH_VERSION);
    assert_eq!(ack.nonce, nonce);
    assert_eq!(ack.source_node_id, packet.target_node_id);
    assert_eq!(ack.target_node_id, packet.source_node_id);
}

#[test]
fn opaque_probe_rejects_tampering_truncation_and_version_downgrade() {
    let key = [2; 32];
    let (frame, _) = build_opaque_punch_packet_with_nomination("a", "b", 1, false, &key, &key);
    for length in 0..frame.len() {
        assert!(decode_authenticated_punch_packet(&frame[..length], &key).is_none());
    }
    for index in [4, 6, 14, 22, 25, frame.len() - 1] {
        let mut invalid = frame.clone();
        invalid[index] ^= 1;
        assert!(decode_authenticated_punch_packet(&invalid, &key).is_none());
    }
    let mut downgraded = frame.clone();
    downgraded[4] = 2;
    assert!(decode_authenticated_punch_packet(&downgraded, &key).is_none());
    let (legacy, _) = build_authenticated_punch_packet("a", "b", 1, &key);
    assert_eq!(
        decode_authenticated_punch_packet(&legacy, &key)
            .unwrap()
            .version,
        2
    );
}
