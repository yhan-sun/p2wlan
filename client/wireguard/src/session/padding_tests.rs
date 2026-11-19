use super::*;

fn sessions() -> (TransportSession, TransportSession) {
    let make = |send_key, recv_key, our_index, peer_index| {
        TransportSession::new(TransportKeyPair {
            send_key,
            recv_key,
            our_index,
            peer_index,
        })
    };
    (
        make([0x42; 32], [0x73; 32], 1, 2),
        make([0x73; 32], [0x42; 32], 2, 1),
    )
}

fn ipv4(len: usize) -> Vec<u8> {
    let mut packet = vec![0xab; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet
}

fn ipv6(len: usize) -> Vec<u8> {
    let mut packet = vec![0xcd; len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    packet
}

#[test]
fn optional_ip_padding_roundtrips_ipv4_ipv6_and_keeps_one_counter_order() {
    let (mut sender, mut receiver) = sessions();
    for (counter, packet) in [ipv4(29), ipv6(61), ipv4(32), ipv6(80)].iter().enumerate() {
        let prepared = PreparedTransportBuffer::new_with_ip_padding(packet).unwrap();
        let ptr = prepared.buffer().as_ptr();
        let wire = sender.encrypt_into_prepared(packet, prepared).unwrap();
        assert_eq!(wire.as_ptr(), ptr);
        assert_eq!(wire.len(), packet.len().div_ceil(16) * 16 + 32);
        assert_eq!(
            MessageTransport::from_bytes(&wire).unwrap().counter,
            counter as u64
        );
        assert_eq!(receiver.decrypt_from_bytes(&wire).unwrap(), *packet);
        assert!(matches!(
            receiver.decrypt_from_bytes(&wire),
            Err(WireGuardError::ReplayDetected(_))
        ));
    }
}

#[test]
fn optional_ip_padding_respects_exact_path_budget_without_rejecting_original() {
    for packet in [ipv4(29), ipv6(61), ipv4(1167), ipv6(1169)] {
        let padded = packet.len().div_ceil(16) * 16;
        for budget in [packet.len() - 1, packet.len(), padded - 1, padded, 1168] {
            let (mut sender, mut receiver) = sessions();
            let mut prepared = PreparedTransportBuffer::new_with_ip_padding(&packet).unwrap();
            prepared.limit_ip_padding(budget);
            let wire = sender.encrypt_into_prepared(&packet, prepared).unwrap();
            let expected_len = if padded <= budget {
                padded
            } else {
                packet.len()
            };
            assert_eq!(wire.len(), expected_len + 32);
            assert_eq!(receiver.decrypt_from_bytes(&wire).unwrap(), packet);
        }
    }
}

#[test]
fn padding_keeps_legacy_wire_default_and_legacy_ip_length_receiver_compatible() {
    for packet in [ipv4(29), ipv6(61)] {
        let (mut sender, mut receiver) = sessions();
        let wire = sender.encrypt_to_bytes(&packet).unwrap();
        assert_eq!(wire.len(), packet.len() + 32);
        assert_eq!(receiver.decrypt_from_bytes(&wire).unwrap(), packet);

        let prepared = PreparedTransportBuffer::new_with_ip_padding(&packet).unwrap();
        let wire = sender.encrypt_into_prepared(&packet, prepared).unwrap();
        let message = MessageTransport::from_bytes(&wire).unwrap();
        // Model the previous receiver's authenticated plaintext output, then
        // the exact existing DataPlane IP-total-length slice before TUN write.
        let legacy_plain = p2pnet_crypto::aead::decrypt_with_counter(
            &[0x42; 32],
            message.counter,
            b"",
            &message.encrypted_payload,
        )
        .unwrap();
        let total = p2pnet_tun::IpPacket::new(&legacy_plain)
            .unwrap()
            .total_len();
        assert_eq!(&legacy_plain[..total], packet);
    }
}

#[test]
fn padding_never_interprets_non_ip_or_malformed_or_jumbo_inputs() {
    let mut bad_ihl = ipv4(29);
    bad_ihl[0] = 0x4f;
    let mut truncated = ipv4(29);
    truncated[2..4].copy_from_slice(&100u16.to_be_bytes());
    let mut trailed = ipv4(29);
    trailed.push(0);
    let jumbo = ipv6(40);
    for packet in [
        vec![],
        b"non-IP control data".to_vec(),
        bad_ihl,
        truncated,
        trailed,
        jumbo,
    ] {
        let (mut sender, _) = sessions();
        let prepared = PreparedTransportBuffer::new_with_ip_padding(&packet).unwrap();
        assert_eq!(prepared.buffer().len(), packet.len() + 32);
        let wire = sender.encrypt_into_prepared(&packet, prepared).unwrap();
        assert_eq!(wire.len(), packet.len() + 32);
    }
}

#[test]
fn receive_padding_requires_authenticated_zero_suffix_and_bucket_size() {
    for (extra, suffix) in [(3, 0), (3, 1), (2, 0), (19, 0)] {
        let (mut sender, mut receiver) = sessions();
        let original = ipv4(29);
        let mut packet = original.clone();
        packet.resize(packet.len() + extra, suffix);
        let wire = sender.encrypt_to_bytes(&packet).unwrap();
        let expected = if extra == 3 && suffix == 0 {
            &original
        } else {
            &packet
        };
        let mut forged = wire.clone();
        forged[16] ^= 1;
        assert!(matches!(
            receiver.decrypt_from_bytes(&forged),
            Err(WireGuardError::DecryptionFailed)
        ));
        assert_eq!(&receiver.decrypt_from_bytes(&wire).unwrap(), expected);
    }
}

#[test]
fn length_buckets_quantify_synthetic_distribution_without_network_claims() {
    let (mut sender, _) = sessions();
    let mut original_sizes = std::collections::BTreeSet::new();
    let mut bucket_sizes = std::collections::BTreeSet::new();
    let mut added = 0usize;
    let mut baseline_bytes = 0usize;
    for len in 28..=1168 {
        let packet = ipv4(len);
        let prepared = PreparedTransportBuffer::new_with_ip_padding(&packet).unwrap();
        let wire = sender.encrypt_into_prepared(&packet, prepared).unwrap();
        original_sizes.insert(len + 32);
        bucket_sizes.insert(wire.len());
        let overhead = wire.len() - len - 32;
        assert!(overhead <= 15);
        assert!(wire.len() <= 1200);
        added += overhead;
        baseline_bytes += len + 32;
    }
    assert_eq!(original_sizes.len(), 1141);
    assert_eq!(bucket_sizes.len(), 72);
    println!("length_bucket_synthetic packets={} original_distinct_sizes={} padded_distinct_sizes={} added_bytes={} baseline_wire_bytes={} max_added_per_packet=15", original_sizes.len(), original_sizes.len(), bucket_sizes.len(), added, baseline_bytes);
}
