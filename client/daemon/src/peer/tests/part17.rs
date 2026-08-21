#[test]
fn remote_nat_profile_generation_is_monotonic_and_fresh() {
    let mut connection = PeerConnection::new("peer-nat-profile", "10.20.0.2");
    let current = "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7";
    let stale = "p2v2:m=address_or_port_dependent;a=random;d=?;c=40;f=address_dependent;h=unknown;g=6";
    let endpoint = Some("203.0.113.20:41000".parse().unwrap());

    assert!(connection.update_remote_nat_profile(current, endpoint));
    assert_eq!(
        connection
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation),
        Some(7)
    );
    assert!(connection.remote_nat_profile_is_fresh());

    assert!(!connection.update_remote_nat_profile(stale, endpoint));
    let profile = connection.remote_nat_profile.as_ref().unwrap();
    assert_eq!(profile.generation, Some(7));
    assert!(profile.capabilities.prediction_candidate);
}

#[test]
fn legacy_remote_nat_label_cannot_downgrade_versioned_profile() {
    let mut connection = PeerConnection::new("peer-legacy-nat", "10.20.0.3");
    let versioned = "p2v2:m=open;a=stable;d=?;c=80;f=endpoint_independent;h=unknown;g=2";
    let legacy = "p2v2:m=address_or_port_dependent;a=random;d=?;c=20;f=address_dependent;h=unknown";

    assert!(connection.update_remote_nat_profile(versioned, None));
    assert!(!connection.update_remote_nat_profile(legacy, None));
    assert_eq!(
        connection
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation),
        Some(2)
    );
}
