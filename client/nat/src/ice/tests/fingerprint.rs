// R1 fingerprint-hint tests: exhaustive label length, byte-for-byte
// `m=`/`a=`/`d=`/`c=` compatibility, parse round-trip, bare/corrupted
// handling, and the structural proof that the `f=` axis contributes nothing
// under R1's static inference (so `scatter_decision` cannot move).
//
// Included into `ice::tests` (see tests.rs), which already does
// `use super::*;`, so all `ice` items are in scope — no re-import here.

/// Build a fully-controlled `NatProfile` for label/parse tests.  Allocation is
/// driven by `udp_blocked` / `prediction_candidate` / `port_delta` /
/// `likely_symmetric` exactly as in `control_label`, so callers pin those to
/// steer `a=`.  `MappingLifetime` is deliberately left at `Unknown`: it is NOT
/// serialized into the control label, so it cannot affect length or round-trip
/// (this is a non-goal for R1, kept constant here to avoid a false axis).
#[allow(clippy::too_many_arguments)]
fn fingerprint_profile(
    mapping: MappingBehavior,
    filtering: FilteringBehavior,
    hairpin: HairpinBehavior,
    udp_blocked: bool,
    prediction_candidate: bool,
    port_delta: Option<i32>,
    likely_symmetric: Option<bool>,
    confidence: u8,
) -> NatProfile {
    NatProfile {
        local_addr: "192.168.1.2:5000".to_string(),
        observations: Vec::new(),
        udp_blocked,
        public_endpoint: None,
        public_ip_stable: None,
        public_port_stable: None,
        port_preserved: None,
        port_delta,
        likely_symmetric,
        mapping_behavior: mapping,
        filtering_behavior: filtering,
        hairpin_behavior: hairpin,
        mapping_lifetime: MappingLifetime::Unknown,
        prediction_candidate,
        predicted_endpoints: Vec::new(),
        birthday_candidate: false,
        confidence,
    }
}

fn all_mappings() -> [MappingBehavior; 5] {
    [
        MappingBehavior::Unknown,
        MappingBehavior::UdpBlocked,
        MappingBehavior::OpenInternet,
        MappingBehavior::EndpointIndependent,
        MappingBehavior::AddressOrPortDependent,
    ]
}
fn all_filterings() -> [FilteringBehavior; 6] {
    [
        FilteringBehavior::Unknown,
        FilteringBehavior::EndpointIndependent,
        FilteringBehavior::LikelyEndpointIndependent,
        FilteringBehavior::AddressDependent,
        FilteringBehavior::AddressOrPortDependent,
        FilteringBehavior::UdpBlocked,
    ]
}
fn all_hairpins() -> [HairpinBehavior; 4] {
    [
        HairpinBehavior::Unknown,
        HairpinBehavior::Supported,
        HairpinBehavior::Unsupported,
        HairpinBehavior::NotApplicable,
    ]
}

/// Exhaustive: every (mapping × filtering × hairpin) combo stays within the
/// server's 128-byte `nat_type` cap.  This supersedes the old ad-hoc `<= 64`
/// assertion that guarded only one profile.
#[test]
fn test_control_label_all_enum_combos_within_128() {
    for &mapping in all_mappings().iter() {
        for &filtering in all_filterings().iter() {
            for &hairpin in all_hairpins().iter() {
                let profile = fingerprint_profile(
                    mapping,
                    filtering,
                    hairpin,
                    false,
                    false,
                    Some(12345), // widest plausible delta token
                    Some(true),
                    100,
                );
                let label = profile.control_label();
                assert!(
                    label.len() <= 128,
                    "label exceeds server cap ({len} bytes): {label}",
                    len = label.len()
                );
            }
        }
    }
}

/// The `m=`/`a=`/`d=`/`c=` region must be byte-for-byte the historical label
/// (only the `p2:` → `p2v2:` prefix changes and `;f=`/`;h=` are appended).
/// This is what keeps an old client's `.contains("a=linear")` heuristics
/// matching a new label.
#[test]
fn test_control_label_madc_fragments_byte_identical_to_legacy() {
    // stable / endpoint-independent
    let p = fingerprint_profile(
        MappingBehavior::EndpointIndependent,
        FilteringBehavior::Unknown,
        HairpinBehavior::Unknown,
        false,
        false,
        Some(0),
        None,
        70,
    );
    assert_eq!(
        p.control_label(),
        "p2v2:m=endpoint_independent;a=stable;d=0;c=70;f=unknown;h=unknown"
    );

    // linear / address-or-port-dependent
    let p = fingerprint_profile(
        MappingBehavior::AddressOrPortDependent,
        FilteringBehavior::Unknown,
        HairpinBehavior::Unknown,
        false,
        true,
        Some(32),
        Some(true),
        90,
    );
    assert_eq!(
        p.control_label(),
        "p2v2:m=address_or_port_dependent;a=linear;d=32;c=90;f=unknown;h=unknown"
    );

    // blocked (udp) — allocation `blocked` takes precedence over everything
    let p = fingerprint_profile(
        MappingBehavior::UdpBlocked,
        FilteringBehavior::UdpBlocked,
        HairpinBehavior::Unknown,
        true,
        false,
        None,
        None,
        60,
    );
    assert_eq!(
        p.control_label(),
        "p2v2:m=blocked;a=blocked;d=?;c=60;f=udp_blocked;h=unknown"
    );

    // open internet — hairpin becomes `not_applicable`, filtering `endpoint_independent`
    let p = fingerprint_profile(
        MappingBehavior::OpenInternet,
        FilteringBehavior::EndpointIndependent,
        HairpinBehavior::NotApplicable,
        false,
        false,
        None,
        None,
        40,
    );
    assert_eq!(
        p.control_label(),
        "p2v2:m=open;a=stable;d=?;c=40;f=endpoint_independent;h=not_applicable"
    );
}

/// Round-trip: `parse_nat_hint(control_label(p))` recovers m/a/f/h of `p`
/// (a is the derived allocation, f/h are the enums), for every combo.
#[test]
fn test_parse_roundtrip_recovers_mapping_allocation_filtering_hairpin() {
    for &mapping in all_mappings().iter() {
        for &filtering in all_filterings().iter() {
            for &hairpin in all_hairpins().iter() {
                // Pin allocation to a few representative values by varying the
                // driving fields, and round-trip each.
                for (udp_blocked, prediction, delta, likely_sym) in [
                    (false, false, None, None),
                    (false, false, None, Some(true)),
                    (false, true, Some(7), None),
                    (true, false, None, None),
                ] {
                    let profile = fingerprint_profile(
                        mapping,
                        filtering,
                        hairpin,
                        udp_blocked,
                        prediction,
                        delta,
                        likely_sym,
                        55,
                    );
                    let label = profile.control_label();
                    let hint = parse_nat_hint(&label);
                    assert!(hint.parsed, "label must parse: {label}");
                    assert_eq!(hint.mapping, mapping, "m mismatch: {label}");
                    assert_eq!(hint.filtering, filtering, "f mismatch: {label}");
                    assert_eq!(hint.hairpin, hairpin, "h mismatch: {label}");
                    assert_eq!(hint.allocation, expected_allocation(&profile), "a mismatch: {label}");
                    assert_eq!(hint.confidence, Some(55), "c mismatch: {label}");
                    assert_eq!(hint.port_delta, profile.port_delta, "d mismatch: {label}");
                }
            }
        }
    }
}

/// Mirror of `control_label`'s allocation derivation, used only to assert the
/// round-tripped `a=` equals the source profile's derived allocation.
fn expected_allocation(p: &NatProfile) -> NatAllocation {
    if p.udp_blocked {
        NatAllocation::Blocked
    } else if p.prediction_candidate && p.port_delta.is_some() {
        NatAllocation::Linear
    } else if matches!(
        p.mapping_behavior,
        MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
    ) {
        NatAllocation::Stable
    } else if p.likely_symmetric == Some(true) {
        NatAllocation::Random
    } else {
        NatAllocation::Unknown
    }
}

/// Old `p2:` labels (no `f=`/`h=`) parse with `f`/`h == Unknown`, `parsed`,
/// and reproduce the pre-R1 scatter inputs exactly.
#[test]
fn test_parse_old_p2_label_yields_unknown_f_h() {
    let hint = parse_nat_hint("p2:m=endpoint_independent;a=stable;d=0;c=70");
    assert!(hint.parsed);
    assert_eq!(hint.mapping, MappingBehavior::EndpointIndependent);
    assert_eq!(hint.allocation, NatAllocation::Stable);
    assert_eq!(hint.filtering, FilteringBehavior::Unknown);
    assert_eq!(hint.hairpin, HairpinBehavior::Unknown);
    assert_eq!(hint.port_delta, Some(0));
    assert_eq!(hint.confidence, Some(70));
}

/// Bare words and corrupted inputs are NOT parsed — the consumer falls back to
/// the legacy classifier on the raw string (never panics, never changes).
#[test]
fn test_parse_bare_and_corrupted_not_parsed() {
    for bad in ["", "symmetric", "address_or_port_dependent", "Confluence", "p2v2:garbage", "p2:!!!"]
    {
        let hint = parse_nat_hint(bad);
        assert!(!hint.parsed, "must not parse a bare/corrupted input: {bad:?}");
        assert_eq!(hint.filtering, FilteringBehavior::Unknown);
        assert_eq!(hint.hairpin, HairpinBehavior::Unknown);
        assert_eq!(hint.mapping, MappingBehavior::Unknown);
    }
}

/// A PREFIX-correct label with a corrupted TOKEN must also fail to parse (not
/// silently read the bad value as `Unknown`).  This is the strict-fallback
/// guarantee: e.g. a truncated `m=address_or_port_dependentX` must fall back to
/// the legacy wide-`contains`, which DOES match that substring and scatter —
/// reading it as `Unknown` would under-scatter and regress.
#[test]
fn test_parse_corrupted_token_value_not_parsed() {
    for bad in [
        "p2v2:m=address_or_port_dependentX;a=linear;d=32;c=90;f=unknown;h=unknown", // truncated m
        "p2v2:m=bogus_token;a=stable;d=0;c=70;f=unknown;h=unknown",             // unknown m value
        "p2v2:m=open;a=sometimes;d=0;c=70;f=unknown;h=unknown",                 // unknown a value
        "p2v2:m=open;a=stable;d=0;c=999;f=unknown;h=unknown",                   // c out of u8 range
        "p2v2:m=open;a=stable;d=-5;c=70;f=unknown;h=unknown",                   // negative d
        "p2v2:m=open;a=stable;d=0;c=70;f=weird;h=unknown",                      // unknown f value
        "p2v2:m=open;a=stable;d=0;c=70;f=unknown;h=maybe",                      // unknown h value
        "p2v2:m=open;a=stable;d=0;c=70;z=9;f=unknown;h=unknown",                // unrecognized key
    ] {
        let hint = parse_nat_hint(bad);
        assert!(!hint.parsed, "corrupted token must not parse: {bad:?}");
    }
}

/// Structural no-regression at the *inference* level: for every mapping
/// behavior, the static-inferred filtering (via the REAL production
/// `infer_filtering_behavior`) satisfies `f == apd  =>  m == apd`.  That
/// implication is the guarantee behind "the f axis contributes nothing in
/// R1": whenever the f-term of `scatter_decision` could fire, the m-axis
/// base term has already fired.  (The udp_blocked=true path is a separate
/// entry point that forces m and f together as well.)
#[test]
fn test_r1_static_inference_f_apd_implies_m_apd() {
    for &mapping in all_mappings().iter() {
        let filtering = infer_filtering_behavior(false, mapping);
        if filtering == FilteringBehavior::AddressOrPortDependent {
            assert_eq!(
                mapping,
                MappingBehavior::AddressOrPortDependent,
                "under static inference, f==apd must imply m==apd (got m={mapping:?})"
            );
        }
    }
    // The udp_blocked=true path: m and f are both the blocked flavor.
    let blocked = infer_filtering_behavior(true, MappingBehavior::UdpBlocked);
    assert_eq!(blocked, FilteringBehavior::UdpBlocked);
}
