/// Derive shared candidate/capability evidence from one connection snapshot.
///
/// The caller supplies profile usability and bounded-birthday policy from its
/// existing owners. In particular, the runtime passes profile usability only
/// after its live time/epoch admission checks; diagnostics combines those two
/// facts without rebinding the profile or granting a session owner.
///
/// Relay availability retains the caller's scope: configured fallback intent
/// in the runtime and transport availability in path-selection diagnostics.
/// Fresh-mapping evidence also retains its existing scope and is currently not
/// consumed by the pure planner. This helper adds no strategy or admission.
fn traversal_context_for_connection(
    conn: &PeerConnection,
    local: &NatCapabilities,
    remote: &NatCapabilities,
    inputs: TraversalContext,
) -> TraversalContext {
    let remote_candidates = conn
        .candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    let on_link_lan = remote_candidates
        .iter()
        .any(|endpoint| conn.is_on_link_host_candidate(*endpoint));
    // Use the same measured capability endpoint in both callers. The local
    // endpoint supplied to diagnostics still describes candidate pairs, but
    // its address family alone is not traversal planning evidence.
    let global_ipv6_direct_available = local
        .stable_public_endpoint
        .as_deref()
        .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok())
        .is_some_and(|endpoint| {
            endpoint.is_ipv6()
                && remote_candidates
                    .iter()
                    .any(|candidate| candidate.is_ipv6() && is_public_probe_endpoint(*candidate))
        });
    let peer_reflexive_evidence = conn.candidate_pairs.iter().any(|pair| {
        matches!(pair.source, CandidatePairSource::PeerReflexive)
            && matches!(
                pair.state,
                CandidatePairState::Succeeded | CandidatePairState::Selected
            )
    });
    let learned_endpoint_evidence = conn.candidate_pairs.iter().any(|pair| {
        matches!(pair.source, CandidatePairSource::Learned)
            && matches!(
                pair.state,
                CandidatePairState::Succeeded | CandidatePairState::Selected
            )
    });
    let remote_stable_endpoint_available = remote.is_stable_endpoint()
        || (!conn.remote_nat_profile.as_ref().is_some_and(|profile| {
            profile.capabilities.mapping_behavior != MappingBehavior::Unknown
        }) && conn.endpoint.is_some_and(is_public_probe_endpoint));
    TraversalContext {
        on_link_lan,
        global_ipv6_direct_available,
        peer_reflexive_evidence,
        learned_endpoint_evidence,
        local_stable_endpoint_available: local.is_stable_endpoint(),
        remote_stable_endpoint_available,
        bounded_birthday_allowed: inputs.bounded_birthday_allowed
            && (local.birthday_candidate || remote.birthday_candidate),
        ..inputs
    }
}
