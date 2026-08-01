/// Convert ICE candidates to a list of SocketAddr for hole punching.
pub fn candidates_to_addrs(candidates: &[IceCandidate]) -> Vec<SocketAddr> {
    candidates
        .iter()
        .filter_map(|c| c.endpoint.to_socket_addr())
        .collect()
}
