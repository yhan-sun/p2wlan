use super::*;
use crate::udp::probe_budget::{
    OUTBOUND_PROBE_BUDGET_PER_DESTINATION_IP, OUTBOUND_PROBE_PERSISTENT_PER_DESTINATION_IP,
};

#[tokio::test]
async fn aggregate_destination_budget_cannot_be_bypassed_by_peer_or_socket_rotation() {
    let budget = GlobalOutboundProbeBudget::new();
    let ip: IpAddr = "198.51.100.10".parse().unwrap();
    for index in 0..OUTBOUND_PROBE_BUDGET_PER_DESTINATION_IP {
        let peer = format!("peer-{}", index % 8);
        assert_eq!(
            budget
                .admit(&peer, SocketAddr::new(ip, 40000 + index as u16), index % 3)
                .await,
            OutboundProbeAdmission::Accepted
        );
    }
    assert_eq!(
        budget
            .admit("another-peer", SocketAddr::new(ip, 55000), 100)
            .await,
        OutboundProbeAdmission::GlobalDestinationRateLimited
    );
    assert_eq!(
        budget
            .admit("another-peer", "198.51.100.11:55000".parse().unwrap(), 100)
            .await,
        OutboundProbeAdmission::Accepted
    );
}

#[tokio::test]
async fn aggregate_destination_persistent_limit_survives_short_window_and_rekey() {
    let budget = GlobalOutboundProbeBudget::new();
    let endpoint: SocketAddr = "198.51.100.10:40000".parse().unwrap();
    let old = Instant::now() - Duration::from_secs(2);
    budget.state.lock().await.insert(
        OutboundProbeBudgetKey::DestinationIpPersistent(endpoint.ip()),
        std::iter::repeat_n(old, OUTBOUND_PROBE_PERSISTENT_PER_DESTINATION_IP).collect(),
    );
    assert_eq!(
        budget.admit("new-session-owner", endpoint, 20).await,
        OutboundProbeAdmission::GlobalDestinationPersistentRateLimited
    );
    let mut state = budget.state.lock().await;
    retain_live_budget_entries(&mut state, old + OUTBOUND_PROBE_PERSISTENT_WINDOW);
    assert!(state.is_empty());
    drop(state);
    assert_eq!(
        budget.admit("new-session-owner", endpoint, 20).await,
        OutboundProbeAdmission::Accepted
    );
}

#[tokio::test]
async fn denied_destination_attempts_do_not_consume_unrelated_capacity() {
    let budget = GlobalOutboundProbeBudget::new();
    let endpoint: SocketAddr = "198.51.100.10:40000".parse().unwrap();
    budget.state.lock().await.insert(
        OutboundProbeBudgetKey::DestinationIp(endpoint.ip()),
        std::iter::repeat_n(Instant::now(), OUTBOUND_PROBE_BUDGET_PER_DESTINATION_IP).collect(),
    );
    for _ in 0..10 {
        assert_eq!(
            budget.admit("peer", endpoint, 0).await,
            OutboundProbeAdmission::GlobalDestinationRateLimited
        );
    }
    let state = budget.state.lock().await;
    assert!(!state.contains_key(&OutboundProbeBudgetKey::Network));
    assert!(!state.contains_key(&OutboundProbeBudgetKey::Peer("peer".into())));
}
