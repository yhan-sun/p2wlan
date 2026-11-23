use super::PeerConnection;
use p2pnet_nat::engine::{EndpointReceipt, PunchTarget};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

const LIFETIME: Duration = Duration::from_secs(3);
const CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObservedUdpEndpoints {
    pub socket_index: usize,
    pub remote_source: SocketAddr,
    pub local_as_seen_by_peer: SocketAddr,
}

#[derive(Debug)]
struct Answer {
    session: u64,
    local_epoch: u64,
    challenge: [u8; 8],
    target: PunchTarget,
    at: Instant,
    consumed: bool,
}

#[derive(Debug, Default)]
pub(crate) struct EndpointExchange {
    answers: VecDeque<Answer>,
    latest: Option<VerifiedObservation>,
}

#[derive(Debug)]
struct VerifiedObservation {
    pair: ObservedUdpEndpoints,
    session: u64,
    epoch: u64,
    at: Instant,
    local_node_id: String,
}

impl EndpointExchange {
    pub(crate) fn answered(
        &mut self,
        session: u64,
        local_epoch: u64,
        challenge: [u8; 8],
        target: PunchTarget,
    ) {
        let now = Instant::now();
        self.answers.retain(|a| {
            a.local_epoch == local_epoch && a.session == session && now - a.at < LIFETIME
        });
        if self.answers.iter().any(|a| a.challenge == challenge) {
            return;
        }
        if self.answers.len() == CAPACITY {
            self.answers.pop_front();
        }
        self.answers.push_back(Answer {
            session,
            local_epoch,
            challenge,
            target,
            at: now,
            consumed: false,
        });
    }

    pub(crate) fn accept(
        &mut self,
        local: &str,
        session: u64,
        epoch: u64,
        target: PunchTarget,
        receipt: EndpointReceipt,
    ) -> bool {
        let now = Instant::now();
        let Some(answer) = self.answers.iter_mut().find(|a| {
            a.session == session
                && a.local_epoch == epoch
                && a.challenge == receipt.challenge
                && a.target == target
                && !a.consumed
                && now - a.at < LIFETIME
        }) else {
            return false;
        };
        answer.consumed = true;
        self.latest = Some(VerifiedObservation {
            pair: ObservedUdpEndpoints {
                socket_index: target.socket,
                remote_source: target.address,
                local_as_seen_by_peer: receipt.observed,
            },
            session,
            epoch,
            at: now,
            local_node_id: local.to_owned(),
        });
        true
    }

    pub(super) fn current(
        &self,
        conn: &PeerConnection,
        epoch: u64,
    ) -> Option<ObservedUdpEndpoints> {
        let observation = self.latest.as_ref()?;
        (observation.epoch == epoch
            && observation.at.elapsed() < LIFETIME
            && conn.compact_session(&observation.local_node_id)?.id == observation.session)
            .then_some(observation.pair)
    }
}

impl PeerConnection {
    pub(crate) fn observed_udp_endpoints(&self, network: u64) -> Option<ObservedUdpEndpoints> {
        let run = self.punch_run.as_ref()?;
        let offer = self.negotiated_punch.as_ref()?;
        if !run.current_for_diagnostics(self, network)
            || !offer.current(self, network)
            || offer.profile.as_ref() != Some(&run.remote)
        {
            return None;
        }
        run.endpoint_exchange
            .lock()
            .ok()?
            .current(self, run.pacer.epoch())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn endpoint_receipts_expire_and_cannot_move_between_rounds_or_keys() {
        let mut exchange = EndpointExchange::default();
        let target = PunchTarget {
            address: ([127, 0, 0, 1], 1010).into(),
            socket: 2,
        };
        let receipt = EndpointReceipt {
            challenge: [12; 8],
            observed: ([127, 0, 0, 1], 2020).into(),
        };
        exchange.answered(11, 7, receipt.challenge, target);
        assert!(!exchange.accept("a", 12, 7, target, receipt));
        assert!(!exchange.accept("a", 11, 8, target, receipt));
        tokio::time::advance(LIFETIME).await;
        assert!(!exchange.accept("a", 11, 7, target, receipt));
        for i in 0..=CAPACITY {
            exchange.answered(11, 8, (i as u64).to_be_bytes(), target);
        }
        assert_eq!(exchange.answers.len(), CAPACITY);
        assert!(!exchange.accept(
            "a",
            11,
            8,
            target,
            EndpointReceipt {
                challenge: [0; 8],
                ..receipt
            }
        ));
        let fresh = EndpointReceipt {
            challenge: 1u64.to_be_bytes(),
            ..receipt
        };
        assert!(exchange.accept("a", 11, 8, target, fresh));
        exchange.answered(11, 8, fresh.challenge, target);
        assert!(!exchange.accept("a", 11, 8, target, fresh));
    }
}
