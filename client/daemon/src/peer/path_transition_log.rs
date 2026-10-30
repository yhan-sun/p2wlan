//! One transition's frozen diagnostics. It never owns connection/path state.
use super::path_state_machine::PathTransitionDecision;
use super::{ConnectionState, NetworkPath, PathEpoch, PeerConnection};
use std::net::SocketAddr;
struct Changed {
    previous: ConnectionState,
    next: ConnectionState,
    previous_active: Option<NetworkPath>,
    active: Option<NetworkPath>,
    revision: u64,
    direct_generation: u64,
    relay_ready_generation: Option<u64>,
    relay_confirmed_generation: Option<u64>,
    relay_connection: Option<u64>,
    relay_server: Option<String>,
    endpoint: Option<SocketAddr>,
}
enum Event {
    Refused {
        epoch: Option<PathEpoch>,
        decision: PathTransitionDecision,
        revision: u64,
        duplicate: bool,
    },
    Changed(Changed),
}
pub(crate) struct DeferredPathTransitionLog {
    peer: String,
    event: Option<Event>,
}
impl DeferredPathTransitionLog {
    pub(super) fn new(peer: &str) -> Self {
        Self {
            peer: peer.to_owned(),
            event: None,
        }
    }
    pub(super) fn refused(
        &mut self,
        epoch: Option<PathEpoch>,
        decision: PathTransitionDecision,
        revision: u64,
        duplicate: bool,
    ) {
        if tracing::level_enabled!(tracing::Level::DEBUG) && self.event.is_none() {
            self.event = Some(Event::Refused {
                epoch,
                decision,
                revision,
                duplicate,
            });
        }
    }
    pub(super) fn changed(
        &mut self,
        conn: &PeerConnection,
        states: (
            ConnectionState,
            ConnectionState,
            Option<NetworkPath>,
            Option<NetworkPath>,
        ),
        revision: u64,
    ) {
        if tracing::level_enabled!(tracing::Level::INFO) && self.event.is_none() {
            self.event = Some(Event::Changed(Changed {
                previous: states.0,
                next: states.1,
                previous_active: states.2,
                active: states.3,
                revision,
                direct_generation: conn.direct_generation,
                relay_ready_generation: conn.relay_ready_generation,
                relay_confirmed_generation: conn.relay_confirmed_generation,
                relay_connection: conn.relay_confirmed_connection_id,
                relay_server: conn.relay_server.clone(),
                endpoint: conn.endpoint,
            }));
        }
    }
}
impl Drop for DeferredPathTransitionLog {
    fn drop(&mut self) {
        match self.event.as_ref() {
            Some(Event::Refused {
                epoch,
                decision,
                revision,
                duplicate: false,
            }) => {
                tracing::debug!(target:"p2pnet_daemon::peer::path_state_machine",event="path_transition_rejected",peer_id=%self.peer,epoch=?epoch,decision=?decision,revision,"rejected stale or illegal path event")
            }
            Some(Event::Refused {
                epoch,
                decision,
                revision,
                duplicate: true,
            }) => {
                tracing::debug!(target:"p2pnet_daemon::peer::path_state_machine",event="path_transition_duplicate",peer_id=%self.peer,epoch=?epoch,decision=?decision,revision,"ignored duplicate path event without executing side effects")
            }
            Some(Event::Changed(s)) => {
                tracing::info!(target:"p2pnet_daemon::peer::connection",event="peer_connection_state_changed",peer_id=%self.peer,previous_state=?s.previous,new_state=?s.next,previous_active_path=?s.previous_active,active_path=?s.active,path_revision=s.revision,direct_generation=s.direct_generation,relay_ready_generation=?s.relay_ready_generation,relay_confirmed_generation=?s.relay_confirmed_generation,relay_confirmed_connection_id=?s.relay_connection,relay_server=?s.relay_server,direct_endpoint=?s.endpoint,"peer connection state changed peer_id={} previous={:?} new={:?}",self.peer,s.previous,s.next);
                tracing::info!(target:"p2pnet_daemon::peer","Peer {} state: {} → {}",self.peer,s.previous,s.next);
            }
            None => {}
        }
    }
}
