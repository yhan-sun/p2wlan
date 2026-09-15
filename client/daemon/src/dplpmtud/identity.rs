use crate::peer::{ActiveBusinessPath, DirectValidationIdentity, PathEpoch, PeerPathLifecycle};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::sizes::OuterIpFamily;

/// Stable identity of the concrete local socket in one UDP publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct DplpmtudSocketIdentity {
    pub(crate) transport_instance_id: u64,
    pub(crate) socket_index: usize,
}

/// Exact local identity of one already-authenticated Direct UDP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DplpmtudPathIdentity {
    pub(crate) peer_id: String,
    pub(crate) epoch: PathEpoch,
    pub(crate) direct_validation_owner_token: u64,
    pub(crate) direct_validation_request_id: u16,
    pub(crate) authenticated_remote_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) socket: DplpmtudSocketIdentity,
    pub(crate) outer_ip_family: OuterIpFamily,
}

impl DplpmtudPathIdentity {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_committed_validation(
        peer_id: impl Into<String>,
        validation: DirectValidationIdentity,
        authenticated_remote_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
        transport_instance_id: u64,
        socket_index: usize,
    ) -> Option<Self> {
        if local_endpoint.is_ipv4() != authenticated_remote_endpoint.is_ipv4() {
            return None;
        }
        Some(Self {
            peer_id: peer_id.into(),
            epoch: validation.epoch,
            direct_validation_owner_token: validation.owner_token?,
            direct_validation_request_id: validation.request_id?,
            authenticated_remote_endpoint,
            local_endpoint,
            socket: DplpmtudSocketIdentity {
                transport_instance_id,
                socket_index,
            },
            outer_ip_family: OuterIpFamily::from_ip(authenticated_remote_endpoint.ip()),
        })
    }

    pub(crate) fn matches_committed_path(
        &self,
        lifecycle: PeerPathLifecycle,
        epoch: Option<PathEpoch>,
        active: &ActiveBusinessPath,
    ) -> bool {
        lifecycle == PeerPathLifecycle::Online
            && epoch == Some(self.epoch)
            && matches!(
                active,
                ActiveBusinessPath::Direct(validation)
                    if validation.epoch == self.epoch
                        && validation.owner_token == Some(self.direct_validation_owner_token)
                        && validation.request_id == Some(self.direct_validation_request_id)
                        && validation.commit_endpoint()
                            == Some(self.authenticated_remote_endpoint)
            )
    }

    pub(crate) fn summary(&self) -> DplpmtudPathIdentitySnapshot {
        DplpmtudPathIdentitySnapshot {
            peer_id: self.peer_id.clone(),
            network_generation: self.epoch.network_generation,
            peer_session_generation: self.epoch.peer_session_generation.value(),
            remote_candidate_epoch: self.epoch.remote_candidate_epoch,
            direct_validation_owner_token: self.direct_validation_owner_token,
            direct_validation_request_id: self.direct_validation_request_id,
            authenticated_remote_endpoint: self.authenticated_remote_endpoint.to_string(),
            local_endpoint: self.local_endpoint.to_string(),
            transport_instance_id: self.socket.transport_instance_id,
            socket_index: self.socket.socket_index,
            outer_ip_family: self.outer_ip_family,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DplpmtudPathIdentitySnapshot {
    pub(crate) peer_id: String,
    pub(crate) network_generation: u64,
    pub(crate) peer_session_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) direct_validation_owner_token: u64,
    pub(crate) direct_validation_request_id: u16,
    pub(crate) authenticated_remote_endpoint: String,
    pub(crate) local_endpoint: String,
    pub(crate) transport_instance_id: u64,
    pub(crate) socket_index: usize,
    pub(crate) outer_ip_family: OuterIpFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudAckIngress {
    pub(crate) remote_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) socket: DplpmtudSocketIdentity,
}
