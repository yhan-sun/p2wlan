//! Original successful-encryption identity, without network or send authority.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Instant;

use tokio::sync::Mutex;

use super::super::{PeerTransportSessions, TransportSessionSlot};
use crate::dataplane::OutboundPacket;
use crate::error::DaemonError;
use crate::peer::PeerSessionGeneration;
use crate::transport::{
    EncryptedPeerPacket, SessionBoundEncryption, SessionUnavailableReason, WireGuardTransport,
};

/// Identifies the actual slot that encrypted this ciphertext. No raw key bytes,
/// network generation, current-owner qualification or physical-send success.
pub(crate) struct OriginalEncryptionSource {
    owner: Weak<Mutex<HashMap<String, PeerTransportSessions>>>,
    peer_id: String,
    session_instance: u64,
    original_role: crate::transport::OriginalSessionRole,
    authorized_peer_lifecycle: Option<PeerSessionGeneration>,
    encrypted_at: Instant,
}

/// Short original-registry guard, constructed only from real TX/RX sources.
pub(crate) struct OriginalEchoSessionGuard<'a> {
    sessions: tokio::sync::OwnedMutexGuard<HashMap<String, PeerTransportSessions>>,
    source: &'a OriginalEncryptionSource,
}
impl OriginalEchoSessionGuard<'_> {
    pub(crate) fn is_current(&self) -> bool {
        self.sessions
            .get(&self.source.peer_id)
            .and_then(|peer| peer.active.as_ref())
            .is_some_and(|active| {
                active.session_instance == self.source.session_instance
                    && active.authorized_peer_lifecycle == self.source.authorized_peer_lifecycle
                    && !active.session.is_expired()
            })
    }
}

impl OriginalEncryptionSource {
    /// Keep the actual session registry through the echo's synchronous boundary.
    /// Even a registry writer outside emit cannot revoke these original facts.
    pub(crate) fn try_original_echo_receive_session_guard<'a>(
        &'a self,
        rx: &crate::transport::OriginalSessionSource,
    ) -> Option<OriginalEchoSessionGuard<'a>> {
        use crate::transport::OriginalSessionRole;
        if !self.owner.ptr_eq(&rx.owner)
            || self.peer_id != rx.peer_id()
            || self.original_role != OriginalSessionRole::Active
            || rx.original_role() != OriginalSessionRole::Active
            || self.session_instance != rx.session_instance()
            || self.authorized_peer_lifecycle.is_none()
            || self.authorized_peer_lifecycle != rx.authorized_peer_lifecycle()
        {
            return None;
        }
        let sessions = self.owner.upgrade()?.try_lock_owned().ok()?;
        let guard = OriginalEchoSessionGuard {
            sessions,
            source: self,
        };
        guard.is_current().then_some(guard)
    }
    pub(crate) fn try_copy_for_publication(
        &self,
    ) -> std::result::Result<Self, std::collections::TryReserveError> {
        let mut peer_id = String::new();
        peer_id.try_reserve_exact(self.peer_id.len())?;
        peer_id.push_str(&self.peer_id);
        Ok(Self {
            owner: self.owner.clone(),
            peer_id,
            session_instance: self.session_instance,
            original_role: self.original_role,
            authorized_peer_lifecycle: self.authorized_peer_lifecycle,
            encrypted_at: self.encrypted_at,
        })
    }

    pub(crate) fn owner_is_live(&self) -> bool {
        self.owner.upgrade().is_some()
    }

    // Only the encryption parent may capture after encrypt_to_bytes Ok, while
    // the same original sessions guard still owns this actual active slot.
    pub(super) fn capture_successful_slot(
        transport: &WireGuardTransport,
        peer_id: &str,
        slot: &TransportSessionSlot,
        encrypted_at: Instant,
    ) -> Self {
        Self {
            owner: Arc::downgrade(&transport.sessions),
            peer_id: peer_id.to_string(),
            session_instance: slot.session_instance,
            original_role: crate::transport::OriginalSessionRole::Active,
            authorized_peer_lifecycle: slot.authorized_peer_lifecycle,
            encrypted_at,
        }
    }
}

// Metadata consumers are the next stage; keep the allowance on these immutable
// accessors only, not on the module or crypto implementation.
#[allow(dead_code)]
impl OriginalEncryptionSource {
    pub(crate) fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub(crate) fn session_instance(&self) -> u64 {
        self.session_instance
    }

    pub(crate) fn original_role(&self) -> crate::transport::OriginalSessionRole {
        self.original_role
    }

    pub(crate) fn authorized_peer_lifecycle(&self) -> Option<PeerSessionGeneration> {
        self.authorized_peer_lifecycle
    }

    pub(crate) fn encrypted_at(&self) -> Instant {
        self.encrypted_at
    }

    pub(crate) fn belongs_to(&self, transport: &WireGuardTransport) -> bool {
        Weak::ptr_eq(&self.owner, &Arc::downgrade(&transport.sessions))
    }
}

/// Public ciphertext remains unchanged. Only actual crypto can construct this
/// private success carrier. Compatibility entry points select capture=false:
/// they carry None and never create an original source just to discard it.
pub(crate) struct EncryptedOutboundWithSource {
    packet: EncryptedPeerPacket,
    source: Option<OriginalEncryptionSource>,
}

impl EncryptedOutboundWithSource {
    pub(super) fn new(
        packet: EncryptedPeerPacket,
        source: Option<OriginalEncryptionSource>,
    ) -> Self {
        Self { packet, source }
    }

    pub(crate) fn into_packet(self) -> EncryptedPeerPacket {
        self.packet
    }

    #[allow(dead_code)]
    pub(crate) fn packet(&self) -> &EncryptedPeerPacket {
        &self.packet
    }

    #[allow(dead_code)]
    pub(crate) fn source(&self) -> Option<&OriginalEncryptionSource> {
        self.source.as_ref()
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts(self) -> (EncryptedPeerPacket, Option<OriginalEncryptionSource>) {
        (self.packet, self.source)
    }
}

pub(crate) enum SessionBoundEncryptionWithSource {
    Encrypted {
        packet: EncryptedOutboundWithSource,
        plaintext: OutboundPacket,
        session_lock_wait_us: u64,
        crypto_us: u64,
    },
    Contended(OutboundPacket),
    Unavailable {
        packet: OutboundPacket,
        reason: SessionUnavailableReason,
    },
    Failed {
        packet: OutboundPacket,
        error: DaemonError,
    },
}

impl SessionBoundEncryptionWithSource {
    pub(super) fn into_legacy(self) -> SessionBoundEncryption {
        match self {
            Self::Encrypted {
                packet,
                plaintext,
                session_lock_wait_us,
                crypto_us,
            } => SessionBoundEncryption::Encrypted {
                packet: packet.into_packet(),
                plaintext,
                session_lock_wait_us,
                crypto_us,
            },
            Self::Contended(packet) => SessionBoundEncryption::Contended(packet),
            Self::Unavailable { packet, reason } => {
                SessionBoundEncryption::Unavailable { packet, reason }
            }
            Self::Failed { packet, error } => SessionBoundEncryption::Failed { packet, error },
        }
    }
}
