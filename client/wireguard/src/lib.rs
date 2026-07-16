//! # p2pnet-wireguard
//!
//! WireGuard Noise IK handshake and transport encryption for P2PNet.
//!
//! ## Overview
//!
//! - **Handshake**: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s (Noise IK pattern)
//! - **Key Exchange**: X25519 (Curve25519 ECDH)
//! - **Encryption**: ChaCha20-Poly1305 AEAD
//! - **Transport**: Counter-based nonces with replay protection
//! - **Identity**: X25519 static key pairs for node identification
//!
//! ## Usage
//!
//! ```no_run
//! use p2pnet_crypto::NodeIdentity;
//! use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
//!
//! // Generate identities
//! let alice = NodeIdentity::generate();
//! let bob = NodeIdentity::generate();
//!
//! // Alice initiates handshake (she knows Bob's public key)
//! let mut initiator = HandshakeInitiator::new(alice, bob.public_key(), None);
//! let init_msg = initiator.create_initiation().unwrap();
//!
//! // Bob responds
//! let mut responder = HandshakeResponder::new(bob, None);
//! let (resp_msg, bob_keys) = responder.consume_initiation_and_respond(&init_msg).unwrap();
//!
//! // Alice processes the response
//! let alice_keys = initiator.consume_response(&resp_msg).unwrap();
//!
//! // Both sides now have transport sessions
//! let mut alice_session = TransportSession::new(alice_keys);
//! let mut bob_session = TransportSession::new(bob_keys);
//!
//! // Alice encrypts an IP packet
//! let encrypted = alice_session.encrypt_to_bytes(b"Hello Bob!").unwrap();
//!
//! // Bob decrypts it
//! let decrypted = bob_session.decrypt_from_bytes(&encrypted).unwrap();
//! assert_eq!(&decrypted, b"Hello Bob!");
//! ```

pub mod error;
pub mod handshake;
pub mod session;
pub mod types;

// Re-export primary types
pub use error::{Result, WireGuardError};
pub use handshake::{HandshakeInitiator, HandshakeResponder, TransportKeyPair};
pub use session::TransportSession;
pub use types::{
    MessageInitiation, MessageResponse, MessageTransport, PeerConfig, SessionKeys,
    INITIALIZATION_MSG_SIZE, RESPONSE_MSG_SIZE, TYPE_COOKIE_REPLY, TYPE_INITIALIZATION,
    TYPE_RESPONSE, TYPE_TRANSPORT,
};

/// WireGuard tunnel state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Initial state, no handshake initiated.
    Idle,
    /// Handshake initiation sent, waiting for response.
    HandshakeInitiated,
    /// Handshake response received, ready to send data.
    HandshakeComplete,
    /// Transport mode, sending/receiving encrypted data.
    Transport,
    /// Session expired, needs rekeying.
    Expired,
}

/// WireGuard peer state.
#[derive(Debug)]
pub struct WireGuardPeer {
    /// Peer's public key (32 bytes).
    pub public_key: [u8; 32],
    /// Peer's endpoint (ip:port).
    pub endpoint: Option<String>,
    /// Current transport session (if handshake completed).
    pub session: Option<TransportSession>,
    /// Preshared key (optional, for extra security).
    pub preshared_key: Option<[u8; 32]>,
    /// Current tunnel state.
    pub state: TunnelState,
}

impl WireGuardPeer {
    /// Create a new peer with the given public key.
    pub fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            endpoint: None,
            session: None,
            preshared_key: None,
            state: TunnelState::Idle,
        }
    }

    /// Set the peer's endpoint.
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = Some(endpoint.to_string());
        self
    }

    /// Check if the peer has an active session.
    pub fn is_connected(&self) -> bool {
        self.session.is_some() && self.state == TunnelState::Transport
    }
}
