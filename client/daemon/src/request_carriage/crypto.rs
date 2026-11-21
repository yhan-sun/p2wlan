//! Carriage adapters around the single original crypto core in each path.

use crate::error::{DaemonError, Result};
use crate::transport::{
    SessionBoundEncryption, SessionBoundEncryptionWithSource, SessionUnavailableReason,
    WireGuardTransport,
};

use super::{EncryptedRequestDelivery, RawRequestDelivery};

pub(crate) enum RequestEncryptionAttempt {
    Encrypted {
        packet: EncryptedRequestDelivery,
        plaintext: RawRequestDelivery,
        session_lock_wait_us: u64,
        crypto_us: u64,
    },
    Contended(RawRequestDelivery),
    Unavailable {
        packet: RawRequestDelivery,
        reason: SessionUnavailableReason,
    },
    Failed {
        packet: RawRequestDelivery,
        error: DaemonError,
    },
}

impl WireGuardTransport {
    pub(crate) async fn encrypt_request_with_emit_guard(
        &self,
        packet: RawRequestDelivery,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        let RawRequestDelivery { raw, binding } = packet;
        if binding.is_some() {
            self.encrypt_outbound_with_emit_guard_and_source(raw)
                .await
                .map(|result| {
                    result.map(|encrypted| {
                        let (packet, source) = encrypted.into_parts();
                        EncryptedRequestDelivery {
                            packet,
                            binding,
                            source,
                            echo_emit: None,
                        }
                    })
                })
        } else {
            self.encrypt_outbound_with_emit_guard(raw)
                .await
                .map(|result| {
                    result.map(|packet| EncryptedRequestDelivery {
                        packet,
                        binding: None,
                        source: None,
                        echo_emit: None,
                    })
                })
        }
    }

    pub(crate) fn try_encrypt_request_with_emit_guard_for_session(
        &self,
        packet: RawRequestDelivery,
        expected_session_instance: u64,
    ) -> RequestEncryptionAttempt {
        let RawRequestDelivery { raw, binding } = packet;
        if binding.is_some() {
            match self.try_encrypt_outbound_with_emit_guard_for_session_and_source(
                raw,
                expected_session_instance,
            ) {
                SessionBoundEncryptionWithSource::Encrypted {
                    packet,
                    plaintext,
                    session_lock_wait_us,
                    crypto_us,
                } => {
                    let (packet, source) = packet.into_parts();
                    RequestEncryptionAttempt::Encrypted {
                        packet: EncryptedRequestDelivery {
                            packet,
                            binding: binding.clone(),
                            source,
                            echo_emit: None,
                        },
                        plaintext: RawRequestDelivery {
                            raw: plaintext,
                            binding,
                        },
                        session_lock_wait_us,
                        crypto_us,
                    }
                }
                SessionBoundEncryptionWithSource::Contended(raw) => {
                    RequestEncryptionAttempt::Contended(RawRequestDelivery { raw, binding })
                }
                SessionBoundEncryptionWithSource::Unavailable {
                    packet: raw,
                    reason,
                } => RequestEncryptionAttempt::Unavailable {
                    packet: RawRequestDelivery { raw, binding },
                    reason,
                },
                SessionBoundEncryptionWithSource::Failed { packet: raw, error } => {
                    RequestEncryptionAttempt::Failed {
                        packet: RawRequestDelivery { raw, binding },
                        error,
                    }
                }
            }
        } else {
            match self
                .try_encrypt_outbound_with_emit_guard_for_session(raw, expected_session_instance)
            {
                SessionBoundEncryption::Encrypted {
                    packet,
                    plaintext,
                    session_lock_wait_us,
                    crypto_us,
                } => RequestEncryptionAttempt::Encrypted {
                    packet: EncryptedRequestDelivery {
                        packet,
                        binding: None,
                        source: None,
                        echo_emit: None,
                    },
                    plaintext: RawRequestDelivery::from(plaintext),
                    session_lock_wait_us,
                    crypto_us,
                },
                SessionBoundEncryption::Contended(raw) => {
                    RequestEncryptionAttempt::Contended(RawRequestDelivery::from(raw))
                }
                SessionBoundEncryption::Unavailable {
                    packet: raw,
                    reason,
                } => RequestEncryptionAttempt::Unavailable {
                    packet: RawRequestDelivery::from(raw),
                    reason,
                },
                SessionBoundEncryption::Failed { packet: raw, error } => {
                    RequestEncryptionAttempt::Failed {
                        packet: RawRequestDelivery::from(raw),
                        error,
                    }
                }
            }
        }
    }
}
