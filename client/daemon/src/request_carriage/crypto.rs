//! Carriage adapters around the single original crypto core in each path.
use super::{DeliveryMetadata, EncryptedRequestDelivery, RawRequestDelivery};
use crate::error::{DaemonError, Result};
use crate::transport::{
    PreparedEncryptionBuffer, SessionBoundEncryptionWithSource, SessionUnavailableReason,
    WireGuardTransport,
};

fn observe_crypto_input(transport: &WireGuardTransport, packet: &mut RawRequestDelivery) {
    packet
        .metadata
        .observe_crypto_input(transport.resource_capture(), &packet.raw.packet);
}

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
    #[cfg(test)]
    pub(crate) async fn encrypt_request_with_emit_guard(
        &self,
        packet: RawRequestDelivery,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        self.encrypt_request_with_emit_guard_profiled(packet, None)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn encrypt_request_with_emit_guard_profiled(
        &self,
        packet: RawRequestDelivery,
        profile: Option<&mut crate::dataplane::DeferredCryptoProfile<'_>>,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        self.encrypt_request_with_emit_guard_diagnostics(packet, profile, None)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn encrypt_request_with_emit_guard_diagnostics(
        &self,
        packet: RawRequestDelivery,
        profile: Option<&mut crate::dataplane::DeferredCryptoProfile<'_>>,
        log: Option<&mut crate::transport::DeferredEncryptionLog>,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        self.encrypt_request_in_original_session(packet, None, profile, log)
            .await
    }

    pub(crate) async fn encrypt_request_with_prepared_buffer_diagnostics(
        &self,
        packet: RawRequestDelivery,
        prepared: PreparedEncryptionBuffer,
        profile: Option<&mut crate::dataplane::DeferredCryptoProfile<'_>>,
        log: Option<&mut crate::transport::DeferredEncryptionLog>,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        self.encrypt_request_in_original_session(packet, Some(prepared), profile, log)
            .await
    }

    async fn encrypt_request_in_original_session(
        &self,
        mut packet: RawRequestDelivery,
        prepared: Option<PreparedEncryptionBuffer>,
        profile: Option<&mut crate::dataplane::DeferredCryptoProfile<'_>>,
        log: Option<&mut crate::transport::DeferredEncryptionLog>,
    ) -> Result<Option<EncryptedRequestDelivery>> {
        packet.materialize();
        observe_crypto_input(self, &mut packet);
        let RawRequestDelivery { raw, metadata, .. } = packet;
        let (binding, original_residency) = metadata.into_parts();
        let encrypted = if let Some(prepared) = prepared {
            self.encrypt_outbound_with_prepared_buffer_diagnostics(
                raw,
                prepared,
                binding.is_some(),
                profile,
                log,
            )
            .await?
        } else if let Some(log) = log {
            self.encrypt_outbound_with_emit_guard_diagnostics(raw, binding.is_some(), profile, log)
                .await?
        } else if binding.is_some() {
            self.encrypt_outbound_with_emit_guard_and_source(raw, profile)
                .await?
        } else {
            self.encrypt_outbound_with_emit_guard_observed(raw, profile)
                .await?
        };
        // The original input observation survives the original crypto future,
        // including cancellation, but does not retain or clone its Vec.
        drop(original_residency);
        Ok(encrypted.map(|encrypted| {
            let (packet, source, residency) = encrypted.into_observed_parts();
            EncryptedRequestDelivery {
                packet,
                metadata: DeliveryMetadata::from_parts(binding, residency),
                source,
                echo_emit: None,
            }
        }))
    }

    #[cfg(test)]
    pub(crate) fn try_encrypt_request_with_emit_guard_for_session(
        &self,
        packet: RawRequestDelivery,
        expected_session_instance: u64,
    ) -> RequestEncryptionAttempt {
        self.try_encrypt_request_with_emit_guard_diagnostics(
            packet,
            expected_session_instance,
            None,
            None,
        )
    }

    pub(crate) fn try_encrypt_request_with_emit_guard_diagnostics(
        &self,
        mut packet: RawRequestDelivery,
        expected_session_instance: u64,
        profile: Option<&mut crate::dataplane::DeferredCryptoProfile<'_>>,
        log: Option<&mut crate::transport::DeferredEncryptionLog>,
    ) -> RequestEncryptionAttempt {
        packet.materialize();
        observe_crypto_input(self, &mut packet);
        let RawRequestDelivery { raw, metadata } = packet;
        let (binding, original_residency) = metadata.into_parts();
        let encrypted = if let Some(log) = log {
            self.try_encrypt_outbound_with_emit_guard_diagnostics(
                raw,
                expected_session_instance,
                binding.is_some(),
                profile,
                log,
            )
        } else if binding.is_some() {
            self.try_encrypt_outbound_with_emit_guard_for_session_and_source(
                raw,
                expected_session_instance,
            )
        } else {
            self.try_encrypt_outbound_with_emit_guard_for_session(raw, expected_session_instance)
        };
        match encrypted {
            SessionBoundEncryptionWithSource::Encrypted {
                packet,
                plaintext,
                session_lock_wait_us,
                crypto_us,
            } => {
                let (packet, source, residency) = packet.into_observed_parts();
                RequestEncryptionAttempt::Encrypted {
                    packet: EncryptedRequestDelivery {
                        packet,
                        metadata: DeliveryMetadata::from_parts(binding.clone(), residency),
                        source,
                        echo_emit: None,
                    },
                    plaintext: RawRequestDelivery {
                        raw: plaintext,
                        metadata: DeliveryMetadata::from_parts(binding, original_residency),
                    },
                    session_lock_wait_us,
                    crypto_us,
                }
            }
            SessionBoundEncryptionWithSource::Contended(raw) => {
                RequestEncryptionAttempt::Contended(RawRequestDelivery {
                    raw,
                    metadata: DeliveryMetadata::from_parts(binding, original_residency),
                })
            }
            SessionBoundEncryptionWithSource::Unavailable {
                packet: raw,
                reason,
            } => RequestEncryptionAttempt::Unavailable {
                packet: RawRequestDelivery {
                    raw,
                    metadata: DeliveryMetadata::from_parts(binding, original_residency),
                },
                reason,
            },
            SessionBoundEncryptionWithSource::Failed { packet: raw, error } => {
                RequestEncryptionAttempt::Failed {
                    packet: RawRequestDelivery {
                        raw,
                        metadata: DeliveryMetadata::from_parts(binding, original_residency),
                    },
                    error,
                }
            }
        }
    }
}
