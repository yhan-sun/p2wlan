//! Select one original-capacity queue, keeping public legacy element types.
use super::{rx_owned::RxPayload, ResidencyStage, ResourceCapture, RxOwned};
use std::sync::Arc;
use tokio::sync::mpsc;

pub(crate) trait RxChannelPayload: RxPayload {
    const ADMISSION: ResidencyStage;
    const CHANNEL: ResidencyStage;
    const ACTIVE: ResidencyStage;
}
impl RxChannelPayload for crate::transport::ReceivedEncryptedPacket {
    const ADMISSION: ResidencyStage = ResidencyStage::RxWireAdmission;
    const CHANNEL: ResidencyStage = ResidencyStage::RxWireChannel;
    const ACTIVE: ResidencyStage = ResidencyStage::RxWireActive;
}
impl RxChannelPayload for crate::dataplane::InboundPacket {
    const ADMISSION: ResidencyStage = ResidencyStage::RxPlaintextAdmission;
    const CHANNEL: ResidencyStage = ResidencyStage::RxPlaintextChannel;
    const ACTIVE: ResidencyStage = ResidencyStage::RxPlaintextActive;
}

pub(crate) enum RxSink<T: RxChannelPayload> {
    Legacy(mpsc::Sender<T>),
    Pooled(mpsc::Sender<RxOwned<T>>),
    Observed {
        tx: mpsc::Sender<RxOwned<T>>,
        capture: Arc<ResourceCapture>,
    },
}
pub(crate) enum RxReceiver<T: RxChannelPayload> {
    Legacy(mpsc::Receiver<T>),
    Pooled(mpsc::Receiver<RxOwned<T>>),
    Observed {
        rx: mpsc::Receiver<RxOwned<T>>,
        capture: Arc<ResourceCapture>,
    },
}
#[derive(Debug)]
pub(crate) struct RxChannelClosed;

impl<T: RxChannelPayload> Clone for RxSink<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Legacy(tx) => Self::Legacy(tx.clone()),
            Self::Pooled(tx) => Self::Pooled(tx.clone()),
            Self::Observed { tx, capture } => Self::Observed {
                tx: tx.clone(),
                capture: capture.clone(),
            },
        }
    }
}
impl<T: RxChannelPayload> From<mpsc::Sender<T>> for RxSink<T> {
    fn from(tx: mpsc::Sender<T>) -> Self {
        Self::Legacy(tx)
    }
}
impl<T: RxChannelPayload> From<mpsc::Receiver<T>> for RxReceiver<T> {
    fn from(rx: mpsc::Receiver<T>) -> Self {
        Self::Legacy(rx)
    }
}

impl<T: RxChannelPayload> RxSink<T> {
    pub(crate) fn channel(
        capacity: usize,
        capture: Option<Arc<ResourceCapture>>,
    ) -> (Self, RxReceiver<T>) {
        if let Some(capture) = capture {
            let (tx, rx) = mpsc::channel(capacity);
            (
                Self::Observed {
                    tx,
                    capture: capture.clone(),
                },
                RxReceiver::Observed { rx, capture },
            )
        } else {
            let (tx, rx) = mpsc::channel(capacity);
            (Self::Legacy(tx), RxReceiver::Legacy(rx))
        }
    }
    pub(crate) fn channel_with_pool(
        capacity: usize,
        capture: Option<Arc<ResourceCapture>>,
    ) -> (Self, RxReceiver<T>) {
        if capture.is_some() {
            return Self::channel(capacity, capture);
        }
        let (tx, rx) = mpsc::channel(capacity);
        (Self::Pooled(tx), RxReceiver::Pooled(rx))
    }

    pub(crate) fn supports_pool(&self) -> bool {
        matches!(self, Self::Pooled(_))
    }

    pub(crate) fn capture(&self) -> Option<&Arc<ResourceCapture>> {
        match self {
            Self::Legacy(_) | Self::Pooled(_) => None,
            Self::Observed { capture, .. } => Some(capture),
        }
    }
    pub(crate) fn capacity(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.capacity(),
            Self::Observed { tx, .. } | Self::Pooled(tx) => tx.capacity(),
        }
    }
    pub(crate) fn max_capacity(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.max_capacity(),
            Self::Observed { tx, .. } | Self::Pooled(tx) => tx.max_capacity(),
        }
    }
    pub(crate) async fn send(&self, value: T) -> Result<(), RxChannelClosed> {
        self.send_with_capture(value, self.capture()).await
    }
    pub(crate) async fn send_with_capture(
        &self,
        value: T,
        capture: Option<&Arc<ResourceCapture>>,
    ) -> Result<(), RxChannelClosed> {
        if let (Some(source), Some(target)) = (capture, self.capture()) {
            if !Arc::ptr_eq(source, target) {
                // A finished source creates no lease. Keep the diagnostic
                // boundary visible even when only the target observes bytes.
                source.unobserved_residency_exit();
                target.unobserved_residency_exit();
            }
        }
        self.send_owned(RxOwned::observe(
            value,
            capture.or(self.capture()),
            T::ADMISSION,
        ))
        .await
    }
    pub(crate) async fn send_owned(&self, mut owned: RxOwned<T>) -> Result<(), RxChannelClosed> {
        match self {
            Self::Legacy(tx) => {
                let parts = owned.into_parts();
                let resources = parts.0;
                let value = parts.1;
                if let Some(lease) = resources.as_ref() {
                    lease.unobserved_exit();
                }
                if resources.is_some() {
                    let slot = tx.reserve().await.map_err(|_| RxChannelClosed)?;
                    // Retire BEFORE commit: an untracked receiver may start
                    // a new partial observation immediately after dequeue.
                    // Keeping this lease then would count the same Vec twice.
                    drop(resources);
                    slot.send(value);
                    Ok(())
                } else {
                    tx.send(value).await.map_err(|_| RxChannelClosed)
                }
            }
            Self::Pooled(tx) => tx.send(owned).await.map_err(|_| RxChannelClosed),
            Self::Observed { tx, capture } => {
                owned.align(Some(capture), T::ADMISSION, false);
                let slot = tx.reserve().await.map_err(|_| RxChannelClosed)?;
                owned.align(Some(capture), T::CHANNEL, false);
                slot.send(owned);
                Ok(())
            }
        }
    }
}

impl<T: RxChannelPayload> RxReceiver<T> {
    pub(crate) async fn recv(
        &mut self,
        expected: Option<&Arc<ResourceCapture>>,
    ) -> Option<RxOwned<T>> {
        let mut owned = match self {
            Self::Legacy(rx) => RxOwned::from(rx.recv().await?),
            Self::Pooled(rx) => rx.recv().await?,
            Self::Observed { rx, capture } => {
                let mut owned = rx.recv().await?;
                owned.align(Some(capture), T::ACTIVE, false);
                owned
            }
        };
        owned.align(expected, T::ACTIVE, true);
        Some(owned)
    }
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Legacy(rx) => rx.len(),
            Self::Observed { rx, .. } | Self::Pooled(rx) => rx.len(),
        }
    }
}

pub(crate) type EncryptedRxSink = RxSink<crate::transport::ReceivedEncryptedPacket>;
pub(crate) type EncryptedRxReceiver = RxReceiver<crate::transport::ReceivedEncryptedPacket>;
pub(crate) type PlaintextRxSink = RxSink<crate::dataplane::InboundPacket>;
pub(crate) type PlaintextRxReceiver = RxReceiver<crate::dataplane::InboundPacket>;

#[cfg(test)]
#[path = "rx_channel_tests.rs"]
mod tests;
