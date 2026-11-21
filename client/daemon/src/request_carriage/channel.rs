//! One selected existing raw channel; conversion has no extra queue or task.

use tokio::sync::mpsc;

use super::{OutboundPacket, RawRequestDelivery};

#[derive(Clone)]
pub(crate) enum RawOutboundSink {
    Legacy(mpsc::Sender<OutboundPacket>),
    Tracked(mpsc::Sender<RawRequestDelivery>),
}

pub(crate) enum RawOutboundPermit<'a> {
    Legacy(mpsc::Permit<'a, OutboundPacket>),
    Tracked(mpsc::Permit<'a, RawRequestDelivery>),
}

impl RawOutboundSink {
    pub(crate) fn is_tracked(&self) -> bool {
        matches!(self, Self::Tracked(_))
    }

    pub(crate) fn max_capacity(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.max_capacity(),
            Self::Tracked(tx) => tx.max_capacity(),
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.capacity(),
            Self::Tracked(tx) => tx.capacity(),
        }
    }

    pub(crate) async fn reserve(&self) -> Result<RawOutboundPermit<'_>, ()> {
        match self {
            Self::Legacy(tx) => tx
                .reserve()
                .await
                .map(RawOutboundPermit::Legacy)
                .map_err(|_| ()),
            Self::Tracked(tx) => tx
                .reserve()
                .await
                .map(RawOutboundPermit::Tracked)
                .map_err(|_| ()),
        }
    }

    #[allow(dead_code)] // Preserve the original sender API for legacy callers.
    pub(crate) fn try_send(
        &self,
        packet: impl Into<RawRequestDelivery>,
    ) -> Result<(), Box<mpsc::error::TrySendError<RawRequestDelivery>>> {
        let packet = packet.into();
        match self {
            Self::Legacy(tx) => {
                if packet.binding.is_some() {
                    return Err(Box::new(mpsc::error::TrySendError::Closed(packet)));
                }
                tx.try_send(packet.raw).map_err(|error| {
                    Box::new(match error {
                        mpsc::error::TrySendError::Full(raw) => {
                            mpsc::error::TrySendError::Full(raw.into())
                        }
                        mpsc::error::TrySendError::Closed(raw) => {
                            mpsc::error::TrySendError::Closed(raw.into())
                        }
                    })
                })
            }
            Self::Tracked(tx) => tx.try_send(packet).map_err(Box::new),
        }
    }

    pub(crate) async fn send(
        &self,
        packet: impl Into<RawRequestDelivery>,
    ) -> Result<(), Box<mpsc::error::SendError<RawRequestDelivery>>> {
        let packet = packet.into();
        match self {
            Self::Legacy(tx) => {
                // Matching private constructors never send a tracked delivery
                // to this compatibility sink. A miswire cannot strip identity.
                if packet.binding.is_some() {
                    return Err(Box::new(mpsc::error::SendError(packet)));
                }
                tx.send(packet.raw)
                    .await
                    .map_err(|error| Box::new(mpsc::error::SendError(error.0.into())))
            }
            Self::Tracked(tx) => tx.send(packet).await.map_err(Box::new),
        }
    }
}

impl RawOutboundPermit<'_> {
    pub(crate) fn send(self, packet: RawRequestDelivery) -> Result<(), Box<RawRequestDelivery>> {
        match self {
            Self::Legacy(slot) => {
                if packet.binding.is_some() {
                    return Err(Box::new(packet));
                }
                slot.send(packet.raw);
            }
            Self::Tracked(slot) => {
                slot.send(packet);
            }
        }
        Ok(())
    }
}

pub(crate) enum RawOutboundReceiver {
    Legacy(mpsc::Receiver<OutboundPacket>),
    Tracked(mpsc::Receiver<RawRequestDelivery>),
}

impl From<mpsc::Receiver<OutboundPacket>> for RawOutboundReceiver {
    fn from(rx: mpsc::Receiver<OutboundPacket>) -> Self {
        Self::Legacy(rx)
    }
}

impl From<mpsc::Receiver<RawRequestDelivery>> for RawOutboundReceiver {
    fn from(rx: mpsc::Receiver<RawRequestDelivery>) -> Self {
        Self::Tracked(rx)
    }
}

impl RawOutboundReceiver {
    pub(crate) async fn recv(&mut self) -> Option<RawRequestDelivery> {
        match self {
            Self::Legacy(rx) => rx.recv().await.map(RawRequestDelivery::from),
            Self::Tracked(rx) => rx.recv().await,
        }
    }

    pub(crate) fn try_recv(&mut self) -> Result<RawRequestDelivery, mpsc::error::TryRecvError> {
        match self {
            Self::Legacy(rx) => rx.try_recv().map(RawRequestDelivery::from),
            Self::Tracked(rx) => rx.try_recv(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Legacy(rx) => rx.len(),
            Self::Tracked(rx) => rx.len(),
        }
    }

    pub(crate) fn close(&mut self) {
        match self {
            Self::Legacy(rx) => rx.close(),
            Self::Tracked(rx) => rx.close(),
        }
    }
}
