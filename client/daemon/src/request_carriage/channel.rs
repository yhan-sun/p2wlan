//! One selected existing raw channel; conversion has no extra queue or task.

use crate::dataplane_resources::{ResidencyStage, ResourceCapture};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{OutboundPacket, RawRequestDelivery};

#[derive(Clone)]
pub(crate) enum RawOutboundSink {
    Legacy(mpsc::Sender<OutboundPacket>),
    Tracked(mpsc::Sender<RawRequestDelivery>),
    ObservedTracked {
        tx: mpsc::Sender<RawRequestDelivery>,
        capture: Arc<ResourceCapture>,
    },
}

pub(crate) enum RawOutboundPermit<'a> {
    Legacy(mpsc::Permit<'a, OutboundPacket>),
    Tracked(mpsc::Permit<'a, RawRequestDelivery>),
    ObservedTracked {
        slot: mpsc::Permit<'a, RawRequestDelivery>,
        capture: &'a Arc<ResourceCapture>,
    },
}

impl RawOutboundSink {
    pub(crate) fn with_resource_capture(self, capture: Arc<ResourceCapture>) -> Self {
        match self {
            Self::Tracked(tx) | Self::ObservedTracked { tx, .. } => {
                Self::ObservedTracked { tx, capture }
            }
            Self::Legacy(tx) => {
                capture.unobserved_residency_exit();
                Self::Legacy(tx)
            }
        }
    }

    pub(crate) fn is_tracked(&self) -> bool {
        !matches!(self, Self::Legacy(_))
    }

    pub(crate) fn max_capacity(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.max_capacity(),
            Self::Tracked(tx) | Self::ObservedTracked { tx, .. } => tx.max_capacity(),
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.capacity(),
            Self::Tracked(tx) | Self::ObservedTracked { tx, .. } => tx.capacity(),
        }
    }

    pub(crate) async fn reserve(&self) -> Result<RawOutboundPermit<'_>, ()> {
        match self {
            Self::Legacy(tx) => tx
                .reserve()
                .await
                .map(RawOutboundPermit::Legacy)
                .map_err(|_| ()),
            Self::ObservedTracked { tx, capture } => tx
                .reserve()
                .await
                .map(|slot| RawOutboundPermit::ObservedTracked { slot, capture })
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
        let mut packet = packet.into();
        match self {
            Self::Legacy(tx) => {
                packet.materialize();
                if packet.binding().is_some() {
                    return Err(Box::new(mpsc::error::TrySendError::Closed(packet)));
                }
                packet.metadata.unobserved_exit();
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
            Self::Tracked(tx) if !packet.metadata.is_observed() => {
                tx.try_send(packet).map_err(Box::new)
            }
            Self::Tracked(tx) => Self::try_send_observed(tx, packet, None),
            Self::ObservedTracked { tx, capture } => {
                Self::try_send_observed(tx, packet, Some(capture))
            }
        }
    }

    pub(crate) async fn send(
        &self,
        packet: impl Into<RawRequestDelivery>,
    ) -> Result<(), Box<mpsc::error::SendError<RawRequestDelivery>>> {
        let mut packet = packet.into();
        match self {
            Self::Legacy(tx) => {
                packet.materialize();
                // Matching private constructors never send a tracked delivery
                // to this compatibility sink. A miswire cannot strip identity.
                if packet.binding().is_some() {
                    return Err(Box::new(mpsc::error::SendError(packet)));
                }
                packet.metadata.unobserved_exit();
                tx.send(packet.raw)
                    .await
                    .map_err(|error| Box::new(mpsc::error::SendError(error.0.into())))
            }
            Self::Tracked(tx) if !packet.metadata.is_observed() => {
                tx.send(packet).await.map_err(Box::new)
            }
            Self::Tracked(tx) => Self::send_observed(tx, packet, None).await,
            Self::ObservedTracked { tx, capture } => {
                Self::send_observed(tx, packet, Some(capture)).await
            }
        }
    }

    fn try_send_observed(
        tx: &mpsc::Sender<RawRequestDelivery>,
        mut packet: RawRequestDelivery,
        capture: Option<&Arc<ResourceCapture>>,
    ) -> Result<(), Box<mpsc::error::TrySendError<RawRequestDelivery>>> {
        packet.observe_resources(capture, ResidencyStage::ChannelReserve);
        match tx.try_reserve() {
            Ok(slot) => {
                packet.relocate_resources(ResidencyStage::RawChannel);
                slot.send(packet);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(Box::new(mpsc::error::TrySendError::Full(packet)))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(Box::new(mpsc::error::TrySendError::Closed(packet)))
            }
        }
    }

    async fn send_observed(
        tx: &mpsc::Sender<RawRequestDelivery>,
        mut packet: RawRequestDelivery,
        capture: Option<&Arc<ResourceCapture>>,
    ) -> Result<(), Box<mpsc::error::SendError<RawRequestDelivery>>> {
        packet.observe_resources(capture, ResidencyStage::ChannelReserve);
        match tx.reserve().await {
            Ok(slot) => {
                packet.relocate_resources(ResidencyStage::RawChannel);
                slot.send(packet);
                Ok(())
            }
            Err(_) => Err(Box::new(mpsc::error::SendError(packet))),
        }
    }
}

impl RawOutboundPermit<'_> {
    pub(crate) fn send(
        self,
        mut packet: RawRequestDelivery,
    ) -> Result<(), Box<RawRequestDelivery>> {
        match self {
            Self::Legacy(slot) => {
                packet.materialize();
                if packet.binding().is_some() {
                    return Err(Box::new(packet));
                }
                packet.metadata.unobserved_exit();
                slot.send(packet.raw);
            }
            Self::Tracked(slot) => {
                packet.relocate_resources(ResidencyStage::RawChannel);
                slot.send(packet);
            }
            Self::ObservedTracked { slot, capture } => {
                let mut packet = packet;
                packet.observe_resources(Some(capture), ResidencyStage::RawChannel);
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
            Self::Tracked(rx) => rx.recv().await.map(|mut packet| {
                packet.relocate_resources(ResidencyStage::DetachedRaw);
                packet
            }),
        }
    }

    pub(crate) fn try_recv(&mut self) -> Result<RawRequestDelivery, mpsc::error::TryRecvError> {
        match self {
            Self::Legacy(rx) => rx.try_recv().map(RawRequestDelivery::from),
            Self::Tracked(rx) => rx.try_recv().map(|mut packet| {
                packet.relocate_resources(ResidencyStage::DetachedRaw);
                packet
            }),
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
