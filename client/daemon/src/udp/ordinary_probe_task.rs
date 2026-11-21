//! One original fresh-mapping child, using its invocation's existing deadline.

use super::ordinary_probe_cost::{OrdinaryProbeCost, OrdinaryProducerSettlement};

pub(crate) struct OrdinaryProbeTask {
    cost: OrdinaryProbeCost,
    deadline: tokio::time::Instant,
    child: Option<tokio::task::JoinHandle<()>>,
}

impl OrdinaryProbeTask {
    pub(crate) fn spawn(
        cost: OrdinaryProbeCost,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Self {
        // Construction owns exactly one optimization child, not a registry.
        let producer = cost.start_producer();
        let child = tokio::spawn(async move {
            let _producer = producer;
            work.await;
        });
        Self {
            cost,
            deadline,
            child: Some(child),
        }
    }

    pub(crate) async fn finish(&mut self, cancelled: bool) -> Option<tokio::task::JoinError> {
        let child = self.child.as_mut()?;
        if cancelled {
            child.abort();
        }
        match tokio::time::timeout_at(self.deadline, child).await {
            Ok(result) => {
                // A completed handle is removed before exposing its result.
                self.child.take();
                let settlement = match &result {
                    Ok(()) => OrdinaryProducerSettlement::Joined,
                    Err(error) if error.is_cancelled() => {
                        OrdinaryProducerSettlement::CancelledJoined
                    }
                    Err(_) => OrdinaryProducerSettlement::FailedJoined,
                };
                self.cost.settle_producer(settlement);
                result.err()
            }
            Err(_) => {
                if let Some(child) = self.child.as_ref() {
                    child.abort();
                }
                self.cost
                    .settle_producer(OrdinaryProducerSettlement::OriginalProducerNotJoined);
                None
            }
        }
    }
}

impl Drop for OrdinaryProbeTask {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_ref() {
            child.abort();
            self.cost
                .settle_producer(OrdinaryProducerSettlement::OriginalProducerNotJoined);
            tracing::debug!(
                event = "ordinary_probe_retained_cost",
                snapshot = ?self.cost.snapshot(),
                scope = "observed_primary_compatibility_returns_only",
                "original invocation dropped; abort requested; producer not joined; excludes bursts and ACKs"
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/ordinary_probe_task.rs"]
mod tests;
