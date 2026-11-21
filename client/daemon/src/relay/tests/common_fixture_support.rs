//! Fixture-only access to actual original common pool handles/members.
//! No original read/write fact or source can be constructed here.
use super::*;

impl RelayTransport {
    pub(crate) fn common_route_is_observed_for_test(&self, peer: &str, common: &str) -> bool {
        self.rendezvous.as_ref().is_some_and(|pool| {
            let routes = pool.routes.lock().unwrap_or_else(|p| p.into_inner());
            !pool.stopped.load(std::sync::atomic::Ordering::Acquire)
                && routes.clients.contains_key(common)
                && routes.peers.get(peer).is_some_and(|route| route == common)
        })
    }

    pub(crate) fn common_members_ready_for_test(&self, common: &str) -> bool {
        self.rendezvous.as_ref().is_some_and(|pool| {
            let routes = pool.routes.lock().unwrap_or_else(|p| p.into_inner());
            !pool.stopped.load(std::sync::atomic::Ordering::Acquire)
                && routes.clients.len() == 2
                && routes.clients.contains_key(self.endpoint())
                && routes.clients.contains_key(common)
                && self.endpoint() != common
        })
    }

    pub(crate) fn take_common_pool_handles_for_test(&self) -> Vec<tokio::task::JoinHandle<()>> {
        self.rendezvous.as_ref().map_or_else(Vec::new, |pool| {
            std::mem::take(&mut *pool.tasks.lock().unwrap_or_else(|p| p.into_inner()))
        })
    }

    // The original two-candidate constructor creates primary first, then its
    // sole common auxiliary worker. Transfer that exact task, before abort/join.
    pub(crate) fn take_original_common_worker_for_test(
        &self,
        common: &str,
    ) -> std::result::Result<(Arc<RelayClient>, tokio::task::JoinHandle<()>), String> {
        let pool = self.rendezvous.as_ref().ok_or("original pool missing")?;
        if pool.plan.candidates.len() != 2
            || pool
                .plan
                .candidates
                .iter()
                .filter(|c| c.endpoint != self.endpoint())
                .count()
                != 1
            || !pool.plan.candidates.iter().any(|c| c.endpoint == common)
            || common == self.endpoint()
        {
            return Err("original common fixture pool shape changed".into());
        }
        let client = pool
            .routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clients
            .get(common)
            .cloned()
            .ok_or("original common member missing")?;
        let mut tasks = pool.tasks.lock().unwrap_or_else(|p| p.into_inner());
        if tasks.len() != 2 {
            return Err("original common worker shape changed".into());
        }
        Ok((client, tasks.remove(1)))
    }

    pub(crate) fn install_actual_common_client_for_test(
        &self,
        common: &str,
        actual: &RelayTransport,
    ) -> bool {
        actual.endpoint() == common
            && self
                .rendezvous
                .as_ref()
                .is_some_and(|pool| pool.insert(common, actual.client.clone()))
    }

    pub(crate) fn actual_common_client_for_test(&self, common: &str) -> Option<Arc<RelayClient>> {
        self.rendezvous.as_ref().and_then(|pool| {
            pool.routes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clients
                .get(common)
                .cloned()
        })
    }
}
