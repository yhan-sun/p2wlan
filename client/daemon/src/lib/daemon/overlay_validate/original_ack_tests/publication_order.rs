//! A real ACK read before the original Full publication's real observation
//! cannot inherit that later publication. No timestamp/phase setter is used.
use super::*;
use crate::overlay_requests::OverlayCreditStale as Stale;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use tokio::sync::oneshot;

struct PublicationRelease(Option<SyncSender<()>>);
impl PublicationRelease {
    fn release(&mut self) -> Check {
        self.0
            .take()
            .ok_or("publication gate already released")?
            .send(())
            .map_err(|_| "actual publication gate ended before release".into())
    }
}
impl Drop for PublicationRelease {
    fn drop(&mut self) {
        // Always release the bounded fixture barrier on a body error. This is
        // not a publication/source guard and does not reset either fact.
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

pub(super) async fn exercise_publication_order(
    a: &mut Endpoint,
    b: &mut Endpoint,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    let path = PathKind::Direct;
    let (request, routed) = mint_actual(a, budget).await?;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let mut release = PublicationRelease(Some(release_tx));
    let gate_failed = Arc::new(AtomicBool::new(false));
    let hook_failed = gate_failed.clone();
    request
        .physical_publication
        .set_recorded_observation_hook_for_test(move || {
            // The original LAN core has already released UDP slot, epoch and
            // emit before its original publisher invokes this one-shot hook.
            // B/A can therefore run the actual echo/decrypt path on the other
            // worker. Timeout is an explicit failure, never a negative pass.
            let announced = entered_tx.send(()).is_ok();
            let released = release_rx.recv_timeout(Duration::from_millis(500)).is_ok();
            if !announced || !released {
                hook_failed.store(true, Ordering::Release);
            }
        });
    let wg = a.wireguard.clone();
    let peers = a.peers.clone();
    let udp = a.udp.clone();
    let relay = a.relay.clone();
    let generation = a.peers.current_network_generation_sync();
    let (finished_tx, finished_rx) = oneshot::channel();
    owners.spawn("owned actual LAN causal sender", async move {
        let sent = crate::network_outbound::send_original_for_test(
            routed, &wg, &peers, generation, true, &udp, &relay, false,
        )
        .await;
        let _ = finished_tx.send(sent);
        require(
            sent,
            "actual causal LAN sender failed instead of physically completing",
        )
    });
    budget
        .step("actual Full enters bounded observation gap", entered_rx)
        .await?
        .map_err(|_| "actual sender never reached the original observation gap")?;
    let received = actual_delivery(b, budget).await?;
    require(
        received.event.packet == request.original_packet(),
        "observation-gap remote did not actually decrypt original REQUEST",
    )?;
    let echo = inject_actual_echo(b, received, budget).await?;
    actual_send(b, echo.clone(), path, budget).await?;
    let early = actual_delivery(a, budget).await?;
    require(
        request.physical_publication.state() == PhysicalPublicationState::Publishing
            && request.physical_publication.record().is_none()
            && request
                .physical_publication
                .recorded_observed_at()
                .is_none(),
        "real observation gap ended before the actual ACK arrived",
    )?;
    require(
        commit(a, &request, &early)?
            == OverlayCreditOutcome::Unknown(OverlayCreditUnknown::OriginalPublication),
        "early real ACK gained credit before Full was observably published",
    )?;
    native_handler(a, early.clone(), budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.received_valid == 0
            && a.stats.verified_round_trips == 0,
        "native early ACK gained credit in the real publication gap",
    )?;
    release.release()?;
    require(
        budget
            .step(
                "actual publisher completes after explicit release",
                finished_rx,
            )
            .await?
            .map_err(|_| "actual causal sender disappeared")?,
        "actual causal sender did not report Sent",
    )?;
    require(
        !gate_failed.load(Ordering::Acquire),
        "actual publication barrier exceeded its original 500ms failure bound",
    )?;
    require(
        request.physical_publication.state() == PhysicalPublicationState::Recorded,
        "actual publisher did not finish its real original Full record",
    )?;
    let observed_at = request
        .physical_publication
        .recorded_observed_at()
        .ok_or("real original publication observation is absent")?;
    let source = early
        .source
        .as_ref()
        .ok_or("actual early ACK source missing")?;
    let read = source
        .original_udp_read()
        .ok_or("actual early Direct read missing")?;
    require(
        read.received_at() < observed_at && source.session().authenticated_at() < observed_at,
        "early provenance was not actually before the later original publication",
    )?;
    require(
        commit(a, &request, &early)? == OverlayCreditOutcome::Stale(Stale::ReadBeforePublication),
        "early actual ACK inherited a later observable Full publication",
    )?;
    native_handler(a, early, budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.received_valid == 0
            && a.stats.verified_round_trips == 0,
        "native stale early ACK consumed once after publication",
    )?;
    // Independently encrypt the actual sealed echo again. The canonical is
    // unchanged, while the new actual reader/authentication times are later.
    let fresh_ack = repeat_actual_echo(a, b, echo, path, budget).await?;
    native_fresh(a, &request, fresh_ack, path, budget).await?;
    let (fresh, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    require(
        !Arc::ptr_eq(&request, &fresh),
        "causal recovery reused canonical identity",
    )?;
    native_fresh(a, &fresh, ack, path, budget).await
}
