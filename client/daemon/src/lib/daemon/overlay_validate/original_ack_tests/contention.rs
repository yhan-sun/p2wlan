//! Actual current-owner locks held after a complete authenticated ACK loop.
//! It changes no owner state and manufactures no source or Full.
use super::*;
use crate::overlay_requests::OverlayCreditLockSite as LockSite;
use std::result::Result;

async fn actual_conflict(
    a: &Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
    site: LockSite,
    budget: Budget,
) -> Result<OverlayCreditOutcome, String> {
    // Acquiring the fixture's one chosen real lock may wait under the same
    // prerequisite deadline. Once acquired, the final API is purely sync.
    // Each lexical arm releases it before the result is examined or any
    // subsequent network, recovery, or cleanup work can begin.
    match site {
        LockSite::Emit => {
            let _held = budget
                .step(
                    "hold original emit",
                    a.wireguard.acquire_outbound_emit_guard(a.remote_node),
                )
                .await?;
            commit(a, request, ack)
        }
        LockSite::Epoch => {
            let gate = a.peers.network_epoch_gate();
            let _held = budget.step("hold original epoch", gate.lock()).await?;
            commit(a, request, ack)
        }
        LockSite::Sessions => {
            let _held = budget
                .step(
                    "hold original sessions",
                    a.wireguard.hold_session_registry_for_test(),
                )
                .await?;
            commit(a, request, ack)
        }
        LockSite::Connections => {
            let _held = budget
                .step(
                    "hold original connections",
                    a.peers.hold_connections_writer_for_test(),
                )
                .await?;
            commit(a, request, ack)
        }
        LockSite::Membership => a
            .peers
            .with_peer_membership_held_for_test(|| commit(a, request, ack)),
        LockSite::Quarantine => a
            .peers
            .with_original_quarantine_held_for_test(|| commit(a, request, ack)),
        LockSite::DirectPolicy => a
            .peers
            .with_original_capability_held_for_test(|| commit(a, request, ack)),
        LockSite::UdpSlot => {
            let _held = budget.step("hold original UDP slot", a.udp.write()).await?;
            commit(a, request, ack)
        }
        LockSite::DirectPublication => {
            let udp = budget
                .step("borrow actual UDP owner", a.udp.read())
                .await?
                .clone()
                .ok_or("actual UDP owner absent before publication conflict")?;
            let runtime = udp.dplpmtud_runtime();
            let _held = runtime
                .try_original_business_publication_guard()
                .ok_or("fixture could not hold actual Direct publication")?;
            commit(a, request, ack)
        }
        LockSite::RelaySlot => {
            let _held = budget
                .step("hold original Relay slot", a.relay.write())
                .await?;
            commit(a, request, ack)
        }
        LockSite::RelayLive | LockSite::RelayClose => {
            let relay = budget
                .step("borrow actual Relay owner", a.relay.read())
                .await?
                .clone()
                .ok_or("actual Relay owner absent before conflict")?;
            if site == LockSite::RelayLive {
                relay.with_original_live_held_for_test(|| commit(a, request, ack))
            } else {
                relay.with_original_client_open_held_for_test(|| commit(a, request, ack))
            }
        }
        _ => Err(format!(
            "{site:?} needs an actual-owner seam not present in this child"
        )),
    }
}

pub(super) async fn exercise_conflicts(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
) -> Check {
    let mut sites = vec![
        LockSite::Emit,
        LockSite::Epoch,
        LockSite::Sessions,
        LockSite::Connections,
        LockSite::Membership,
        LockSite::Quarantine,
    ];
    if path == PathKind::Direct {
        sites.extend([
            LockSite::UdpSlot,
            LockSite::DirectPolicy,
            LockSite::DirectPublication,
        ]);
    } else {
        sites.extend([
            LockSite::RelaySlot,
            LockSite::RelayLive,
            LockSite::RelayClose,
        ]);
    }
    for site in sites {
        let (request, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
        let outcome = actual_conflict(a, &request, &ack, site, budget).await?;
        if outcome != OverlayCreditOutcome::Contended(site) {
            return Err(format!(
                "actual {site:?} conflict returned {outcome:?}, expected exact Contended"
            ));
        }
        require(
            !request.native_ack_credited_for_test(),
            "actual lock conflict consumed the canonical once",
        )?;
        // The same retained real ACK commits after release. This also proves
        // earlier guards held by the final transaction did not leak.
        commit_fresh(a, &request, &ack, path)?;
        require(
            request.native_ack_credited_for_test(),
            "actual contention recovery failed to consume canonical once",
        )?;
        require(
            commit(a, &request, &ack)? == OverlayCreditOutcome::AlreadyCommitted,
            "actual contention recovery granted a second once",
        )?;
    }
    // End with a wholly new canonical and a fresh real reader/decrypt source,
    // rather than relying exclusively on replaying retained observations.
    let (fresh, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    native_fresh(a, &fresh, ack, path, budget).await?;
    require(
        fresh.native_ack_credited_for_test(),
        "new canonical did not recover after the actual lock matrix",
    )?;
    Ok(())
}
