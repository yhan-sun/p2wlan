//! Retain the actual received ACK while the original connection owner is
//! briefly occupied. No packet resend, source factory, or replacement once.
use super::*;
use crate::overlay_requests::OverlayCreditLockSite;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum AckContentionCase {
    Current,
    SessionReplaced,
    Cancelled,
    Deadline,
}

pub(super) async fn exercise_native_ack_contention(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: AckContentionCase,
    budget: Budget,
) -> Check {
    let (request, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    let peers = a.peers.clone();
    let held = budget
        .step(
            "hold actual native ACK connection owner",
            peers.hold_connections_writer_for_test(),
        )
        .await?;
    require(
        commit(a, &request, &ack)?
            == OverlayCreditOutcome::Contended(OverlayCreditLockSite::Connections),
        "original native ACK did not reach the actual connection conflict",
    )?;
    require(
        !request.native_ack_credited_for_test(),
        "conflict consumed once",
    )?;
    let valid = a.stats.received_valid;
    let rounds = a.stats.verified_round_trips;
    match case {
        AckContentionCase::Current => {
            // Both futures belong to this original fixture body; no new worker
            // or grace deadline. The first handler poll sees the held owner.
            let (handled, ()) = tokio::join!(native_handler(a, ack, budget), async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(held);
            });
            handled?;
            require(
                request.native_ack_credited_for_test()
                    && a.stats.received_valid == valid + 1
                    && a.stats.verified_round_trips == rounds + 1,
                "native original ACK was forgotten under live connections contention",
            )?;
        }
        AckContentionCase::SessionReplaced => {
            let wireguard = a.wireguard.clone();
            let remote = a.remote_node;
            let life = request
                .expected_target_lifecycle()
                .ok_or("waiting ACK authorized life missing")?;
            let (sa, _, _, _) = session_pair_for(&a.identity, &b.identity)?;
            let (handled, changed) = tokio::join!(native_handler(a, ack, budget), async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                budget
                    .step(
                        "replace the actual waiting ACK session",
                        wireguard.replace_session_for_lifecycle(remote, sa, life),
                    )
                    .await?;
                drop(held);
                Ok::<(), String>(())
            });
            changed?;
            handled?;
            require(
                !request.native_ack_credited_for_test()
                    && a.stats.received_valid == valid
                    && a.stats.verified_round_trips == rounds,
                "waiting native ACK borrowed the replacement session",
            )?;
            lifecycle::replace_actual_pair(a, b, false, budget).await?;
        }
        AckContentionCase::Cancelled => {
            {
                let pending = native_handler(a, ack, budget);
                tokio::pin!(pending);
                tokio::select! {
                    biased;
                    outcome = &mut pending => {
                        outcome?;
                        return Err("contended native ACK ended before owner cancellation".into());
                    }
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
                // Drop the actual handler future; there is no detached retry.
            }
            drop(held);
            require(
                !request.native_ack_credited_for_test()
                    && a.stats.received_valid == valid
                    && a.stats.verified_round_trips == rounds,
                "cancelled native ACK consumed original once",
            )?;
        }
        AckContentionCase::Deadline => {
            let owners = a.sourced_owners();
            // The independent 19s original-window fixture permits waiting for
            // the real unmodified std Instant deadline. No ordinary 2s step
            // or original packet lifetime is widened.
            tokio::time::timeout_at(
                budget.body_end(),
                handle_native_overlay_ack(
                    ack.event,
                    ack.source,
                    &owners,
                    &a.udp,
                    &a.peers,
                    &a.timeline,
                    &mut a.seen,
                    &mut a.stats,
                    &a.sent,
                    &mut a.bursts,
                ),
            )
            .await
            .map_err(|_| "contended native ACK did not stop at original deadline")?;
            drop(held);
            require(
                !crate::request_carriage::in_original_window(request.sent_at, Instant::now())
                    && !request.native_ack_credited_for_test()
                    && a.stats.received_valid == valid
                    && a.stats.verified_round_trips == rounds,
                "contended native ACK renewed original window or consumed once",
            )?;
        }
    }
    // A fresh actual REQUEST completes after the original pending receipt.
    let (fresh, _echo, delivery) = original_request_and_echo(a, b, path, budget).await?;
    require(
        !Arc::ptr_eq(&request, &fresh),
        "contention recovery reused the old canonical",
    )?;
    native_fresh(a, &fresh, delivery, path, budget).await?;
    require(
        a.stats.verified_round_trips == rounds + 1 + u64::from(case == AckContentionCase::Current),
        "contention recovery changed native once accounting",
    )?;
    Ok(())
}
