//! Actual REQUEST retained at the native pre-injection eligibility boundary.
//! Use the real received source, TUN echo, encryption and native final ACK.
use super::*;
use crate::overlay_requests::OverlayCreditStale;

pub(super) async fn exercise_request_contention(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: AckContentionCase,
    budget: Budget,
) -> Check {
    let (record, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    let received = actual_delivery(b, budget).await?;
    let source = received
        .source
        .as_ref()
        .ok_or("real REQUEST source missing")?;
    let read_at = match (source.original_udp_read(), source.original_relay_read()) {
        (Some(read), None) => read.received_at(),
        (None, Some(read)) => read.completed_at(),
        _ => return Err("real REQUEST read identity missing".into()),
    };
    let life = source
        .session()
        .authorized_peer_lifecycle()
        .ok_or("real REQUEST authorized life missing")?;
    let peers = b.peers.clone();
    let held = budget
        .step(
            "hold actual REQUEST connection owner",
            peers.hold_connections_writer_for_test(),
        )
        .await?;
    let valid = b.stats.received_valid;
    let rounds = b.stats.verified_round_trips;
    match case {
        AckContentionCase::Current => {
            let (echoed, ()) = tokio::join!(call_native_request(b, received, budget), async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(held);
            });
            let echoed = echoed?;
            require(echoed == OriginalRequestEchoOutcome::Injected, &format!("native original REQUEST was forgotten before TUN echo under connections contention: {echoed:?}"))?;
            require(
                b.stats.received_valid == valid + 1 && b.stats.verified_round_trips == rounds,
                "REQUEST wait fabricated a verified roundtrip",
            )?;
            let identity =
                OriginalOverlayAck::parse_request(record.original_packet(), a.remote_node)
                    .ok_or("canonical REQUEST framing changed")?;
            let echo = take_actual_echo(b, identity, budget).await?;
            actual_send(b, echo, path, budget).await?;
            let ack = actual_delivery(a, budget).await?;
            native_fresh(a, &record, ack, path, budget).await?;
        }
        AckContentionCase::SessionReplaced => {
            let wireguard = b.wireguard.clone();
            let remote = b.remote_node;
            let (_, session, _, _) = session_pair_for(&a.identity, &b.identity)?;
            let (echoed, changed) = tokio::join!(call_native_request(b, received, budget), async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                budget
                    .step(
                        "replace actual waiting REQUEST session",
                        wireguard.replace_session_for_lifecycle(remote, session, life),
                    )
                    .await?;
                drop(held);
                Ok::<(), String>(())
            });
            changed?;
            require(
                echoed?
                    == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Stale(
                        OverlayCreditStale::Session,
                    )),
                "waiting REQUEST borrowed replacement session",
            )?;
            lifecycle::replace_actual_pair(a, b, false, budget).await?;
        }
        AckContentionCase::Cancelled => {
            {
                let pending = call_native_request(b, received, budget);
                tokio::pin!(pending);
                tokio::select! {
                    biased;
                    echoed = &mut pending => {
                        echoed?;
                        return Err("contended REQUEST ended before native caller cancellation".into());
                    }
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
            }
            drop(held);
        }
        AckContentionCase::Deadline => {
            let owners = b.sourced_owners();
            let echoed = tokio::time::timeout_at(
                budget.body_end(),
                handle_native_overlay_request(
                    received.event,
                    received.source,
                    &owners,
                    &b.udp,
                    &b.peers,
                    &b.controller,
                    b.vip,
                    true,
                    true,
                    &mut b.seen,
                    &mut b.stats,
                    &mut b.pending,
                ),
            )
            .await
            .map_err(|_| "REQUEST wait exceeded original-window fixture end")?;
            drop(held);
            require(
                !crate::request_carriage::in_original_window(read_at, Instant::now())
                    && echoed
                        == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Stale(
                            OverlayCreditStale::OriginalWindow,
                        )),
                "contended REQUEST renewed the original read window",
            )?;
        }
    }
    if case != AckContentionCase::Current {
        require(
            b.stats.received_valid == valid
                && b.stats.verified_round_trips == rounds
                && b.pending.is_empty(),
            "rejected/cancelled REQUEST changed credit or pending echo",
        )?;
        require(
            matches!(b.routed.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "rejected/cancelled REQUEST injected a TUN echo",
        )?;
        require(
            !record.native_ack_credited_for_test(),
            "rejected/cancelled REQUEST consumed old native once",
        )?;
    }
    let (fresh, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    native_fresh(a, &fresh, ack, path, budget).await?;
    require(
        a.stats.verified_round_trips == 1 + u64::from(case == AckContentionCase::Current),
        "REQUEST wait changed final native once accounting",
    )?;
    Ok(())
}
