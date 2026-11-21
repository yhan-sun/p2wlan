//! Real registry contention at the original sender before encryption, with
//! its existing FIFO, fixed deadline, original source and native ACK handler.
use super::*;
use crate::network_outbound::{OriginalEchoQueueForTest, REASON_ORIGINAL_ECHO_SOURCE_CONTENDED};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum EchoContentionCase {
    Current,
    SessionReplaced,
    Deadline,
}

pub(super) async fn exercise_echo_contention(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: EchoContentionCase,
    budget: Budget,
) -> Check {
    // Install the daemon's single accounting sink. Standalone crypto
    // fixtures otherwise have no transport send-failure counter sink.
    let loss_sink = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    b.peers.set_outbound_loss_sink(loss_sink.clone());
    b.wireguard.set_outbound_loss_sink(Some(loss_sink));
    let (request, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    let received = actual_delivery(b, budget).await?;
    let echo = inject_actual_echo(b, received, budget).await?;
    let mut queue = OriginalEchoQueueForTest::new(
        echo.clone(),
        b.wireguard.clone(),
        b.peers.clone(),
        path == PathKind::Direct,
        b.udp.clone(),
        b.relay.clone(),
        path == PathKind::Relay,
        b.timeline.clone(),
    );
    let deadline = queue.deadline();
    let held = budget
        .step(
            "hold actual B session registry",
            b.wireguard.hold_session_registry_for_test(),
        )
        .await?;
    budget
        .step("actual original Echo FIFO contended flush", queue.flush())
        .await?;
    require(
        queue.retains_exact_echo(&echo),
        "registry contention terminally lost the original sealed Echo",
    )?;
    require(
        queue.deadline() == deadline,
        "contention renewed the original FIFO deadline",
    )?;
    require(
        queue.retry_after().is_some(),
        "contention did not pace the original FIFO retry",
    )?;
    require(
        b.wireguard
            .try_acquire_outbound_emit_guard(b.remote_node)
            .is_some(),
        "contention retained the emit lock",
    )?;
    require(
        b.peers.network_epoch_gate().try_lock().is_ok(),
        "contention retained the epoch lock",
    )?;
    require(
        matches!(a.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "contended Echo reached actual remote decrypt",
    )?;
    require(
        !request.native_ack_credited_for_test(),
        "contention consumed the original native once",
    )?;
    let losses = budget
        .step(
            "actual contention accounting",
            b.peers.outbound_loss_stats(),
        )
        .await?;
    require(
        losses.drops.is_empty(),
        "transient registry contention was accounted as terminal loss",
    )?;
    require(
        losses
            .send_failures
            .get(REASON_ORIGINAL_ECHO_SOURCE_CONTENDED)
            .map(|v| v.packets)
            == Some(1),
        "actual FIFO did not classify one original source contention",
    )?;
    // Exercise the same queue again while the original registry remains held.
    budget
        .step(
            "original retry pacing",
            tokio::time::sleep_until(tokio::time::Instant::from_std(queue.retry_after().unwrap())),
        )
        .await?;
    budget
        .step("second actual contended FIFO flush", queue.flush())
        .await?;
    require(
        queue.retains_exact_echo(&echo) && queue.deadline() == deadline,
        "second contention changed source, bytes or original cutoff",
    )?;
    drop(held);
    match case {
        EchoContentionCase::Current => {
            budget
                .step(
                    "released original retry pacing",
                    tokio::time::sleep_until(tokio::time::Instant::from_std(
                        queue.retry_after().unwrap(),
                    )),
                )
                .await?;
            budget
                .step("current original Echo FIFO send", queue.flush())
                .await?;
            require(queue.is_empty(), "current original Echo remained in FIFO")?;
            let ack = actual_delivery(a, budget).await?;
            native_fresh(a, &request, ack, path, budget).await?;
            require(
                a.stats.verified_round_trips == 1 && request.native_ack_credited_for_test(),
                "current retried Echo did not earn exactly one native roundtrip",
            )?;
            require(
                matches!(a.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                "plaintext retry emitted more than one authenticated Echo",
            )?;
            require(
                budget
                    .step("post-send actual losses", b.peers.outbound_loss_stats())
                    .await?
                    .drops
                    .is_empty(),
                "successful current retry incurred a terminal loss",
            )?;
        }
        EchoContentionCase::SessionReplaced => {
            lifecycle::replace_actual_pair(a, b, false, budget).await?;
            budget
                .step("stale original Echo FIFO flush", queue.flush())
                .await?;
            require(
                queue.is_empty(),
                "old source survived replacement as retryable",
            )?;
            let losses = budget
                .step("stale actual source loss", b.peers.outbound_loss_stats())
                .await?;
            require(
                losses
                    .drops
                    .get("original_echo_source_rejected")
                    .map(|v| v.packets)
                    == Some(1),
                "replaced original source was not terminally rejected",
            )?;
            require(
                !request.native_ack_credited_for_test()
                    && matches!(a.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                "replaced original source emitted or consumed once",
            )?;
            lifecycle::new_actual_positive(a, b, &request, path, budget).await?;
        }
        EchoContentionCase::Deadline => {
            // Wait for the unchanged production three-second cutoff. This is
            // inside the original nine-second body, with its cleanup reserve.
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            budget
                .step("expired original Echo FIFO flush", queue.flush())
                .await?;
            require(queue.is_empty(), "expired original Echo was reparked")?;
            let losses = budget
                .step("expired actual source loss", b.peers.outbound_loss_stats())
                .await?;
            require(
                losses
                    .drops
                    .get(crate::network_outbound::REASON_OUTBOUND_DELIVERY_DEADLINE)
                    .map(|v| v.packets)
                    == Some(1),
                "contention bypassed the original delivery cutoff",
            )?;
            require(
                !request.native_ack_credited_for_test()
                    && matches!(a.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                "expired original Echo emitted or consumed once",
            )?;
            // Queue expiry also reports its existing local ICMP error to the
            // real TUN. Consume and verify that separate output before the
            // next REQUEST; it has no authenticated OverlayIngress source.
            let feedback = budget
                .step("actual expired Echo local ICMP output", b.written.recv())
                .await?
                .ok_or("expired Echo did not produce local TUN feedback")?;
            let ip = p2pnet_tun::Ipv4Packet::new(&feedback)
                .map_err(|e| format!("expired Echo feedback is malformed: {e}"))?;
            require(
                ip.protocol() == p2pnet_tun::Protocol::Icmp
                    && ip.src_addr().to_string() == a.vip
                    && ip.dst_addr().to_string() == b.vip
                    && ip.payload().get(..2) == Some(&[3, 1])
                    && ip.payload().get(8..) == Some(&echo.packet[..28]),
                "expired Echo local feedback is not the exact quoted host-unreachable",
            )?;
            lifecycle::new_actual_positive(a, b, &request, path, budget).await?;
        }
    }
    Ok(())
}
