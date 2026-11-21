//! The sealed actual REQUEST source must remain current after MockTun/read,
//! DataPlane routing, and the actor transfer, immediately before actual send.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum EchoCase {
    SessionReplace,
    Generation,
    UdpOwnerWithdraw,
}

async fn rejected_original_send(
    b: &Endpoint,
    echo: RawRequestDelivery,
    path: PathKind,
    budget: Budget,
) -> Check {
    let sent = budget
        .step(
            "original sender requalifies sealed queued echo",
            crate::network_outbound::send_original_for_test(
                echo,
                &b.wireguard,
                &b.peers,
                b.peers.current_network_generation_sync(),
                path == PathKind::Direct,
                &b.udp,
                &b.relay,
                path == PathKind::Relay,
            ),
        )
        .await?;
    require(
        !sent,
        "original sender emitted an echo with a stale retained REQUEST source",
    )
}

pub(super) async fn exercise_echo_transfer(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: EchoCase,
    budget: Budget,
) -> Check {
    let (request, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    let received = actual_delivery(b, budget).await?;
    let echo = inject_actual_echo(b, received, budget).await?;
    require(
        echo.original_echo().is_some(),
        "real queued echo lost its sealed source",
    )?;
    // The opaque original source is still current. Mutating bytes through the
    // existing RawDelivery API must not borrow its sealed send permission.
    let mut mismatched = echo.clone();
    *mismatched
        .packet
        .last_mut()
        .ok_or("actual sealed echo unexpectedly has no bytes")? ^= 1;
    rejected_original_send(b, mismatched, path, budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == 0
            && b.stats.verified_round_trips == 0,
        "mismatched actual echo bytes borrowed a fresh original source",
    )?;
    match case {
        EchoCase::SessionReplace => {
            lifecycle::replace_actual_pair(a, b, false, budget).await?;
        }
        EchoCase::Generation => {
            budget
                .step(
                    "B generation changes after actual echo route",
                    b.peers
                        .advance_network_generation("b28-echo-transfer-generation"),
                )
                .await?;
        }
        EchoCase::UdpOwnerWithdraw => {
            require(
                path == PathKind::Direct,
                "echo UDP owner control requires Direct",
            )?;
            let slot = budget
                .step("withdraw actual B echo publication", b.udp.read())
                .await?;
            require(
                slot.as_ref()
                    .ok_or("actual B UDP owner missing")?
                    .clear_inbound_publication_owner_if_matches(28002),
                "actual B publication was not withdrawn",
            )?;
        }
    }
    rejected_original_send(b, echo.clone(), path, budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == 0
            && b.stats.verified_round_trips == 0,
        "stale queued echo gained credit before actual send",
    )?;
    require(
        matches!(a.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "stale queued echo produced an actual authenticated ACK delivery",
    )?;
    match case {
        EchoCase::SessionReplace => {}
        EchoCase::Generation => lifecycle::readmit_actual_pair(a, b, path, budget).await?,
        EchoCase::UdpOwnerWithdraw => {
            let slot = budget
                .step("publish actual fresh B owner", b.udp.read())
                .await?;
            slot.as_ref()
                .ok_or("actual B UDP owner vanished")?
                .set_inbound_publication_owner(28004);
        }
    }
    // A fresh owner cannot relabel the already queued immutable old source.
    rejected_original_send(b, echo, path, budget).await?;
    lifecycle::new_actual_positive(a, b, &request, path, budget).await
}
