//! Negative identities are taken from real loops/owners. Parser corruption is
//! explicitly local mutation of already decrypted bytes, not a claim that WG
//! authenticated malformed bytes. No original source capability is minted.
use super::*;
use crate::overlay_requests::OverlayCreditStale as Stale;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum IdentityCase {
    OtherCanonicalAck,
    ForeignWireGuardOwner,
    RoomAuthority,
    ParserCorruption,
}

fn no_native_change(
    a: &Endpoint,
    request: &CanonicalOverlayRequest,
    rounds: u64,
    valid: u64,
) -> Check {
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == rounds
            && a.stats.received_valid == valid,
        "invalid identity/parser input consumed native once or diagnostics",
    )
}

pub(super) async fn exercise_identity(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: IdentityCase,
    budget: Budget,
) -> Check {
    let (request, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    let rounds = a.stats.verified_round_trips;
    let valid = a.stats.received_valid;
    match case {
        IdentityCase::OtherCanonicalAck => {
            let (other, _echo, other_ack) = original_request_and_echo(a, b, path, budget).await?;
            require(
                !Arc::ptr_eq(&request, &other) && request.nonce != other.nonce,
                "wrong-ACK control did not use a second actual canonical",
            )?;
            require(
                commit(a, &request, &other_ack)? == OverlayCreditOutcome::Stale(Stale::Identity),
                "real other-canonical ACK credited the original canonical",
            )?;
            no_native_change(a, &request, rounds, valid)?;
            require(
                !other.native_ack_credited_for_test(),
                "wrong-canonical final API consumed the other canonical once",
            )?;
            native_fresh(a, &other, other_ack, path, budget).await?;
        }
        IdentityCase::ForeignWireGuardOwner => {
            let owners = OriginalOverlayCurrentOwners {
                wireguard: &b.wireguard,
                ..a.current_owners()
            };
            let parsed = OriginalOverlayAck::parse(&ack.event.packet, &ack.event.peer_id)
                .ok_or("actual ACK parse failed before foreign-owner control")?;
            require(
                a.peers.try_commit_original_overlay_ack(
                    &owners,
                    &request,
                    &parsed,
                    ack.source.as_ref(),
                ) == OverlayCreditOutcome::Stale(Stale::Session),
                "real foreign WG owner accepted another owner's original sources",
            )?;
            no_native_change(a, &request, rounds, valid)?;
        }
        IdentityCase::RoomAuthority => {
            let ordinary = a.room.clone();
            a.room = Arc::new(crate::rooms::RoomAuthorization::new("room-original-ack"));
            let rejected = commit(a, &request, &ack)?;
            // Restore the actual fixture owner even if the expectation fails.
            let native = native_handler(a, ack.clone(), budget).await;
            a.room = ordinary;
            require(
                rejected == OverlayCreditOutcome::Unknown(OverlayCreditUnknown::RoomAuthority),
                "enabled actual room owner gained unsupported native ACK authority",
            )?;
            native?;
            no_native_change(a, &request, rounds, valid)?;
        }
        IdentityCase::ParserCorruption => {
            let original = ack.event.packet.clone();
            let udp_start = usize::from(original[0] & 0x0f) * 4;
            let payload = udp_start + 8;
            let mut variants = Vec::new();
            let mut truncated = original.clone();
            truncated.pop();
            variants.push(truncated);
            let mut appended = original.clone();
            appended.push(0);
            variants.push(appended);
            let mut fragmented = original.clone();
            fragmented[6] |= 0x20;
            variants.push(fragmented);
            let mut corrupt_crc = original.clone();
            corrupt_crc[payload + OVERLAY_CHECKSUM_OFFSET] ^= 1;
            variants.push(corrupt_crc);
            let mut wrong_direction = original;
            wrong_direction[payload + OVERLAY_MAGIC.len()] = OVERLAY_DIRECTION_REQUEST;
            variants.push(wrong_direction);
            for packet in variants {
                require(
                    OriginalOverlayAck::parse(&packet, &ack.event.peer_id).is_none(),
                    "locally corrupted actual ACK passed strict frame parsing",
                )?;
                let mut derived = ack.clone();
                derived.event.packet = packet;
                native_handler(a, derived, budget).await?;
                no_native_change(a, &request, rounds, valid)?;
            }
        }
    }
    native_fresh(a, &request, ack, path, budget).await?;
    let (fresh, _echo, fresh_ack) = original_request_and_echo(a, b, path, budget).await?;
    require(
        !Arc::ptr_eq(&request, &fresh),
        "identity recovery reused original canonical",
    )?;
    native_fresh(a, &fresh, fresh_ack, path, budget).await
}
