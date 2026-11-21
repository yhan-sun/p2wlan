//! Real owner transitions after actual authenticated ingress, with a new
//! canonical and complete native-handler positive after each rejection.
use super::*;
use crate::overlay_requests::OverlayCreditStale as Stale;
use crate::transport::{OriginalSessionRole, ResponderSessionCommit, ResponderSessionStage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum LifecycleCase {
    SessionReplace,
    CounterExpiry,
    Generation,
    RemoveReadd,
    Quarantine,
    UdpOwnerWithdraw,
    PendingPromotion,
    PreviousReceive,
    OriginalWindow,
    LegacyUnknown,
}

pub(super) async fn replace_actual_pair(
    a: &Endpoint,
    b: &Endpoint,
    expiry_counter: bool,
    budget: Budget,
) -> Check {
    // Same static identities as the original registered pair, new actual
    // Noise handshake/session instances, and each real owner's current life.
    let (mut sa, sb, _, _) = session_pair_for(&a.identity, &b.identity)?;
    if expiry_counter {
        sa = sa.with_thresholds(
            u64::MAX,
            Duration::from_secs(180),
            2,
            Duration::from_secs(180),
        );
    }
    let life_a = a
        .peers
        .peer_session_generation_sync(a.remote_node)
        .ok_or("A current authorized life missing")?;
    let life_b = b
        .peers
        .peer_session_generation_sync(b.remote_node)
        .ok_or("B current authorized life missing")?;
    budget
        .step(
            "replace actual A authorized session",
            a.wireguard
                .replace_session_for_lifecycle(a.remote_node, sa, life_a),
        )
        .await?;
    budget
        .step(
            "replace actual B authorized session",
            b.wireguard
                .replace_session_for_lifecycle(b.remote_node, sb, life_b),
        )
        .await?;
    Ok(())
}

pub(super) async fn readmit_actual_pair(
    a: &Endpoint,
    b: &Endpoint,
    path: PathKind,
    budget: Budget,
) -> Check {
    let (sa, sb, a_key, b_key) = session_pair_for(&a.identity, &b.identity)?;
    a.install_peer(b_key, b.local_udp().await?, sa, path, budget)
        .await?;
    b.install_peer(a_key, a.local_udp().await?, sb, path, budget)
        .await?;
    Ok(())
}

async fn reject_ack_without_credit(
    a: &mut Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
    expected: OverlayCreditOutcome,
    budget: Budget,
) -> Check {
    let rounds = a.stats.verified_round_trips;
    let valid = a.stats.received_valid;
    let outcome = commit(a, request, ack)?;
    if outcome != expected {
        return Err(format!(
            "actual stale ACK returned {outcome:?}; expected {expected:?}"
        ));
    }
    require(
        !request.native_ack_credited_for_test(),
        "actual rejected ACK consumed the original canonical once",
    )?;
    native_handler(a, ack.clone(), budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == rounds
            && a.stats.received_valid == valid,
        "native handler converted actual rejected ingress into credit",
    )
}

pub(super) async fn new_actual_positive(
    a: &mut Endpoint,
    b: &mut Endpoint,
    old: &Arc<CanonicalOverlayRequest>,
    path: PathKind,
    budget: Budget,
) -> Check {
    let (fresh, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    require(
        !Arc::ptr_eq(old, &fresh) && old.nonce != fresh.nonce,
        "lifecycle recovery reused the rejected canonical identity",
    )?;
    native_fresh(a, &fresh, ack, path, budget).await?;
    require(
        !old.native_ack_credited_for_test() && fresh.native_ack_credited_for_test(),
        "new actual positive resurrected historical native permission",
    )
}

async fn pending_promotion(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
) -> Check {
    let (sa, sb, _, _) = session_pair_for(&a.identity, &b.identity)?;
    let life_a = a
        .peers
        .peer_session_generation_sync(a.remote_node)
        .ok_or("A pending control life missing")?;
    let life_b = b
        .peers
        .peer_session_generation_sync(b.remote_node)
        .ok_or("B pending control life missing")?;
    budget
        .step(
            "A uses actual new initiator session",
            a.wireguard
                .replace_session_for_lifecycle(a.remote_node, sa, life_a),
        )
        .await?;
    let token = "b28-actual-pending".to_string();
    let staged = budget
        .step(
            "stage actual B responder key",
            b.wireguard.stage_responder_session_for_lifecycle(
                b.remote_node,
                token.clone(),
                sb,
                life_b,
            ),
        )
        .await?;
    require(
        staged == ResponderSessionStage::Staged { had_active: true },
        "pending control did not retain a real prior active slot",
    )?;
    let committed = budget
        .step(
            "commit actual pending responder answer",
            b.wireguard.commit_responder_session(b.remote_node, &token),
        )
        .await?;
    require(
        committed == ResponderSessionCommit::PendingConfirmation,
        "pending responder was prematurely active before actual ingress",
    )?;
    let (request, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    let received = actual_delivery(b, budget).await?;
    let source = received
        .source
        .as_ref()
        .ok_or("actual pending source missing")?;
    require(
        source.session().original_role() == OriginalSessionRole::Pending,
        "first actual pending decrypt was relabeled after promotion",
    )?;
    let status = budget
        .step(
            "actual postdecrypt promotion state",
            b.wireguard.session_status(b.remote_node),
        )
        .await?;
    require(
        status.active_session_instance == Some(source.session().session_instance())
            && !status.has_pending_responder,
        "first actual inbound did not promote its exact pending key",
    )?;
    for _ in 0..2 {
        let retained = received.clone();
        let owners = b.sourced_owners();
        let outcome = budget
            .step(
                "retained pending REQUEST must not inherit active",
                handle_native_overlay_request(
                    retained.event,
                    retained.source,
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
            .await?;
        require(
            outcome
                == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Stale(
                    Stale::Session,
                )),
            "historical pending REQUEST gained echo permission after promotion",
        )?;
    }
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == 0
            && b.stats.received_valid == 0
            && b.stats.verified_round_trips == 0
            && b.pending.is_empty(),
        "pending promotion manufactured canonical credit or an echo queue item",
    )?;
    require(
        matches!(b.routed.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "rejected pending REQUEST reached the actual echo route",
    )?;
    new_actual_positive(a, b, &request, path, budget).await
}

async fn legacy_unknown(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
) -> Check {
    require(
        path == PathKind::Direct,
        "LegacyUnknown control requires actual Direct",
    )?;
    let (request, routed) = mint_actual(a, budget).await?;
    let sent = budget
        .step(
            "actual unfenced slow Direct writer",
            crate::network_outbound::send_original_slow_for_test(
                routed,
                &a.wireguard,
                &a.peers,
                a.peers.current_network_generation_sync(),
                true,
                &a.udp,
                &a.relay,
                false,
            ),
        )
        .await?;
    require(sent, "actual legacy slow writer did not physically send")?;
    let record = request
        .physical_publication
        .record()
        .ok_or("actual slow Full missing")?;
    require(
        record
            .udp()
            .is_some_and(|tx| tx.fence() == crate::udp::UdpSendFence::LegacyUnknown),
        "actual slow Direct source was disguised as a fenced Full",
    )?;
    let received = actual_delivery(b, budget).await?;
    let echo = inject_actual_echo(b, received, budget).await?;
    actual_send(b, echo, path, budget).await?;
    let ack = actual_delivery(a, budget).await?;
    reject_ack_without_credit(
        a,
        &request,
        &ack,
        OverlayCreditOutcome::Unknown(OverlayCreditUnknown::OriginalPublication),
        budget,
    )
    .await?;
    new_actual_positive(a, b, &request, path, budget).await
}

async fn previous_receive(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
) -> Check {
    // The actual WG actor exposes only an observation of its rejected
    // previous-key candidate. The regular overlay feed stays suppressed.
    let mut observed = b.wireguard.install_previous_overlay_observer_for_test();
    let (new_a, new_b, _, _) = session_pair_for(&a.identity, &b.identity)?;
    let life_b = b
        .peers
        .peer_session_generation_sync(b.remote_node)
        .ok_or("B previous control life missing")?;
    let emit = budget
        .step(
            "original B emit guard before overlap installation",
            b.wireguard.acquire_outbound_emit_guard(b.remote_node),
        )
        .await?;
    let epoch = b.peers.network_epoch_gate();
    let epoch_guard = budget
        .step("original B epoch before overlap installation", epoch.lock())
        .await?;
    require(
        b.peers.peer_session_generation_sync(b.remote_node) == Some(life_b),
        "B original handshake lifecycle changed before overlap publication",
    )?;
    let replaced = budget
        .step(
            "B retains its real displaced key as Previous",
            b.wireguard.install_active_session_for_lifecycle_locked(
                b.remote_node,
                None,
                new_b,
                life_b,
            ),
        )
        .await?;
    drop(epoch_guard);
    drop(emit);
    require(
        replaced,
        "actual overlap installation had no old active key",
    )?;
    let (request, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    let delivery = budget
        .step("actual previous-key observer delivery", observed.recv())
        .await?
        .ok_or("actual previous-key observer ended")?;
    let received = actual_delivery_from(b, delivery, budget).await?;
    let source = received
        .source
        .as_ref()
        .ok_or("actual Previous source missing")?;
    require(
        source.session().original_role() == OriginalSessionRole::Previous,
        "actual retained prior key was not recorded as Previous",
    )?;
    let status = budget
        .step(
            "actual displaced/current session identities",
            b.wireguard.session_status(b.remote_node),
        )
        .await?;
    require(
        status.previous_session_instance == Some(source.session().session_instance())
            && status.active_session_instance != status.previous_session_instance,
        "Previous fixture did not retain a distinct genuine current slot",
    )?;
    require(
        received.event.packet == request.original_packet(),
        "actual Previous decrypt changed the original REQUEST bytes",
    )?;
    for _ in 0..2 {
        let retained = received.clone();
        let owners = b.sourced_owners();
        let outcome = budget
            .step(
                "actual Previous cannot borrow current echo authority",
                handle_native_overlay_request(
                    retained.event,
                    retained.source,
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
            .await?;
        require(
            outcome
                == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Stale(
                    Stale::Session,
                )),
            "actual Previous REQUEST borrowed active native echo permission",
        )?;
    }
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == 0
            && b.stats.received_valid == 0
            && b.stats.verified_round_trips == 0
            && b.pending.is_empty(),
        "actual Previous REQUEST manufactured native credit or pending echo",
    )?;
    require(
        matches!(b.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "actual Previous candidate escaped the normal native overlay filter",
    )?;
    require(
        matches!(b.routed.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "rejected actual Previous REQUEST reached the real echo route",
    )?;
    let life_a = a
        .peers
        .peer_session_generation_sync(a.remote_node)
        .ok_or("A active recovery life missing")?;
    budget
        .step(
            "A adopts the genuine current pair after Previous rejection",
            a.wireguard
                .replace_session_for_lifecycle(a.remote_node, new_a, life_a),
        )
        .await?;
    new_actual_positive(a, b, &request, path, budget).await
}

pub(super) async fn exercise_lifecycle(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: LifecycleCase,
    budget: Budget,
) -> Check {
    if case == LifecycleCase::PendingPromotion {
        return pending_promotion(a, b, path, budget).await;
    }
    if case == LifecycleCase::PreviousReceive {
        return previous_receive(a, b, path, budget).await;
    }
    if case == LifecycleCase::LegacyUnknown {
        return legacy_unknown(a, b, path, budget).await;
    }
    if case == LifecycleCase::CounterExpiry {
        replace_actual_pair(a, b, true, budget).await?;
    }
    let (request, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    let expected = match case {
        LifecycleCase::SessionReplace => {
            replace_actual_pair(a, b, false, budget).await?;
            OverlayCreditOutcome::Stale(Stale::Session)
        }
        LifecycleCase::CounterExpiry => {
            let packet = crate::dataplane::OutboundPacket {
                peer_id: a.remote_node.to_string(),
                dst_ip: a.remote_vip.to_string(),
                packet: request.original_packet().to_vec(),
                room_authorization: None,
                trace: None,
            };
            let encrypted = budget
                .step(
                    "actual crypto advances to reject counter",
                    a.wireguard.encrypt_outbound(packet),
                )
                .await?
                .map_err(|e| e.to_string())?;
            require(
                encrypted.is_some(),
                "actual expiry control did not allocate final counter",
            )?;
            require(
                budget
                    .step(
                        "actual active session hard expiry",
                        a.wireguard.session_is_expired(a.remote_node),
                    )
                    .await?,
                "real session hard reject threshold did not expire",
            )?;
            OverlayCreditOutcome::Stale(Stale::Session)
        }
        LifecycleCase::Generation => {
            let next = budget
                .step(
                    "actual network generation advance",
                    a.peers.advance_network_generation("b28-actual-generation"),
                )
                .await?;
            require(
                next != request.generation,
                "actual generation did not advance",
            )?;
            OverlayCreditOutcome::Stale(Stale::Generation)
        }
        LifecycleCase::RemoveReadd => {
            budget
                .step("actual peer removal", a.peers.remove_peer(a.remote_node))
                .await?;
            OverlayCreditOutcome::Stale(Stale::Lifecycle)
        }
        LifecycleCase::Quarantine => {
            budget
                .step(
                    "actual peer quarantine",
                    a.peers
                        .quarantine_peer(a.remote_node, "b28-actual-quarantine"),
                )
                .await?;
            OverlayCreditOutcome::Stale(Stale::Quarantine)
        }
        LifecycleCase::UdpOwnerWithdraw => {
            require(
                path == PathKind::Direct,
                "UDP owner control requires actual Direct",
            )?;
            let slot = budget
                .step("actual UDP owner withdrawal", a.udp.read())
                .await?;
            let udp = slot.as_ref().ok_or("actual UDP owner missing")?;
            require(
                udp.clear_inbound_publication_owner_if_matches(28001),
                "actual UDP owner was not withdrawn",
            )?;
            OverlayCreditOutcome::Stale(Stale::DirectPublication)
        }
        LifecycleCase::OriginalWindow => {
            // This is an approved independent 19-second fixture. It waits for
            // the exact unmodified original std Instant deadline, not for an
            // assumed task ordering. All ordinary prerequisites remain 2s.
            let deadline = request.sent_at + OVERLAY_NONCE_TTL + Duration::from_millis(1);
            tokio::time::timeout_at(
                budget.body_end(),
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)),
            )
            .await
            .map_err(|_| "actual original window wait exceeded bounded body")?;
            require(
                !crate::request_carriage::in_original_window(request.sent_at, Instant::now()),
                "unmodified original canonical window did not actually expire",
            )?;
            OverlayCreditOutcome::Stale(Stale::OriginalWindow)
        }
        LifecycleCase::PendingPromotion
        | LifecycleCase::PreviousReceive
        | LifecycleCase::LegacyUnknown => {
            return Err("special lifecycle dispatch was bypassed".into());
        }
    };
    reject_ack_without_credit(a, &request, &ack, expected, budget).await?;
    let old_life = request.expected_target_lifecycle();
    match case {
        LifecycleCase::SessionReplace | LifecycleCase::OriginalWindow => {}
        LifecycleCase::CounterExpiry => replace_actual_pair(a, b, false, budget).await?,
        LifecycleCase::Quarantine => {
            budget
                .step(
                    "actual peer unquarantine",
                    a.peers
                        .unquarantine_peer(a.remote_node, "b28-actual-recovery"),
                )
                .await?;
            readmit_actual_pair(a, b, path, budget).await?;
        }
        LifecycleCase::Generation | LifecycleCase::RemoveReadd => {
            readmit_actual_pair(a, b, path, budget).await?;
            if case == LifecycleCase::RemoveReadd {
                require(
                    a.peers.peer_session_generation_sync(a.remote_node) != old_life,
                    "real remove/re-add reused the historical lifecycle",
                )?;
            }
        }
        LifecycleCase::UdpOwnerWithdraw => {
            let slot = budget
                .step("actual new UDP publication owner", a.udp.read())
                .await?;
            slot.as_ref()
                .ok_or("actual UDP owner vanished")?
                .set_inbound_publication_owner(28003);
        }
        LifecycleCase::PendingPromotion
        | LifecycleCase::PreviousReceive
        | LifecycleCase::LegacyUnknown => {}
    }
    new_actual_positive(a, b, &request, path, budget).await
}
