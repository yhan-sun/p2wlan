//! Revoke the real current return owner, retain original old Echo/prepare,
//! prove compatibility alone cannot authorize asymmetry, then really revalidate.
use super::*;
use crate::request_carriage::EncryptedRequestDelivery;
use crate::udp::{
    DirectBusinessBudgetGate, DirectBusinessUdpSendError, PreparedDirectBusinessSend,
};

async fn join_initial_validators(owners: &mut Owners, budget: Budget) -> Check {
    let mut joined = 0;
    for task in &mut owners.tasks {
        if task.label != "original explicit encrypted validator" {
            continue;
        }
        let handle = task
            .handle
            .as_mut()
            .ok_or("initial validator handle already lost")?;
        let result = budget
            .step("join actual initial validator before revalidation", handle)
            .await?;
        task.handle.take();
        match result {
            Ok(Ok(())) => joined += 1,
            other => return Err(format!("initial original validator join failed: {other:?}")),
        }
    }
    require(
        joined == 2,
        "revalidation began without both original validators joined",
    )
}

async fn join_recovery_validator(owners: &mut Owners, budget: Budget) -> Check {
    let mut pending = owners.tasks.iter_mut().filter(|task| {
        task.label == "original explicit encrypted validator" && task.handle.is_some()
    });
    let task = pending.next().ok_or("actual recovery validator missing")?;
    require(
        pending.next().is_none(),
        "recovery acquired more than its one original validator",
    )?;
    let handle = task.handle.as_mut().unwrap();
    let result = budget
        .step(
            "join actual recovery validator before new canonical",
            handle,
        )
        .await?;
    task.handle.take();
    match result {
        Ok(Ok(())) => Ok(()),
        other => Err(format!("actual recovery validator join failed: {other:?}")),
    }
}

async fn revoke_return(endpoint: &Endpoint, budget: Budget) -> Check {
    let generation = endpoint.peers.current_network_generation_sync();
    let life = endpoint
        .peers
        .peer_session_generation_sync(endpoint.remote_node)
        .ok_or("revoked return lifecycle missing")?;
    let local = endpoint
        .local_udp()
        .await?
        .ok_or("original return local socket missing")?;
    let changed = budget
        .step(
            "original owner commits Direct path failure",
            endpoint
                .peers
                .record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
                    endpoint.remote_node,
                    generation,
                    life,
                    crate::peer::REASON_DIRECT_SEND_FAILED,
                    "pr209 actual return owner invalidation",
                    Some(local),
                ),
        )
        .await?;
    require(changed, "original return owner refused actual revocation")?;
    let snapshot = endpoint
        .peers
        .committed_business_path_snapshot_sync(endpoint.remote_node)
        .ok_or("original revoked path projection missing")?;
    require(
        !matches!(snapshot.active, ActiveBusinessPath::Direct(_)),
        "original revoke left the owned Direct return active",
    )
}

async fn reject_old_prewrite(
    b: &Endpoint,
    echo: &RawRequestDelivery,
    encrypted: &EncryptedRequestDelivery,
    prepared: &PreparedDirectBusinessSend,
    return_endpoint: SocketAddr,
    budget: Budget,
) -> Check {
    let epoch = b.peers.network_epoch_gate();
    let _epoch = budget
        .step("original echo rejection epoch", epoch.lock())
        .await?;
    let slot = budget
        .step("original current echo UDP slot", b.udp.read())
        .await?;
    let udp = slot
        .as_ref()
        .ok_or("original echo slot withdrawn unexpectedly")?;
    let input = echo
        .original_echo()
        .ok_or("actual sealed original Echo missing")?;
    // The real UDP owner can briefly publish while this read-only fixture
    // check runs. Keep the original input and emit/epoch fencing, and wait
    // only for that explicit contention within the existing step deadline.
    // Stale/unknown input still fails; this does not retry any send or ACK.
    budget
        .step("qualify actual current Echo source before rejection", async {
            loop {
                match b
                    .peers
                    .try_qualify_original_echo_input_in_epoch(&b.wireguard, input)
                {
                    Ok(()) => break Ok(()),
                    Err(crate::overlay_requests::OverlayCreditOutcome::Contended(
                        crate::overlay_requests::OverlayCreditLockSite::DirectPublication,
                    )) => tokio::task::yield_now().await,
                    Err(error) => {
                        break Err(format!(
                            "rejection did not preserve real current source qualification: {error:?}"
                        ));
                    }
                }
            }
        })
        .await??;
    // Demonstrate the new qualifier is reached with real active session and
    // current original RX provenance. Do not hold this guard while reacquiring
    // it in the actual prewrite method below.
    let guard = b
        .peers
        .try_original_echo_peer_in_epoch(
            input,
            encrypted
                .source()
                .ok_or("actual encrypted Echo source missing")?,
        )
        .map_err(|e| format!("actual original peer/source guard failed: {e:?}"))?;
    require(
        guard
            .verified_direct_return_local(input, return_endpoint)
            .is_none(),
        "unowned return state qualified a distinct actual receive source",
    )?;
    drop(guard);
    let prewrite = encrypted
        .original_echo_prewrite()
        .ok_or("actual crypto lost sealed prewrite")?;
    let outcome =
        prewrite.try_send_direct_in_epoch(udp, Some(prepared), encrypted, return_endpoint);
    require(
        matches!(outcome, Err(DirectBusinessUdpSendError::StaleToken)),
        &format!("actual old asymmetric Echo/prepared was not rejected StaleToken: {outcome:?}"),
    )
}

async fn await_exact_recovery_budget(
    a: &Endpoint,
    b: &Endpoint,
    request_endpoint: SocketAddr,
    return_endpoint: SocketAddr,
    budget: Budget,
) -> Check {
    let (a_udp, b_udp) = budget
        .step("borrow actual recovery UDP", async {
            let a_udp = a.udp.read().await.as_ref().cloned();
            let b_udp = b.udp.read().await.as_ref().cloned();
            (a_udp, b_udp)
        })
        .await?;
    let a_udp = a_udp.ok_or("A recovery UDP missing")?;
    let b_udp = b_udp.ok_or("B recovery UDP missing")?;
    budget
        .step("current real revalidated DPL publication", async {
            loop {
                let a_ready = a_udp
                    .prepare_direct_business_send(a.remote_node, request_endpoint)
                    .await;
                let b_ready = b_udp
                    .prepare_direct_business_send(b.remote_node, return_endpoint)
                    .await;
                if let (
                    DirectBusinessBudgetGate::Ready(a_prepared),
                    DirectBusinessBudgetGate::Ready(b_prepared),
                ) = (a_ready, b_ready)
                {
                    // BASE can publish Ready while the original worker is
                    // still probing. Wait for both exact real paths to finish
                    // before minting the one recovery REQUEST; do not retry a
                    // REQUEST rejected by the unchanged native emit guard.
                    let complete = |udp: &UdpTransport, prepared: &PreparedDirectBusinessSend| {
                        udp.dplpmtud_runtime()
                            .snapshot_for_path(&prepared.token.path_identity)
                            .is_some_and(|snapshot| {
                                snapshot.state == crate::dplpmtud::DplpmtudState::SearchComplete
                                    && snapshot.budget_revision
                                        == Some(prepared.token.budget_revision)
                                    && snapshot.outstanding_probe.is_none()
                                    && !snapshot.current_plpmtu_confirmation_pending
                            })
                    };
                    if complete(&a_udp, &a_prepared) && complete(&b_udp, &b_prepared) {
                        return Ok(());
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await?
}

pub(super) async fn exercise(
    a: &mut Endpoint,
    b: &mut Endpoint,
    request_endpoint: SocketAddr,
    proxy_source: SocketAddr,
    return_endpoint: SocketAddr,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    join_initial_validators(owners, budget).await?;
    let (old_request, echo) = prepare_asymmetric_echo(
        a,
        b,
        request_endpoint,
        proxy_source,
        return_endpoint,
        budget,
    )
    .await?;
    let rounds = a.stats.verified_round_trips;
    let valid = a.stats.received_valid;
    {
        // Original prepare, real carriage crypto and its retained emit guard,
        // not literals standing in for a token, source, ciphertext or Full.
        let udp = budget
            .step("borrow original Echo prepare UDP", b.udp.read())
            .await?
            .as_ref()
            .cloned()
            .ok_or("original Echo prepare UDP missing")?;
        let prepared = match budget
            .step(
                "capture actual original Echo prepare",
                udp.prepare_direct_business_send(b.remote_node, return_endpoint),
            )
            .await?
        {
            DirectBusinessBudgetGate::Ready(prepared) => prepared,
            other => return Err(format!("actual original Echo prepare not ready: {other:?}")),
        };
        let emit = Arc::new(
            budget
                .step(
                    "retain original Echo emit",
                    b.wireguard.acquire_outbound_emit_guard(b.remote_node),
                )
                .await?,
        );
        let mut encrypted = budget
            .step(
                "original Echo carriage successful encryption",
                b.wireguard.encrypt_request_with_emit_guard(echo.clone()),
            )
            .await?
            .map_err(|e| e.to_string())?
            .ok_or("actual Echo encryption unavailable")?;
        encrypted.bind_original_echo_emit(&emit);
        revoke_return(b, budget).await?;
        reject_old_prewrite(b, &echo, &encrypted, &prepared, return_endpoint, budget).await?;
        require(
            !old_request.native_ack_credited_for_test()
                && a.stats.verified_round_trips == rounds
                && a.stats.received_valid == valid,
            "revoked original Echo gained canonical credit",
        )?;
        let local = b.local_udp().await?.ok_or("compat return local missing")?;
        budget
            .step(
                "original same-endpoint compatibility commit",
                b.peers.record_direct_success_with_local_endpoint(
                    b.remote_node,
                    Some(return_endpoint),
                    Some(local),
                ),
            )
            .await?;
        let snapshot = b
            .peers
            .committed_business_path_snapshot_sync(b.remote_node)
            .ok_or("actual compatibility reducer projection missing")?;
        let ActiveBusinessPath::Direct(identity) = snapshot.active else {
            return Err("original compatibility API did not commit Direct".into());
        };
        require(
            identity.commit_endpoint() == Some(return_endpoint)
                && identity.owner_token.is_none()
                && identity.request_id.is_none(),
            "actual reducer did not expose solely compatibility return identity",
        )?;
        let conn = budget
            .step(
                "inspect original compat return conditions",
                b.peers.get_connection(b.remote_node),
            )
            .await?
            .ok_or("original compat return connection missing")?;
        require(
            snapshot.lifecycle == PeerPathLifecycle::Online
                && snapshot.epoch == Some(identity.epoch)
                && identity.epoch.network_generation == b.peers.current_network_generation_sync()
                && Some(identity.epoch.peer_session_generation)
                    == b.peers.peer_session_generation_sync(b.remote_node)
                && identity.epoch.remote_candidate_epoch == conn.remote_candidate_epoch()
                && conn.direct_generation == identity.epoch.network_generation
                && conn.direct_is_healthy_confirmed()
                && conn.selected_direct_endpoint_for_consent(identity.epoch.network_generation)
                    == Some(return_endpoint)
                && conn.candidate_pairs.iter().any(|pair| {
                    pair.local_generation == identity.epoch.network_generation
                        && pair.remote_candidate_epoch == identity.epoch.remote_candidate_epoch
                        && pair.remote_endpoint == return_endpoint
                        && pair.local_endpoint == Some(local)
                        && pair.state == crate::peer::CandidatePairState::Selected
                        && pair.selected_at.is_some()
                }),
            "compat control lost other genuine current return prerequisites",
        )?;
        reject_old_prewrite(b, &echo, &encrypted, &prepared, return_endpoint, budget).await?;
        require(
            !old_request.native_ack_credited_for_test()
                && a.stats.verified_round_trips == rounds
                && a.stats.received_valid == valid,
            "compat-only original Echo gained canonical credit",
        )?;
        // Old ciphertext and prepared token are dropped, never reparked as a
        // new canonical. Release emit before the real validator's crypto.
    }
    revoke_return(b, budget).await?;
    start_actual_validator(b, return_endpoint, owners, budget).await?;
    await_exact_recovery_budget(a, b, request_endpoint, return_endpoint, budget).await?;
    // DPL publication can precede the validator releasing its original emit
    // guard. Join that actual owner before minting the next request; never
    // retry a request rejected while the old worker still holds the guard.
    join_recovery_validator(owners, budget).await?;
    asymmetric_round(
        a,
        b,
        request_endpoint,
        proxy_source,
        return_endpoint,
        budget,
    )
    .await
    .map_err(|error| format!("asymmetric revalidation recovery/new canonical: {error}"))?;
    require(
        !old_request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == rounds + 1
            && a.stats.received_valid == valid + 1,
        "fresh canonical recovery reused or credited the rejected pending original",
    )
}
