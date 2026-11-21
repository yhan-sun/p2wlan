//! Common reader/canonical ACK evidence through actual original native owners.
//! Client replacement retains the already observed route; it does not test
//! route relearning by a replacement auxiliary merge worker.
use super::*;
use crate::overlay_requests::OverlayCreditStale;
use std::pin::Pin;

const POOL_CAP: usize = 4;
const SERVER_CAP: usize = 3;
const EXPLICIT_CAP: usize = 9;

struct PoolTask {
    handle: Option<JoinHandle<()>>,
    joined: bool,
    unexpected: Option<String>,
}

struct Server {
    original: Option<RelayServer>,
    shutdown: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

#[derive(Default)]
struct CommonOwners {
    inner: Owners,
    pool: Vec<PoolTask>,
    servers: Vec<Server>,
    controllers: Vec<MockTunController>,
}

#[derive(Debug, Default)]
struct Cleanup {
    explicit_total: usize,
    explicit_joined: usize,
    pool_total: usize,
    pool_joined: usize,
    server_total: usize,
    servers_completed: usize,
    errors: Vec<String>,
}

impl CommonOwners {
    async fn close(&mut self, budget: Budget) -> Cleanup {
        let mut collected = Cleanup {
            explicit_total: self.inner.tasks.len(),
            server_total: self.servers.len(),
            ..Cleanup::default()
        };
        // All actual converter handles are cancelled before their clients.
        for task in &self.inner.tasks {
            if let Some(handle) = &task.handle {
                handle.abort();
            }
        }
        for relay in &self.inner.relays {
            relay.abort_writer();
            for handle in relay.take_common_pool_handles_for_test() {
                handle.abort();
                // Preserve every returned handle even on a shape failure.
                self.pool.push(PoolTask {
                    handle: Some(handle),
                    joined: false,
                    unexpected: None,
                });
            }
        }
        collected.pool_total = self.pool.len();
        if collected.explicit_total > EXPLICIT_CAP
            || collected.pool_total > POOL_CAP
            || collected.server_total > SERVER_CAP
        {
            collected
                .errors
                .push("actual owner shape exceeded fixed common fixture caps".into());
        }
        for server in &mut self.servers {
            if let Some(original) = server.original.take() {
                // Keep this consuming original future if its same end expires.
                server.shutdown = Some(Box::pin(original.shutdown()));
            }
        }
        if let Err(error) = self.inner.close(budget).await {
            collected.errors.push(error);
        }
        collected.explicit_joined = self
            .inner
            .tasks
            .iter()
            .filter(|task| task.handle.is_none())
            .count();
        for (index, task) in self.pool.iter_mut().enumerate() {
            if task.joined {
                collected.pool_joined += 1;
                if let Some(error) = task.unexpected.as_ref() {
                    collected.errors.push(error.clone());
                }
                continue;
            }
            let Some(handle) = task.handle.as_mut() else {
                collected
                    .errors
                    .push(format!("pool {index}: no handle or actual join"));
                continue;
            };
            match tokio::time::timeout_at(budget.end, handle).await {
                Ok(result) => {
                    task.handle.take();
                    task.joined = true;
                    collected.pool_joined += 1;
                    if !matches!(&result, Ok(()))
                        && !matches!(&result, Err(error) if error.is_cancelled())
                    {
                        collected.errors.push(format!("pool {index}: {result:?}"));
                    }
                }
                Err(_) => collected
                    .errors
                    .push(format!("pool {index}: original fixture end exhausted")),
            }
        }
        for (index, server) in self.servers.iter_mut().enumerate() {
            let Some(shutdown) = server.shutdown.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(budget.end, shutdown.as_mut()).await {
                Ok(()) => {
                    server.shutdown.take();
                    collected.servers_completed += 1;
                }
                Err(_) => collected
                    .errors
                    .push(format!("server {index}: original fixture end exhausted")),
            }
        }
        if collected.explicit_joined == collected.explicit_total {
            // In particular, a body return cannot close MockTun before abort/join.
            self.controllers.clear();
        }
        collected
    }
}

impl Drop for CommonOwners {
    fn drop(&mut self) {
        for task in &self.pool {
            if let Some(handle) = &task.handle {
                handle.abort();
            }
        }
        // Inner Drop cancels explicit/native clients; only close proves joins.
        // Native private RelayClient reader/writer handles are not claimed joined.
    }
}

#[derive(Debug)]
struct Phase {
    label: &'static str,
    node: &'static str,
    nonce: u64,
    seq: u32,
    full_endpoint: String,
    publication: String,
    reader: String,
    request_reader: String,
    result: &'static str,
    native_once: bool,
}

fn outer(endpoint: &Endpoint) -> Result<RelayTransport, String> {
    endpoint
        .relay
        .try_read()
        .map_err(|_| "actual Relay slot contended")?
        .as_ref()
        .cloned()
        .ok_or_else(|| "actual outer Relay absent".into())
}

async fn prepare(
    owners: &mut CommonOwners,
    budget: Budget,
    a: &mut Option<Endpoint>,
    b: &mut Option<Endpoint>,
) -> Result<String, String> {
    for _ in 0..SERVER_CAP {
        let server = budget
            .step("actual common Relay server", RelayServer::start_random())
            .await?
            .map_err(|error| error.to_string())?;
        owners.servers.push(Server {
            original: Some(server),
            shutdown: None,
        });
    }
    let hubs: Vec<_> = owners
        .servers
        .iter()
        .map(|server| format!("tcp://{}", server.original.as_ref().unwrap().addr))
        .collect();
    *a = Some(
        Endpoint::create_inner(
            NODE_A,
            VIP_A,
            NODE_B,
            VIP_B,
            PathKind::Relay,
            Some(&hubs[0]),
            &mut owners.inner,
            budget,
            false,
            false,
            1,
            Some(&hubs[2]),
        )
        .await?,
    );
    owners
        .controllers
        .push(a.as_ref().unwrap().controller.clone());
    *b = Some(
        Endpoint::create_inner(
            NODE_B,
            VIP_B,
            NODE_A,
            VIP_A,
            PathKind::Relay,
            Some(&hubs[1]),
            &mut owners.inner,
            budget,
            false,
            false,
            1,
            Some(&hubs[2]),
        )
        .await?,
    );
    owners
        .controllers
        .push(b.as_ref().unwrap().controller.clone());
    let (a, b) = (a.as_mut().unwrap(), b.as_mut().unwrap());
    // Freeze independent fixture counter origins before either original mint.
    // Same nonce/seq origins on both nodes would make the reverse REQUEST
    // collide with an earlier local ACK in the original shared seen ring.
    b.next_nonce = 0x29_0000;
    let ra = outer(a)?;
    let rb = outer(b)?;
    require(
        ra.endpoint() == hubs[0] && rb.endpoint() == hubs[1] && ra.endpoint() != rb.endpoint(),
        "actual independent primary choices changed",
    )?;
    budget
        .step("actual original common members registered", async {
            while !ra.common_members_ready_for_test(&hubs[2])
                || !rb.common_members_ready_for_test(&hubs[2])
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
    let (session_a, session_b, a_key, b_key) = session_pair_for(&a.identity, &b.identity)?;
    a.install_peer(b_key, None, session_a, PathKind::Relay, budget)
        .await?;
    b.install_peer(a_key, None, session_b, PathKind::Relay, budget)
        .await?;
    Ok(hubs[2].clone())
}

fn actual_phase(
    label: &'static str,
    endpoint: &Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
    echo: &RawRequestDelivery,
    result: &'static str,
) -> Result<Phase, String> {
    let full = request
        .physical_publication
        .record()
        .ok_or("actual original Full missing")?;
    let tx = full.relay().ok_or("actual Relay Full missing")?;
    let source = ack
        .source
        .as_ref()
        .ok_or("actual original ACK source missing")?;
    let phase = Phase {
        label,
        node: endpoint.node,
        nonce: request.nonce,
        seq: request.seq,
        full_endpoint: tx.endpoint().to_string(),
        publication: source
            .relay_endpoint()
            .ok_or("actual outer publication missing")?
            .into(),
        reader: source
            .relay_reader_endpoint()
            .ok_or("actual reader endpoint missing")?
            .into(),
        request_reader: echo
            .original_echo()
            .ok_or("actual original echo input missing")?
            .source()
            .relay_reader_endpoint()
            .ok_or("actual REQUEST reader endpoint missing")?
            .into(),
        result,
        native_once: request.native_ack_credited_for_test(),
    };
    require(
        phase.publication == outer(endpoint)?.endpoint(),
        "actual ACK changed original outer publication",
    )?;
    Ok(phase)
}

fn require_common_read(endpoint: &Endpoint, ack: &ActualDelivery, common: &str) -> Check {
    let source = ack
        .source
        .as_ref()
        .ok_or("actual common ACK source missing")?;
    require_common_source(endpoint, source, common)
}

fn require_common_source(
    endpoint: &Endpoint,
    source: &OriginalOverlayIngressSource,
    common: &str,
) -> Check {
    let relay = outer(endpoint)?;
    let member = relay
        .actual_common_client_for_test(common)
        .ok_or("actual current common client missing")?;
    let read = source
        .original_relay_read()
        .ok_or("actual common original read missing")?;
    require(
        source.relay_endpoint() == Some(relay.endpoint())
            && source.relay_connection_id() == Some(relay.connection_id())
            && source.relay_reader_endpoint() == Some(common)
            && read.belongs_to_client(&member),
        "actual common read/outer/current-client identity mismatch",
    )
}

// The first actual request is deliberately not replayed to pick a favorable
// HashMap fanout branch. Keep its observed Full/read mismatch and native result.
async fn first_fanout(
    a: &mut Endpoint,
    b: &mut Endpoint,
    common: &str,
    phases: &mut [Option<Phase>],
    budget: Budget,
) -> Check {
    let (request, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, PathKind::Relay, budget).await?;
    let received = actual_delivery(b, budget).await?;
    require(
        received.event.packet == request.original_packet(),
        "actual common REQUEST bytes changed",
    )?;
    require_common_read(b, &received, common)?;
    let echo = inject_actual_echo(b, received, budget).await?;
    actual_send(b, echo.clone(), PathKind::Relay, budget).await?;
    let ack = actual_delivery(a, budget).await?;
    require_common_read(a, &ack, common)?;
    let tx_common = request
        .physical_publication
        .record()
        .and_then(|full| full.relay().map(|tx| tx.endpoint() == common))
        .ok_or("first actual Full Relay fact missing")?;
    let saved = ack.clone();
    let outcome = if tx_common {
        native_fresh(a, &request, ack, PathKind::Relay, budget).await?;
        "Fresh"
    } else {
        require(
            commit(a, &request, &ack)?
                == OverlayCreditOutcome::Unknown(OverlayCreditUnknown::CrossRelayClient),
            "actual first cross-client fanout did not remain Unknown",
        )?;
        let before = (a.stats.received_valid, a.stats.verified_round_trips);
        native_handler(a, ack, budget).await?;
        require(
            !request.native_ack_credited_for_test()
                && before == (a.stats.received_valid, a.stats.verified_round_trips),
            "actual first cross-client fanout gained native credit",
        )?;
        "Unknown(CrossRelayClient)"
    };
    phases[0] = Some(actual_phase(
        "C0 first actual fanout",
        a,
        &request,
        &saved,
        &echo,
        outcome,
    )?);
    require(
        outer(a)?.common_route_is_observed_for_test(a.remote_node, common)
            && outer(b)?.common_route_is_observed_for_test(b.remote_node, common),
        "actual original workers did not observe the common route in both directions",
    )
}

async fn fresh_round(
    a: &mut Endpoint,
    b: &mut Endpoint,
    common: &str,
    label: &'static str,
    budget: Budget,
) -> Result<(Phase, Arc<CanonicalOverlayRequest>, RawRequestDelivery), String> {
    let (request, echo, ack) = original_request_and_echo(a, b, PathKind::Relay, budget).await?;
    require_common_source(
        b,
        echo.original_echo()
            .ok_or("actual native echo input missing")?
            .source(),
        common,
    )?;
    require_common_read(a, &ack, common)?;
    let saved = ack.clone();
    native_fresh(a, &request, ack, PathKind::Relay, budget).await?;
    let phase = actual_phase(label, a, &request, &saved, &echo, "Fresh")?;
    require(
        phase.full_endpoint == common && phase.reader == common && phase.request_reader == common,
        "fresh actual round did not use common Full/read",
    )?;
    Ok((phase, request, echo))
}

async fn native_rounds(
    a: &mut Endpoint,
    b: &mut Endpoint,
    common: &str,
    phases: &mut [Option<Phase>],
    budget: Budget,
) -> Check {
    first_fanout(a, b, common, phases, budget).await?;
    let (phase, request, echo) =
        fresh_round(a, b, common, "C1 common native Fresh", budget).await?;
    phases[1] = Some(phase);
    let before = (a.stats.received_valid, a.stats.verified_round_trips);
    let duplicate = repeat_actual_echo(a, b, echo, PathKind::Relay, budget).await?;
    require_common_read(a, &duplicate, common)?;
    qualify_actual_path(a, &request, &duplicate, PathKind::Relay)?;
    native_handler(a, duplicate, budget).await?;
    require(
        request.native_ack_credited_for_test()
            && before == (a.stats.received_valid, a.stats.verified_round_trips),
        "independently reencrypted duplicate common ACK added native credit",
    )?;
    let (phase, next, _) = fresh_round(a, b, common, "C2 new common native Fresh", budget).await?;
    require(
        !Arc::ptr_eq(&request, &next) && request.nonce != next.nonce && request.seq != next.seq,
        "actual new canonical inherited the previous common request identity",
    )?;
    phases[2] = Some(phase);
    Ok(())
}

async fn replace_common(
    a: &Endpoint,
    common: &str,
    owners: &mut CommonOwners,
    budget: Budget,
) -> Result<Arc<p2pnet_relay::RelayClient>, String> {
    let original = outer(a)?;
    let (old_client, handle) = original.take_original_common_worker_for_test(common)?;
    owners.pool.push(PoolTask {
        handle: Some(handle),
        joined: false,
        unexpected: None,
    });
    let task = owners.pool.last_mut().unwrap();
    let handle = task
        .handle
        .as_mut()
        .ok_or("actual retired common worker missing")?;
    handle.abort();
    let result = budget.step("actual old common worker join", handle).await?;
    task.handle.take();
    task.joined = true;
    if !matches!(&result, Ok(())) && !matches!(&result, Err(error) if error.is_cancelled()) {
        task.unexpected = Some(format!("actual retired common worker: {result:?}"));
    }
    require(
        matches!(&result, Ok(())) || matches!(&result, Err(error) if error.is_cancelled()),
        "actual original common worker ended unexpectedly",
    )?;
    let (replacement, rx) = budget
        .step(
            "actual same-node common client registration",
            RelayTransport::connect_secure_for_read::<OriginalRelayDelivery>(
                common,
                "common",
                a.node,
                a.peers.clone(),
                None,
                true,
                None,
            ),
        )
        .await?
        .map_err(|error| error.to_string())?;
    owners.inner.relays.push(replacement.clone());
    require(
        original.install_actual_common_client_for_test(common, &replacement),
        "actual registered replacement common client was not adopted by original pool",
    )?;
    let input = a
        .common_encrypted_input
        .as_ref()
        .ok_or("original encrypted input missing")?
        .clone();
    owners.inner.spawn(
        "actual replacement common reader with original outer converter",
        async move {
            original
                .run_inbound_for_read(rx, input, None)
                .await
                .map_err(|error| error.to_string())
        },
    );
    require(
        !Arc::ptr_eq(
            &old_client,
            &outer(a)?
                .actual_common_client_for_test(common)
                .ok_or("actual replacement common member missing")?,
        ),
        "actual common client identity did not change",
    )?;
    Ok(old_client)
}

async fn replacement_rounds(
    a: &mut Endpoint,
    b: &mut Endpoint,
    common: &str,
    owners: &mut CommonOwners,
    phases: &mut [Option<Phase>],
    budget: Budget,
) -> Check {
    first_fanout(a, b, common, phases, budget).await?;
    let publication = outer(a)?.connection_id();
    let (old_request, old_echo, old_ack) =
        original_request_and_echo(a, b, PathKind::Relay, budget).await?;
    require_common_read(a, &old_ack, common)?;
    let old_client = replace_common(a, common, owners, budget).await?;
    require(
        outer(a)?.connection_id() == publication,
        "actual common member replacement changed the outer publication",
    )?;
    let read = old_ack
        .source
        .as_ref()
        .and_then(|source| source.original_relay_read())
        .ok_or("retained actual old reader missing")?;
    require(
        read.belongs_to_client(&old_client),
        "retained old read changed its historical client",
    )?;
    require(
        commit(a, &old_request, &old_ack)?
            == OverlayCreditOutcome::Stale(OverlayCreditStale::RelayPublication),
        "same-endpoint new member accepted actual old Full/read",
    )?;
    let before = (a.stats.received_valid, a.stats.verified_round_trips);
    native_handler(a, old_ack.clone(), budget).await?;
    require(
        !old_request.native_ack_credited_for_test()
            && before == (a.stats.received_valid, a.stats.verified_round_trips),
        "actual stale common client ACK consumed native once",
    )?;
    phases[1] = Some(actual_phase(
        "C1 retained old member ACK",
        a,
        &old_request,
        &old_ack,
        &old_echo,
        "Stale(RelayPublication)",
    )?);
    // No fabricated route hint. The existing route was learned by C0's real
    // workers. This reverse round proves actual new-reader/member use; the
    // direct replacement converter does not claim auxiliary route relearning.
    let (phase, reverse, _) =
        fresh_round(b, a, common, "C2 reverse actual new-client round", budget).await?;
    phases[2] = Some(phase);
    let (phase, next, _) = fresh_round(a, b, common, "C3 new member common Fresh", budget).await?;
    require(
        old_request.nonce != next.nonce
            && !Arc::ptr_eq(&old_request, &next)
            && reverse.peer_id != next.peer_id
            && !old_request.native_ack_credited_for_test(),
        "new actual member recovery reused or retroactively credited the old request",
    )?;
    phases[3] = Some(phase);
    Ok(())
}

async fn exercise(replacement: bool) -> Check {
    let budget = Budget::new();
    let mut owners = CommonOwners::default();
    let denominator = if replacement { 4 } else { 3 };
    let mut phases: Vec<Option<Phase>> = (0..denominator).map(|_| None).collect();
    // Keep each original endpoint, including channel owners, alive until its
    // actual DataPlane and converter handles have been aborted and joined.
    let (mut a, mut b) = (None, None);
    let body = AssertUnwindSafe(Box::pin(async {
        let common = prepare(&mut owners, budget, &mut a, &mut b).await?;
        let (a, b) = (a.as_mut().unwrap(), b.as_mut().unwrap());
        if replacement {
            replacement_rounds(a, b, &common, &mut owners, &mut phases, budget).await
        } else {
            native_rounds(a, b, &common, &mut phases, budget).await
        }
    }))
    .catch_unwind();
    let result = tokio::time::timeout_at(budget.body_end(), body).await;
    let body_status = match &result {
        Ok(Ok(Ok(()))) => "passed".to_owned(),
        Ok(Ok(Err(error))) => format!("failed: {error}"),
        Ok(Err(_)) => "panicked".to_owned(),
        Err(_) => "original body deadline exhausted".to_owned(),
    };
    let cleanup = owners.close(budget).await;
    eprintln!("r00_common_native denominator={denominator} body={body_status} phases={phases:?} cleanup={cleanup:?}");
    // All business assertions and panic resumption follow collection attempts.
    require(
        cleanup.errors.is_empty()
            && cleanup.explicit_joined == cleanup.explicit_total
            && cleanup.pool_joined == cleanup.pool_total
            && cleanup.servers_completed == cleanup.server_total,
        &format!("actual common fixture cleanup failed: {cleanup:?}"),
    )?;
    match result {
        Ok(Ok(body)) => body?,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => return Err("actual common body exceeded original nine-second end".into()),
    }
    require(
        cleanup.explicit_total == if replacement { 9 } else { 8 }
            && cleanup.pool_total == POOL_CAP
            && cleanup.server_total == SERVER_CAP,
        "actual common fixture successful owner shape changed",
    )?;
    require(
        phases.iter().all(Option::is_some),
        "fixed actual request denominator has an uncompleted phase",
    )?;
    for phase in phases.iter().flatten() {
        require(
            phase.node == NODE_A || phase.node == NODE_B,
            "phase lost actual original node",
        )?;
        require(
            !phase.label.is_empty() && phase.nonce != 0 && phase.seq != 0,
            "phase lost actual canonical identity",
        )?;
        require(
            phase.native_once == (phase.result == "Fresh"),
            "phase result/native once disagree",
        )?;
    }
    Ok(())
}

pub(in super::super) async fn exercise_common_native() -> Check {
    exercise(false).await
}
pub(in super::super) async fn exercise_common_replacement() -> Check {
    exercise(true).await
}
