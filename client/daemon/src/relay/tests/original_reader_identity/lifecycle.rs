//! Reuse real original reader -> decrypt -> source and native Forward writes.
use super::*;
use crate::relay::original_member::RelayMemberFailure as Failure;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Mode {
    Identity,
    Replace,
    Stop,
    Close,
    Retire,
}

pub(super) fn fresh(
    outer: &RelayTransport,
    tx: &RelayFullSendFact,
    rx: &OriginalRelayFrameRead,
    id: u64,
) -> Check {
    let member = outer
        .try_original_member_guard(tx, rx, id)
        .map_err(|e| format!("fresh membership rejected: {e:?}"))?;
    let _open = member
        .try_open_guard()
        .map_err(|e| format!("fresh open rejected: {e:?}"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check(
    outer: &RelayTransport,
    other: &RelayTransport,
    endpoint: &str,
    old_client: &Arc<RelayClient>,
    facts: &[Arc<RelayFullSendFact>],
    old_read: &OriginalRelayFrameRead,
    new_read: &OriginalRelayFrameRead,
    id: u64,
    mode: Mode,
    end: tokio::time::Instant,
) -> Check {
    let pool = outer.rendezvous.as_ref().ok_or("pool missing")?;
    let fresh_tx = &facts[1];
    require(
        matches!(
            outer.try_original_member_guard(&facts[0], old_read, id),
            Err(Failure::StaleMember)
        ),
        "kept old client authorized replaced member",
    )?;
    require(
        matches!(
            outer.try_original_member_guard(fresh_tx, old_read, id),
            Err(Failure::UnknownReader)
        ),
        "old read borrowed fresh writer identity",
    )?;
    require(
        matches!(
            other.try_original_member_guard(fresh_tx, new_read, id),
            Err(Failure::StalePublication)
        ),
        "wrong outer accepted original facts",
    )?;
    require(
        matches!(
            outer.try_original_member_guard(fresh_tx, new_read, id + 1),
            Err(Failure::StalePublication)
        ),
        "wrong RX publication accepted",
    )?;
    fresh(outer, fresh_tx, new_read, id)?;

    // A late original worker cleanup cannot remove the concrete replacement.
    pool.remove_if_client(endpoint, old_client);
    fresh(outer, fresh_tx, new_read, id)?;
    let current = pool
        .routes
        .lock()
        .unwrap()
        .clients
        .get(endpoint)
        .cloned()
        .ok_or("replacement missing")?;
    require(
        !Arc::ptr_eq(&current, old_client),
        "fixture never replaced original client",
    )?;
    {
        let _routes = pool.routes.lock().unwrap();
        require(
            matches!(
                outer.try_original_member_guard(fresh_tx, new_read, id),
                Err(Failure::ContendedRoutes)
            ),
            "routes conflict failed to reject",
        )?;
        require(
            outer.write_boundaries_live.try_lock().is_ok(),
            "routes conflict captured live",
        )?;
    }
    fresh(outer, fresh_tx, new_read, id)?;
    {
        let _live = outer.write_boundaries_live.lock().unwrap();
        require(
            matches!(
                outer.try_original_member_guard(fresh_tx, new_read, id),
                Err(Failure::ContendedLive)
            ),
            "live conflict failed to reject",
        )?;
        require(
            pool.routes.try_lock().is_ok(),
            "live conflict leaked earlier routes guard",
        )?;
    }
    fresh(outer, fresh_tx, new_read, id)?;
    {
        let _close = current
            .try_open_guard()
            .map_err(|e| format!("hold close: {e:?}"))?;
        let member = outer
            .try_original_member_guard(fresh_tx, new_read, id)
            .map_err(|e| format!("member before close: {e:?}"))?;
        require(
            matches!(member.try_open_guard(), Err(Failure::ContendedClose)),
            "close conflict failed to reject",
        )?;
        drop(member);
        require(
            pool.routes.try_lock().is_ok(),
            "close conflict leaked routes",
        )?;
        require(
            outer.write_boundaries_live.try_lock().is_ok(),
            "close conflict leaked live",
        )?;
    }
    fresh(outer, fresh_tx, new_read, id)?;
    match mode {
        Mode::Replace => {
            pool.remove_if_client(endpoint, &current);
            require(
                matches!(
                    outer.try_original_member_guard(fresh_tx, new_read, id),
                    Err(Failure::StaleMember)
                ),
                "current removal did not revoke",
            )?;
        }
        Mode::Close => {
            // Keep this exact member registered while its original client
            // closes; the real pool worker may otherwise remove it first.
            let member = outer
                .try_original_member_guard(fresh_tx, new_read, id)
                .map_err(|e| format!("member before close: {e:?}"))?;
            current.abort();
            loop {
                require(
                    tokio::time::Instant::now() < end,
                    "closed member observation exceeded original end",
                )?;
                match member.try_open_guard() {
                    Err(Failure::Closed) => {
                        require(
                            tokio::time::Instant::now() < end,
                            "closed member observation exceeded original end",
                        )?;
                        break;
                    }
                    Err(Failure::ContendedClose) => {
                        // Reader/writer shutdown can republish the same
                        // terminal watch under its gate. Contention is never
                        // success: observe Closed within the original end.
                        std::thread::yield_now();
                    }
                    Err(error) => return Err(format!("closed member check failed: {error:?}")),
                    Ok(_) => return Err("closed member became open".into()),
                }
            }
        }
        Mode::Retire => {
            outer.retire_write_boundaries();
            require(
                matches!(
                    outer.try_original_member_guard(fresh_tx, new_read, id),
                    Err(Failure::Retired)
                ),
                "retired original publication accepted",
            )?;
        }
        Mode::Stop => {
            let member = outer
                .try_original_member_guard(fresh_tx, new_read, id)
                .map_err(|e| format!("member before stop: {e:?}"))?;
            let open = member
                .try_open_guard()
                .map_err(|e| format!("open before stop: {e:?}"))?;
            let stopped = pool.clone();
            let stopper = std::thread::spawn(move || stopped.stop());
            let limit = end.into_std();
            while !pool
                .stop_attempted
                .load(std::sync::atomic::Ordering::Acquire)
                && Instant::now() < limit
            {
                std::thread::yield_now();
            }
            let reached = pool
                .stop_attempted
                .load(std::sync::atomic::Ordering::Acquire);
            let held_stop = pool.stopped.load(std::sync::atomic::Ordering::Acquire);
            // Always release before checking outcomes; never strand the stopper.
            drop(open);
            drop(member);
            stopper.join().map_err(|_| "stopper panicked")?;
            require(
                reached && !held_stop,
                "stop crossed held original member guard",
            )?;
            require(
                matches!(
                    outer.try_original_member_guard(fresh_tx, new_read, id),
                    Err(Failure::Stopped)
                ),
                "stop did not revoke membership",
            )?;
            require(
                !pool.insert(endpoint, current),
                "stopped pool accepted a new registration",
            )?;
        }
        Mode::Identity => return Err("lifecycle control not requested".into()),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_member_replacement_and_exact_worker_cleanup() -> Check {
    original_reader_identity(Mode::Replace).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_member_stop_waits_and_cannot_revive() -> Check {
    original_reader_identity(Mode::Stop).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_member_close_retains_history_without_permission() -> Check {
    original_reader_identity(Mode::Close).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_member_retired_outer_rejects_live_old_client() -> Check {
    original_reader_identity(Mode::Retire).await
}
