//! The actual five close publishers contend with the original borrowed gate.
use super::*;
use crate::client::close::{ClosePublisher, RelayCloseSignal};
use crate::client::RelayClientOpenError;
use tokio::sync::oneshot;

struct HeldOpen {
    release: Option<std::sync::mpsc::SyncSender<()>>,
    thread: Option<std::thread::JoinHandle<Check>>,
}
impl HeldOpen {
    async fn start(signal: Arc<RelayCloseSignal>, budget: Budget) -> Result<Self, String> {
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let (ready, started) = oneshot::channel();
        let end = budget.end.into_std();
        let thread = std::thread::spawn(move || {
            let guard = signal
                .try_open()
                .map_err(|e| format!("fresh open: {e:?}"))?;
            let _ = ready.send(());
            let result = released.recv_timeout(end.saturating_duration_since(Instant::now()));
            drop(guard);
            result.map_err(|error| format!("open gate release: {error}"))
        });
        let owner = Self {
            release: Some(release),
            thread: Some(thread),
        };
        budget
            .step("original open guard acquired", started)
            .await?
            .map_err(|_| "open holder exited before acquisition")?;
        Ok(owner)
    }
    fn release_and_join(mut self) -> Check {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.thread
            .take()
            .ok_or("open holder missing")?
            .join()
            .map_err(|_| "open holder panicked")?
    }
}
impl Drop for HeldOpen {
    fn drop(&mut self) {
        // Fixed original end bounds this thread even when an assertion fails.
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn original_close(path: ReaderPath, writer: bool) -> Check {
    let budget = Budget::new();
    let gate = Arc::new(WireGate::new());
    let mut steps = vec![
        WireStep::Write(received("p", b"open original read")?),
        WireStep::Pause(gate.clone()),
    ];
    if !writer {
        steps.push(WireStep::HalfClose);
    }
    let mut peer = SourcedPeer::connect(path, config(), steps, budget).await?;
    let body = async {
        peer.captured().await?;
        peer.witness.release();
        let (_, fact) = peer.next().await?.into_parts();
        let fact = fact.ok_or("actual read source absent")?;
        require(
            fact.belongs_to_client(&peer.client),
            "fresh read identity changed",
        )?;
        require(
            peer.client.try_open_guard().is_ok(),
            "fresh client was closed",
        )?;
        budget.step("peer before native close", gate.wait()).await?;
        let held = HeldOpen::start(peer.client.close_signal.clone(), budget).await?;
        require(
            matches!(
                peer.client.try_open_guard(),
                Err(RelayClientOpenError::Contended)
            ),
            "open conflict did not reject",
        )?;
        let site = match (path, writer) {
            (ReaderPath::Address, false) => ClosePublisher::LegacyReader,
            (ReaderPath::Endpoint, false) => ClosePublisher::GeneralReader,
            (ReaderPath::Address, true) => ClosePublisher::LegacyWriter,
            (ReaderPath::Endpoint, true) => ClosePublisher::GeneralWriter,
        };
        if writer {
            // This is the real original writer's protocol-limit failure. It is
            // not a fabricated write helper or evidence of TCP partial write.
            let error = budget
                .step(
                    "real writer frame failure",
                    peer.client.send_data("p", &vec![0; 65_536]),
                )
                .await?;
            require(
                matches!(error, Err(crate::RelayError::FrameTooLarge(_, _))),
                "original writer failure changed",
            )?;
        } else {
            gate.release();
        }
        budget
            .step(
                "exact original publisher reached gate",
                peer.client.close_signal.wait_site(site, false),
            )
            .await?;
        require(
            !peer.client.close_signal.published_at(site),
            "close crossed held original guard",
        )?;
        held.release_and_join()?;
        budget
            .step(
                "exact original publisher completed",
                peer.client.close_signal.wait_site(site, true),
            )
            .await?;
        budget
            .step("published close releases original guard", async {
                loop {
                    // The published flag is visible before the publisher drops
                    // its original gate. Contention is not proof of Closed.
                    let open = peer.client.try_open_guard();
                    match open {
                        Err(RelayClientOpenError::Closed) => return Ok(()),
                        Err(RelayClientOpenError::Contended) => drop(open),
                        Ok(guard) => {
                            drop(guard);
                            return Err("published close became open".to_string());
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await??;
        require(
            fact.belongs_to_client(&peer.client),
            "close changed historical read identity",
        )?;
        Ok(())
    }
    .await;
    gate.release();
    peer.finish(body).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_original_reader_close_waits_for_open_guard() -> Check {
    original_close(ReaderPath::Address, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn general_original_reader_close_waits_for_open_guard() -> Check {
    original_close(ReaderPath::Endpoint, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_original_writer_failure_waits_for_open_guard() -> Check {
    original_close(ReaderPath::Address, true).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn general_original_writer_failure_waits_for_open_guard() -> Check {
    original_close(ReaderPath::Endpoint, true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_abort_and_drop_publish_original_close_without_receiver() -> Check {
    let budget = Budget::new();
    let mut peer = SourcedPeer::connect(ReaderPath::Endpoint, config(), Vec::new(), budget).await?;
    let body = async {
        let held = HeldOpen::start(peer.client.close_signal.clone(), budget).await?;
        let signal = peer.client.close_signal.clone();
        // Borrow the exact client in an owned scoped thread; never Clone the
        // RelayClient (whose Drop is itself a shared abort operation).
        std::thread::scope(|scope| {
            let close = scope.spawn(|| peer.client.abort());
            // The only async wait is outside the holder: this scope cannot
            // run async, so the test uses a bounded publisher flag observation.
            let end = budget.end.into_std();
            while !signal.attempted_at(ClosePublisher::Abort) {
                if Instant::now() >= end {
                    break;
                }
                std::thread::yield_now();
            }
            let before = signal.attempted_at(ClosePublisher::Abort)
                && !signal.published_at(ClosePublisher::Abort);
            let released = held.release_and_join();
            close.join().map_err(|_| "abort thread panicked")?;
            released?;
            require(before, "explicit abort crossed original open guard")
        })?;
        // Other original reader/writer publishers may still briefly hold the
        // same gate after abort has published. Contention is not Open or
        // Closed: observe the actual terminal result within the original end.
        let closed = budget
            .step("actual abort releases original gate", async {
                loop {
                    let open = peer.client.try_open_guard();
                    match open {
                        Err(RelayClientOpenError::Contended) => drop(open),
                        result => return result,
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await?;
        require(
            matches!(closed, Err(RelayClientOpenError::Closed)),
            "actual abort did not close",
        )?;
        let shell = RelayClient::new_for_test();
        let original = shell.close_signal.clone();
        require(shell.try_open_guard().is_ok(), "fresh shell not open")?;
        drop(shell);
        require(
            original.published_at(ClosePublisher::Abort),
            "Drop skipped original abort publisher",
        )?;
        require(
            matches!(original.try_open(), Err(RelayClientOpenError::Closed)),
            "receiver-free close was lost",
        )?;
        Ok(())
    }
    .await;
    peer.finish(body).await
}
