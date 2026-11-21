//! Fixed external slots for the actual endpoint client's original workers.
//! There is no replacement task, reader, client registry or production join.
use super::close::{ClosePublisher, RelayCloseSignal};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

#[derive(Debug, Default)]
pub(crate) struct Capture {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    handles: [Option<JoinHandle<()>>; 2],
    close: Option<Arc<RelayCloseSignal>>,
}

impl Capture {
    /// Called synchronously after each original spawn and before reg_rx await.
    pub(super) fn install(
        &self,
        index: usize,
        handle: JoinHandle<()>,
        close: Arc<RelayCloseSignal>,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            state.handles[index].is_none(),
            "original endpoint worker slot reused"
        );
        state.handles[index] = Some(handle);
        state.close = Some(close);
    }

    /// Move the same handles once, without holding a mutex across their joins.
    pub(crate) fn retire(&self) -> Retired {
        let state =
            std::mem::take(&mut *self.state.lock().unwrap_or_else(|error| error.into_inner()));
        Retired { state }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        stop_and_abort(state);
    }
}

pub(crate) struct Retired {
    state: State,
}

impl Retired {
    pub(crate) fn count(&self) -> usize {
        self.state
            .handles
            .iter()
            .filter(|handle| handle.is_some())
            .count()
    }

    pub(crate) async fn close_and_join(
        &mut self,
        end: tokio::time::Instant,
    ) -> std::result::Result<usize, String> {
        if let Some(close) = &self.state.close {
            close.publish_closed(ClosePublisher::Abort);
        }
        let mut joined = 0;
        let mut errors = Vec::new();
        for (index, slot) in self.state.handles.iter_mut().enumerate() {
            let Some(handle) = slot.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(end, handle).await {
                Ok(result) => {
                    slot.take();
                    joined += 1;
                    if let Err(error) = result {
                        errors.push(format!("original endpoint worker {index}: {error}"));
                    }
                }
                Err(_) => errors.push(format!(
                    "original endpoint worker {index}: original end expired"
                )),
            }
        }
        if errors.is_empty() {
            Ok(joined)
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Retired {
    fn drop(&mut self) {
        stop_and_abort(&mut self.state);
    }
}

fn stop_and_abort(state: &mut State) {
    if let Some(close) = &state.close {
        close.publish_closed(ClosePublisher::Abort);
    }
    for handle in state.handles.iter().flatten() {
        handle.abort();
    }
}
