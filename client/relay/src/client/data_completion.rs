//! Resolve the actual writer result before synchronous diagnostics.
//! Callers have already run their original Full observer; this helper cannot
//! construct physical provenance, retry, change clocks or invoke that factory.
use super::Result;
use tokio::sync::oneshot;

pub(super) struct Diagnostic {
    pub(super) failed: bool,
    pub(super) boundary_rejected: bool,
    pub(super) error: Option<String>,
}

pub(super) fn finish(
    completion: oneshot::Sender<Result<()>>,
    result: Result<()>,
    diagnostics: impl FnOnce(Diagnostic),
) -> (bool, bool) {
    let failed = result.is_err();
    let boundary_rejected = matches!(&result, Err(crate::RelayError::WriteBoundaryRejected));
    let error = failed.then(|| format!("{:?}", result.as_ref().err()));
    let _ = completion.send(result);
    diagnostics(Diagnostic {
        failed,
        boundary_rejected,
        error,
    });
    (failed, boundary_rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Result/oneshot controls only. No fake Full or write fact is created.
    #[test]
    fn actual_completion_is_observable_before_success_diagnostic_callback() {
        let (tx, mut rx) = oneshot::channel();
        let flags = finish(tx, Ok(()), |diagnostic| {
            assert!(matches!(rx.try_recv(), Ok(Ok(()))));
            assert!(
                !diagnostic.failed && !diagnostic.boundary_rejected && diagnostic.error.is_none()
            );
        });
        assert_eq!(flags, (false, false));
    }
    #[test]
    fn actual_completion_keeps_typed_error_and_dropped_receiver_diagnostics() {
        for rejected in [false, true] {
            let (tx, mut rx) = oneshot::channel();
            let error = if rejected {
                crate::RelayError::WriteBoundaryRejected
            } else {
                crate::RelayError::WriterStoppedBeforeWrite
            };
            let flags = finish(tx, Err(error), |diagnostic| {
                let observed = rx.try_recv().unwrap().unwrap_err();
                assert_eq!(
                    matches!(observed, crate::RelayError::WriteBoundaryRejected),
                    rejected
                );
                assert!(diagnostic.failed && diagnostic.error.is_some());
            });
            assert_eq!(flags, (true, rejected));
        }
        let (tx, rx) = oneshot::channel();
        drop(rx);
        let mut called = false;
        assert_eq!(finish(tx, Ok(()), |_| called = true), (false, false));
        assert!(called);
    }
}
