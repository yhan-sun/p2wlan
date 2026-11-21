// Synthetic AsyncWrite controls for each ORIGINAL private write helper.
// These exercise partial/short/error/close results, not a real socket writer,
// physical provenance, NIC delivery or remote ACK. No fact factory is called.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWrite;
use tokio::sync::watch;

#[derive(Clone, Copy)]
enum Failure {
    Zero,
    Error,
    Pending,
}

struct PartialWriter {
    accepted: Arc<AtomicUsize>,
    failure: Failure,
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.accepted.load(Ordering::Acquire) == 0 {
            let length = bytes.len().min(3);
            self.accepted.store(length, Ordering::Release);
            return Poll::Ready(Ok(length));
        }
        match self.failure {
            Failure::Zero => Poll::Ready(Ok(0)),
            Failure::Error => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic partial write error",
            ))),
            Failure::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn short_or_error(failure: Failure, expected: std::io::ErrorKind) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut writer = PartialWriter {
        accepted: accepted.clone(),
        failure,
    };
    let (close_tx, mut close_rx) = watch::channel(false);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        super::write_all_or_shutdown(&mut writer, b"exact full frame", &mut close_rx),
    )
    .await
    .unwrap();
    assert_eq!(accepted.load(Ordering::Acquire), 3);
    match result {
        Err(crate::RelayError::Io(error)) => assert_eq!(error.kind(), expected),
        other => panic!("partial synthetic helper must not return Ok: {other:?}"),
    }
    drop(close_tx);
}

#[tokio::test]
async fn b2_lib_original_helper_partial_then_short_is_not_full_ok() {
    short_or_error(Failure::Zero, std::io::ErrorKind::WriteZero).await;
}

#[tokio::test]
async fn b2_lib_original_helper_partial_then_error_is_not_full_ok() {
    short_or_error(Failure::Error, std::io::ErrorKind::BrokenPipe).await;
}

#[tokio::test]
async fn b2_lib_original_helper_partial_pending_then_close_is_uncertain() {
    use std::future::{poll_fn, Future};

    let accepted = Arc::new(AtomicUsize::new(0));
    let mut writer = PartialWriter {
        accepted: accepted.clone(),
        failure: Failure::Pending,
    };
    let (close_tx, mut close_rx) = watch::channel(false);
    let mut write = Box::pin(super::write_all_or_shutdown(
        &mut writer,
        b"exact full frame",
        &mut close_rx,
    ));
    tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|cx| match write.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(other) => panic!("partial helper must still be Pending: {other:?}"),
        }),
    )
    .await
    .unwrap();
    assert_eq!(accepted.load(Ordering::Acquire), 3);
    close_tx.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), write)
        .await
        .unwrap();
    assert!(matches!(result, Err(crate::RelayError::WriteUncertain(_))));
}
