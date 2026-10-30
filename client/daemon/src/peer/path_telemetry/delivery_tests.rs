use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{PathTelemetryHub, PathTelemetrySender};
use crate::peer::{NetworkPath, PathEpochDiagnostics, PathObservabilitySnapshot};

async fn read_telemetry_request(stream: &mut tokio::net::TcpStream) -> serde_json::Value {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0, "request closed before headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        assert!(bytes.len() < 8192, "header exceeds fixture bound");
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_lowercase();
    assert!(headers.starts_with("post /api/v1/telemetry/paths "));
    assert!(headers.contains("authorization: bearer dc-delivery-test"));
    assert!(headers.contains("x-p2wlan-registration-seq: 42"));
    let length: usize = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length:")
                .map(|value| value.trim().parse().unwrap())
        })
        .unwrap();
    while bytes.len() < header_end + length {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0, "request closed before body");
        bytes.extend_from_slice(&chunk[..count]);
    }
    serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap()
}

fn delivery_snapshot(generation: u64, revision: u64) -> PathObservabilitySnapshot {
    PathObservabilitySnapshot {
        current_path: Some(NetworkPath::Direct),
        lifecycle: "online".into(),
        path_state_revision: revision,
        network_epoch: Some(PathEpochDiagnostics {
            network_generation: generation,
            peer_session_generation: 1,
            remote_candidate_epoch: 1,
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn path_telemetry_http_failure_preserves_latest_generation_for_fallback_retry() {
    let hub = Arc::new(PathTelemetryHub::new("reporter".into(), "network".into()));
    hub.set_registration_seq(42);
    hub.enqueue("remote", &delivery_snapshot(1, 10));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_hub = hub.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let body = read_telemetry_request(&mut stream).await;
        // The current peer advances while the original POST is in flight.
        server_hub.enqueue("remote", &delivery_snapshot(2, 1));
        // A different unchanged peer only has the failed POST as its dirty item.
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        body
    });
    hub.enqueue("unchanged", &delivery_snapshot(1, 2));
    let sender = PathTelemetrySender::new(
        hub.clone(),
        format!("http://{address}"),
        "dc-delivery-test".into(),
    );
    assert!(sender.flush_http().await.is_err());
    assert_eq!(
        server.await.unwrap()["observations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let retry_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let retry_address = retry_listener.local_addr().unwrap();
    let retried = tokio::spawn(async move {
        let (mut stream, _) = retry_listener.accept().await.unwrap();
        let body = read_telemetry_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
        body
    });
    let retry_sender = PathTelemetrySender::new(
        hub.clone(),
        format!("http://{retry_address}"),
        "dc-delivery-test".into(),
    );
    assert_eq!(
        retry_sender.flush_http().await.unwrap(),
        2,
        "transient HTTP failure lost the unchanged peer's only observation"
    );
    let body = retried.await.unwrap();
    let observations = body["observations"].as_array().unwrap();
    let remote = observations
        .iter()
        .find(|item| item["remote_device_id"] == "remote")
        .unwrap();
    assert_eq!(
        remote["network_generation"], 2,
        "retry restored an obsolete clone"
    );
    assert_eq!(remote["observation_revision"], 1);
    assert_eq!(hub.metrics().send_http_failures, 1);
    assert_eq!(hub.metrics().requeued_observations, 1);
    assert_eq!(hub.metrics().send_failures, 1);
}

#[tokio::test]
async fn path_telemetry_http_transport_failure_is_requeued_and_classified() {
    let hub = Arc::new(PathTelemetryHub::new("reporter".into(), "network".into()));
    hub.set_registration_seq(42);
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let sender = PathTelemetrySender::new(
        hub.clone(),
        format!("http://{address}"),
        "dc-delivery-test".into(),
    );
    assert!(sender.flush_http().await.is_err());
    assert!(hub.has_dirty());
    assert_eq!(hub.metrics().send_transport_failures, 1);
    assert_eq!(hub.metrics().send_timeouts, 0);
}

#[tokio::test]
async fn path_telemetry_http_timeout_is_requeued_and_classified() {
    let hub = Arc::new(PathTelemetryHub::new("reporter".into(), "network".into()));
    hub.set_registration_seq(42);
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_telemetry_request(&mut stream).await;
        std::future::pending::<()>().await;
    });
    let sender = PathTelemetrySender::new(
        hub.clone(),
        format!("http://{address}"),
        "dc-delivery-test".into(),
    );
    let result = sender.flush_http().await;
    server.abort();
    assert!(result.is_err());
    assert!(hub.has_dirty());
    assert_eq!(hub.metrics().send_timeouts, 1);
    assert_eq!(hub.metrics().send_transport_failures, 0);
}

#[test]
fn path_telemetry_retry_budget_is_bounded_and_new_samples_remain_deliverable() {
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    for _ in 0..super::hub::MAX_TELEMETRY_RETRIES {
        let batch = hub.drain_bounded_frame(32).unwrap();
        hub.retry_observations(&batch.payload.observations);
        assert!(hub.has_dirty());
    }
    let batch = hub.drain_bounded_frame(32).unwrap();
    hub.retry_observations(&batch.payload.observations);
    assert!(!hub.has_dirty());
    assert_eq!(hub.metrics().retry_exhausted_observations, 1);
    assert_eq!(
        hub.snapshot_all().len(),
        1,
        "latest state was discarded on retry exhaustion"
    );
    hub.enqueue("remote", &delivery_snapshot(2, 1));
    let batch = hub.drain_bounded_frame(32).unwrap();
    assert_eq!(batch.payload.observations[0].network_generation, 2);
    hub.retry_observations(&batch.payload.observations);
    assert!(hub.has_dirty());
}

#[test]
fn path_telemetry_ready_resync_preserves_retry_budget_and_last_queued_retry() {
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    for _ in 0..super::hub::MAX_TELEMETRY_RETRIES {
        let batch = hub.drain_bounded_frame(32).unwrap();
        hub.retry_observations(&batch.payload.observations);
        hub.mark_all_dirty();
    }
    // The third requeue is still entitled to its final delivery attempt.
    let final_attempt = hub.drain_bounded_frame(32).unwrap();
    hub.retry_observations(&final_attempt.payload.observations);
    assert_eq!(hub.metrics().retry_exhausted_observations, 1);
    for _ in 0..4 {
        hub.mark_all_dirty();
        assert!(hub.drain_bounded_frame(32).is_none());
    }
    assert_eq!(hub.snapshot_all().len(), 1);
    assert_eq!(hub.metrics().requeued_observations, 3);

    hub.enqueue("remote", &delivery_snapshot(2, 1));
    hub.mark_all_dirty();
    let fresh = hub.drain_bounded_frame(32).unwrap();
    assert_eq!(fresh.payload.observations[0].network_generation, 2);
    hub.retry_observations(&fresh.payload.observations);
    assert!(
        hub.has_dirty(),
        "a new authoritative sample gets a new budget"
    );
}

#[test]
fn path_telemetry_exhaustion_fences_a_resync_queued_during_delivery() {
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    for _ in 0..super::hub::MAX_TELEMETRY_RETRIES {
        let batch = hub.drain_bounded_frame(32).unwrap();
        hub.retry_observations(&batch.payload.observations);
    }
    let final_attempt = hub.drain_bounded_frame(32).unwrap();
    // The HTTP fallback can still be in flight when WebSocket becomes ready.
    hub.mark_all_dirty();
    hub.retry_observations(&final_attempt.payload.observations);
    assert_eq!(hub.metrics().retry_exhausted_observations, 1);
    assert!(hub.drain_bounded_frame(32).is_none());
    assert!(!hub.has_dirty());
}

#[test]
fn path_telemetry_old_completion_cannot_revive_an_exhausted_new_sample() {
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    let old = hub.drain_bounded_frame(32).unwrap();
    hub.enqueue("remote", &delivery_snapshot(2, 1));
    for _ in 0..=super::hub::MAX_TELEMETRY_RETRIES {
        let batch = hub.drain_bounded_frame(32).unwrap();
        hub.retry_observations(&batch.payload.observations);
    }
    assert!(!hub.has_dirty());
    hub.retry_observations(&old.payload.observations);
    assert!(
        !hub.has_dirty(),
        "old failure cannot requeue exhausted latest"
    );
    hub.record_delivery_success(&old.payload.observations);
    hub.mark_all_dirty();
    assert!(hub.drain_bounded_frame(32).is_none());
    assert_eq!(hub.metrics().retry_exhausted_observations, 1);
}

#[test]
fn path_telemetry_matching_success_restores_an_exhausted_sample_budget() {
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    hub.enqueue("remote", &delivery_snapshot(1, 1));
    let original = hub.snapshot_all();
    for _ in 0..=super::hub::MAX_TELEMETRY_RETRIES {
        let batch = hub.drain_bounded_frame(32).unwrap();
        hub.retry_observations(&batch.payload.observations);
    }
    // A matching in-flight transport may still succeed after another failed.
    hub.record_delivery_success(&original);
    hub.mark_all_dirty();
    for _ in 0..super::hub::MAX_TELEMETRY_RETRIES {
        let batch = hub.drain_bounded_frame(32).unwrap();
        hub.retry_observations(&batch.payload.observations);
    }
    let final_attempt = hub.drain_bounded_frame(32).unwrap();
    hub.retry_observations(&final_attempt.payload.observations);
    assert!(!hub.has_dirty());
    assert_eq!(hub.metrics().retry_exhausted_observations, 2);
}
