//! Actual local TLS endpoint/registration; no DNS64 or ticket-auth claim.
use super::*;
use crate::client::original_workers_for_test::Capture;
use std::any::Any;
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

type Check = std::result::Result<(), String>;

async fn caught<F: Future>(future: F) -> std::result::Result<F::Output, Box<dyn Any + Send>> {
    let mut future = Box::pin(future);
    poll_fn(
        |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(payload)),
        },
    )
    .await
}

async fn step<T>(
    work_end: tokio::time::Instant,
    label: &str,
    future: impl Future<Output = T>,
) -> std::result::Result<T, String> {
    tokio::time::timeout_at(
        work_end.min(tokio::time::Instant::now() + Duration::from_secs(2)),
        future,
    )
    .await
    .map_err(|_| format!("{label}: fixed prerequisite timeout"))
}

struct Certificates {
    directory: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}

impl Certificates {
    fn create() -> std::result::Result<Self, String> {
        let directory = std::env::temp_dir().join(format!(
            "p2wlan-ipv6-endpoint-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let owned = Self {
            certificate: directory.join("certificate.pem"),
            key: directory.join("key.pem"),
            directory,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&owned.directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let certified = rcgen::generate_simple_self_signed(vec!["::1".to_string()])
            .map_err(|error| error.to_string())?;
        for (path, bytes) in [
            (&owned.certificate, certified.cert.pem()),
            (&owned.key, certified.key_pair.serialize_pem()),
        ] {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|error| error.to_string())?;
            file.write_all(bytes.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        Ok(owned)
    }
}

impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Default)]
struct Owners {
    server: Option<RelayServer>,
    client: Option<RelayClient>,
    capture: Arc<Capture>,
    bare: Option<JoinHandle<Check>>,
    bare_joined: bool,
    native_captured: usize,
    native_joined: usize,
    certificates: Option<Certificates>,
    ports: Vec<std::net::SocketAddr>,
}

impl Owners {
    async fn close(&mut self, end: tokio::time::Instant) -> Check {
        if let Some(client) = &self.client {
            client.abort();
        }
        let mut native = self.capture.retire();
        let expected_native = native.count();
        self.native_captured = expected_native;
        let native_joined = native.close_and_join(end).await;
        let mut errors = Vec::new();
        if let Err(error) = &native_joined {
            errors.push(error.clone());
        }
        if let Ok(joined) = native_joined.as_ref() {
            self.native_joined = *joined;
        }
        self.client.take();
        if let Some(handle) = self.bare.as_mut() {
            handle.abort();
            match tokio::time::timeout_at(end, handle).await {
                Ok(result) => {
                    self.bare.take();
                    self.bare_joined = true;
                    match result {
                        Ok(Ok(())) => {}
                        Err(error) if error.is_cancelled() => {}
                        other => errors.push(format!("bare IPv6 control owner failed: {other:?}")),
                    }
                }
                Err(_) => errors.push("bare IPv6 control join exceeded original end".into()),
            }
        }
        let mut server_joined = false;
        if let Some(server) = self.server.as_mut() {
            let _ = server.shutdown_tx.send(());
            match tokio::time::timeout_at(end, &mut server.handle).await {
                Ok(result) => {
                    self.server.take();
                    server_joined = true;
                    if let Err(error) = result {
                        errors.push(format!("original Relay server owner failed: {error}"));
                    }
                }
                Err(_) => errors.push("original Relay server join exceeded original end".into()),
            }
        }
        let mut rebound = 0;
        for addr in &self.ports {
            match tokio::time::timeout_at(end, tokio::net::TcpListener::bind(addr)).await {
                Ok(Ok(listener)) => {
                    drop(listener);
                    rebound += 1;
                }
                other => errors.push(format!("actual IPv6 port did not rebind: {other:?}")),
            }
        }
        if let Some(certificates) = &self.certificates {
            if let Err(error) = std::fs::remove_dir_all(&certificates.directory) {
                errors.push(format!("owned certificate cleanup failed: {error}"));
            }
        }
        self.certificates.take();
        if errors.is_empty() {
            eprintln!("x02_ipv6_endpoint_owned_cleanup native_joined={}/{expected_native} server_joined={server_joined} bare_joined={} ports_rebound={rebound} original_end_unchanged=true",
                native_joined.unwrap(), self.bare_joined);
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        if let Some(client) = &self.client {
            client.abort();
        }
        if let Some(handle) = &self.bare {
            handle.abort();
        }
        if let Some(server) = &self.server {
            let _ = server.shutdown_tx.send(());
            server.handle.abort();
        }
        // Capture/Retired Drop only aborts; arbitrary parent Drop is not joined.
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_tls_endpoint_uses_literal_host_and_registers_with_default_server_name() -> Check {
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    let work_end = end - Duration::from_secs(1);
    let mut owners = Owners::default();
    let mut bare_connected = false;
    let mut endpoint_registered = false;
    let mut endpoint_failure = None;
    let body = caught(tokio::time::timeout_at(work_end, async {
        owners.certificates = Some(Certificates::create()?);
        let certificates = owners.certificates.as_ref().unwrap();
        let config = RelayServerConfig {
            tls_cert_chain_path: Some(certificates.certificate.clone()),
            tls_private_key_path: Some(certificates.key.clone()),
            require_authentication: false,
            allow_legacy_unauthenticated: true,
            ..RelayServerConfig::default()
        };
        let server = step(
            work_end,
            "actual IPv6 TLS listener",
            RelayServer::start_with_config("[::1]:0", config),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let addr = server.addr;
        owners.server = Some(server); // original handle captured before next await
        owners.ports.push(addr);
        if !addr.is_ipv6() || !addr.ip().is_loopback() {
            return Err("TLS listener is not actual ::1".into());
        }
        let listener = step(
            work_end,
            "bare IPv6 control listener",
            tokio::net::TcpListener::bind("[::1]:0"),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let bare_addr = listener.local_addr().map_err(|error| error.to_string())?;
        owners.ports.push(bare_addr);
        owners.bare = Some(tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.map_err(|error| error.to_string())?;
            if !peer.is_ipv6()
                || !stream
                    .local_addr()
                    .map_err(|error| error.to_string())?
                    .is_ipv6()
            {
                return Err("control accepted the wrong real address family".into());
            }
            stream
                .write_all(b"ipv6-control")
                .await
                .map_err(|error| error.to_string())?;
            Ok(())
        }));
        let mut control = step(
            work_end,
            "original bare IPv6 netbind",
            p2pnet_netbind::connect_tcp_host("::1", bare_addr.port(), None),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let mut message = [0u8; 12];
        step(
            work_end,
            "actual bare IPv6 control bytes",
            control.read_exact(&mut message),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if message != *b"ipv6-control" {
            return Err("real IPv6 control bytes mismatched".into());
        }
        drop(control);
        let joined = step(
            work_end,
            "join actual bare IPv6 owner",
            owners.bare.as_mut().unwrap(),
        )
        .await?;
        owners.bare.take();
        joined.map_err(|error| error.to_string())??;
        owners.bare_joined = true;
        bare_connected = true;
        let client_config = RelayClientConfig {
            tls_ca_cert_path: Some(owners.certificates.as_ref().unwrap().certificate.clone()),
            original_workers_for_test: Some(owners.capture.clone()),
            ..RelayClientConfig::default()
        };
        // No name override, plaintext permission, certificate bypass or budget override.
        let outcome = step(
            work_end,
            "original IPv6 endpoint TLS/registration",
            RelayClient::connect_with_endpoint(
                &format!("tls://{addr}"),
                "ipv6-endpoint-node",
                client_config,
            ),
        )
        .await?;
        match outcome {
            Ok((client, _rx)) => {
                owners.client = Some(client); // originals already captured before registration await
                endpoint_registered = true;
            }
            Err(error @ (crate::RelayError::ConnectFailed(_) | crate::RelayError::TlsError(_))) => {
                endpoint_failure = Some(format!("{error:?}"));
            }
            Err(error) => {
                return Err(format!(
                    "non-designated endpoint prerequisite failed: {error:?}"
                ))
            }
        }
        Ok(())
    }))
    .await;
    let cleanup = owners.close(end).await;
    match body {
        Err(payload) => {
            if let Err(error) = cleanup {
                eprintln!("x02 original panic cleanup failed: {error}");
            }
            resume_unwind(payload)
        }
        Ok(result) => {
            cleanup?;
            result.map_err(|_| "original fixture body deadline expired; not accepted RED")??;
        }
    }
    assert!(
        bare_connected,
        "IPv6 endpoint test did not reach original bare ::1 prerequisite"
    );
    assert!(endpoint_registered,
        "x02 actual IPv6 TLS endpoint must connect and register using its default IP server name; original_error={endpoint_failure:?}");
    assert_eq!(
        (owners.native_captured, owners.native_joined),
        (2, 2),
        "registered endpoint did not retain and join both original workers"
    );
    Ok(())
}
