use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p2pnet_crypto::Ed25519KeyPair;
use p2pnet_relay::{RelayClient, RelayClientConfig, RelayMessage, RelayServer, RelayServerConfig};
use std::io::Write;
use tempfile::NamedTempFile;

pub(super) struct TlsRelayPair {
    pub(super) endpoint: String,
    nodes: [&'static str; 2],
    clients: [RelayClient; 2],
    inboxes: [mpsc::Receiver<RelayMessage>; 2],
    server: RelayServer,
}

impl TlsRelayPair {
    pub(super) async fn connect(nodes: [&'static str; 2]) -> Self {
        let local = LocalTlsRelay::start().await;
        let endpoint = local.endpoint();
        let connect = |node: &'static str| {
            RelayClient::connect_with_endpoint(
                &endpoint,
                node,
                RelayClientConfig {
                    tls_ca_cert_path: Some(local.cert.path().to_owned()),
                    relay_ticket: Some(local.ticket(node)),
                    ..Default::default()
                },
            )
        };
        let [(a, ra), (b, rb)] = [
            connect(nodes[0]).await.unwrap(),
            connect(nodes[1]).await.unwrap(),
        ];
        Self {
            endpoint,
            nodes,
            clients: [a, b],
            inboxes: [ra, rb],
            server: local.server,
        }
    }

    pub(super) async fn exchange(
        &mut self,
        wg: &mut [TransportSession; 2],
        sequence: u16,
        payload: &[u8],
    ) {
        let addresses = [Ipv4Addr::new(10, 20, 0, 1), Ipv4Addr::new(10, 20, 0, 2)];
        for i in 0..2 {
            let j = 1 - i;
            let packet = Ipv4Packet::build_icmp_echo_request(
                addresses[i],
                addresses[j],
                i as u16,
                sequence,
                payload,
            );
            self.clients[i]
                .send_data(self.nodes[j], &wg[i].encrypt_to_bytes(&packet).unwrap())
                .await
                .unwrap();
            let (from_node, data) = timeout(Duration::from_secs(2), async {
                loop {
                    match self.inboxes[j]
                        .recv()
                        .await
                        .expect("registered relay connection")
                    {
                        RelayMessage::Data { from_node, data } => break (from_node, data),
                        RelayMessage::Pong { .. } => continue,
                        other => panic!("unexpected relay message during data transfer: {other:?}"),
                    }
                }
            })
            .await
            .expect("next numbered relay business frame");
            assert_eq!(from_node, self.nodes[i]);
            assert_eq!(wg[j].decrypt_from_bytes(&data).unwrap(), packet);
        }
    }

    pub(super) async fn shutdown(self) {
        for client in &self.clients {
            client.abort();
        }
        self.server.shutdown().await;
    }
}

pub(super) struct LocalTlsRelay {
    pub(super) server: RelayServer,
    pub(super) cert: NamedTempFile,
    issuer: Ed25519KeyPair,
}

impl LocalTlsRelay {
    pub(super) async fn start() -> Self {
        let tls = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let mut cert = NamedTempFile::new().unwrap();
        let mut key = NamedTempFile::new().unwrap();
        cert.write_all(tls.cert.pem().as_bytes()).unwrap();
        key.write_all(tls.signing_key.serialize_pem().as_bytes())
            .unwrap();
        let issuer = Ed25519KeyPair::generate();
        let server = RelayServer::start_with_config(
            "127.0.0.1:0",
            RelayServerConfig {
                require_authentication: true,
                allow_legacy_unauthenticated: false,
                tls_cert_chain_path: Some(cert.path().to_owned()),
                tls_private_key_path: Some(key.path().to_owned()),
                ticket_keyring_json: Some(
                    serde_json::json!({"matrix": hex::encode(issuer.public_key())}).to_string(),
                ),
                ticket_audience: Some("matrix-relay".into()),
                ticket_region: Some("local".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        Self {
            server,
            cert,
            issuer,
        }
    }

    pub(super) fn endpoint(&self) -> String {
        format!("tls://{}", self.server.addr)
    }

    pub(super) fn ticket(&self, node: &str) -> String {
        let now = crate::gateway_mapping::now_ms() / 1000;
        let header = serde_json::json!({"alg":"EdDSA","kid":"matrix","typ":"p2wlan-relay+jwt"});
        let claims = serde_json::json!({"iss":"p2wlan-control","aud":"matrix-relay","sub":node,
            "device_id":node,"node_id":node,"network_id":"matrix-room","relay_region":"local",
            "relay_protocol":p2pnet_relay::RELAY_PROTOCOL_VERSION,"iat":now,"nbf":now,"exp":now+300});
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(self.issuer.sign(signed.as_bytes()))
        )
    }
}
