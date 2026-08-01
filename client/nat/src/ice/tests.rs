use super::*;
use crate::stun::{StunAttribute, StunMessage, BINDING_REQUEST, BINDING_RESPONSE};

#[derive(Debug, Clone, Copy)]
enum ChangeResponseMode {
    ChangedPortForIpPort,
    ChangedPortForPortOnly,
}

async fn spawn_change_request_stun_server(
    mode: ChangeResponseMode,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let alternate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = primary.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, client_addr)) = primary.recv_from(&mut buf).await {
            let Ok(req) = StunMessage::decode(&buf[..len]) else {
                continue;
            };
            if req.msg_type != BINDING_REQUEST {
                continue;
            }

            let (change_ip, change_port) = change_request_flags(&req);
            let should_drop = matches!(
                (mode, change_ip, change_port),
                (ChangeResponseMode::ChangedPortForPortOnly, true, true)
            );
            if should_drop {
                continue;
            }

            let from_alternate = matches!(
                (mode, change_ip, change_port),
                (ChangeResponseMode::ChangedPortForIpPort, true, true)
                    | (ChangeResponseMode::ChangedPortForPortOnly, false, true)
            );
            let mut resp = StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
            resp.add_attribute(StunAttribute::XorMappedAddress(client_addr));
            let encoded = resp.encode();
            if from_alternate {
                let _ = alternate.send_to(&encoded, client_addr).await;
            } else {
                let _ = primary.send_to(&encoded, client_addr).await;
            }
        }
    });

    (addr, handle)
}

fn change_request_flags(message: &StunMessage) -> (bool, bool) {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            StunAttribute::ChangeRequest {
                change_ip,
                change_port,
            } => Some((*change_ip, *change_port)),
            _ => None,
        })
        .unwrap_or((false, false))
}

include!("tests/interfaces.rs");
include!("tests/profile.rs");
include!("tests/probes.rs");
include!("tests/gather.rs");
