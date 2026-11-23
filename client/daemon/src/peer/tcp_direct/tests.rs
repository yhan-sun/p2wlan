use super::*;
use tokio::net::{TcpListener, TcpStream};

async fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a, b) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (a.unwrap(), b.unwrap().0)
}

#[tokio::test]
async fn mutual_proofs_reject_wrong_keys_and_reflected_roles() {
    for (remote_key, role, accepted) in [
        ([2; 32], false, false),
        ([1; 32], true, false),
        ([1; 32], false, true),
    ] {
        let (mut a, mut b) = sockets().await;
        let (client, server) = tokio::join!(
            wire::authenticate(&mut a, [1; 32], true),
            wire::authenticate(&mut b, remote_key, role),
        );
        assert_eq!(client.is_ok(), accepted);
        assert_eq!(server.is_ok(), accepted);
        if accepted {
            let key = client.unwrap();
            assert_eq!(key, server.unwrap());
            assert_ne!(key, [1; 32]);
            let nonce = [7; 32];
            assert_ne!(
                wire::heartbeat(&key, wire::PING, true, &nonce),
                wire::heartbeat(&key, wire::PONG, false, &nonce)
            );
        }
    }
}

#[test]
fn stream_frames_require_bounded_wireguard_transport_messages() {
    assert!(wire::data_record(&[0; 32]).is_none());
    assert!(wire::data_record(&[4; 16]).is_none());
    let mut wire = vec![0; 65_535];
    wire[0] = 4;
    let frame = wire::data_record(&wire).unwrap();
    assert_eq!(&frame[..2], &[255; 2]);
    assert_eq!(&frame[2..], wire);
    wire.push(0);
    assert!(super::wire::data_record(&wire).is_none());
}

#[tokio::test]
async fn simultaneous_decisions_bind_connection_role_stage_and_peer_vote() {
    for (other_key, other_role, other_stage, accepted) in [
        ([1; 32], false, 1, true),
        ([2; 32], false, 1, false),
        ([1; 32], true, 1, false),
        ([1; 32], false, 2, false),
    ] {
        let (mut a, mut b) = sockets().await;
        let (local, remote) = tokio::join!(
            simultaneous::exchange_decision(&mut a, &[1; 32], true, 1, true),
            simultaneous::exchange_decision(&mut b, &other_key, other_role, other_stage, false)
        );
        if accepted {
            assert!(!local.unwrap());
            assert!(remote.unwrap());
        } else {
            assert_eq!(local.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert_eq!(remote.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }
}
