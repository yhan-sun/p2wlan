from pathlib import Path

path = Path("client/daemon/src/transport/tests.rs")
text = path.read_text(encoding="utf-8")
old = """        let connection = peers.get_connection(\"peer-a\").await.unwrap();
        assert_eq!(connection.state, ConnectionState::Idle);
        assert_eq!(connection.relay_server, None);
"""
new = """        let connection = peers.get_connection(\"peer-a\").await.unwrap();
        assert_eq!(connection.state, ConnectionState::Idle);
        assert_eq!(
            connection.relay_server.as_deref(),
            Some(\"tls://relay.test:443\"),
            \"decrypted Relay ingress is retained as health metadata\"
        );
        assert_eq!(
            connection.relay_confirmed_generation, None,
            \"an internal rekey confirmation must not confirm Relay delivery\"
        );
        assert_eq!(
            connection.active_path(), None,
            \"Relay observation metadata must not activate the Relay path\"
        );
"""
if text.count(old) != 1:
    raise SystemExit(
        f"relay observation assertion: expected exactly one match, found {text.count(old)}"
    )
path.write_text(text.replace(old, new, 1), encoding="utf-8")
