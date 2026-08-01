impl Daemon {
    fn local_identity(&self) -> Result<NodeIdentity> {
        let private_key = decode_x25519_key(&self.config.node.private_key, "node private key")?;
        Ok(NodeIdentity::from_private_key(private_key))
    }

}
