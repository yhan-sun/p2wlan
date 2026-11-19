use super::{Config, DaemonInstanceLock, IdentityProtection};
use std::fs;
use std::path::PathBuf;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "p2wlan-identity-protection-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn write_key(path: &std::path::Path, value: u8) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    writeln!(file, "{}", hex::encode([value; 32])).unwrap();
}

#[cfg(unix)]
#[test]
fn key_file_round_trip_rewrap_and_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let root = TestDirectory::new();
    let profile = root.0.join("config.json");
    let key = root.0.join("wrapping.key");
    let replacement = root.0.join("replacement.key");
    write_key(&key, 31);
    write_key(&replacement, 77);

    let original = Config::generate_default("https://example.test", "default").unwrap();
    original.save_to_file(&profile).unwrap();
    assert!(!Config::load_from_file(&profile)
        .unwrap()
        .identity_is_protected());
    let source = IdentityProtection::KeyFile { path: key.clone() };
    let lock = DaemonInstanceLock::acquire(&profile).unwrap();
    let initial = fs::read(&profile).unwrap();
    assert!(Config::protect_identity_file(&profile, source.clone()).is_err());
    assert_eq!(fs::read(&profile).unwrap(), initial);
    drop(lock);
    Config::protect_identity_file(&profile, source).unwrap();

    let stored = fs::read_to_string(&profile).unwrap();
    assert!(!stored.contains(&original.node.private_key));
    assert!(!stored.contains(&original.node.ed25519_private_key));
    assert!(original.save_to_file(&profile).is_err());
    assert_eq!(fs::read_to_string(&profile).unwrap(), stored);
    let mut restored = Config::load_from_file(&profile).unwrap();
    assert!(restored.identity_is_protected());
    assert_eq!(restored.node.private_key, original.node.private_key);
    assert_eq!(
        restored.node.ed25519_private_key,
        original.node.ed25519_private_key
    );
    restored.node.device_name = "updated device".into();
    restored.save_to_file(&profile).unwrap();
    assert_eq!(
        Config::load_from_file(&profile).unwrap().node.device_name,
        "updated device"
    );

    write_key(&key, 99);
    let before_failed_rotation = fs::read(&profile).unwrap();
    let new_source = IdentityProtection::KeyFile {
        path: replacement.clone(),
    };
    assert!(Config::load_from_file(&profile).is_err());
    assert!(Config::protect_identity_file(&profile, new_source.clone()).is_err());
    assert_eq!(fs::read(&profile).unwrap(), before_failed_rotation);
    write_key(&key, 31);
    Config::protect_identity_file(&profile, new_source).unwrap();
    let rewrapped = fs::read(&profile).unwrap();
    assert!(restored.save_to_file(&profile).is_err());
    assert_eq!(fs::read(&profile).unwrap(), rewrapped);
    fs::remove_file(key).unwrap();
    assert_eq!(
        Config::load_from_file(&profile).unwrap().node.private_key,
        original.node.private_key
    );
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Config::load_from_file(&profile).is_err());
}

#[cfg(unix)]
#[test]
fn protected_profile_rejects_public_key_changes_and_missing_backend() {
    let root = TestDirectory::new();
    let profile = root.0.join("config.json");
    let key = root.0.join("wrapping.key");
    write_key(&key, 28);
    Config::generate_default("https://example.test", "default")
        .unwrap()
        .save_to_file(&profile)
        .unwrap();
    Config::protect_identity_file(&profile, IdentityProtection::KeyFile { path: key }).unwrap();
    let stored = fs::read(&profile).unwrap();
    let mut modified: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    modified["node"]["public_key"] = hex::encode([1; 32]).into();
    fs::write(&profile, serde_json::to_vec(&modified).unwrap()).unwrap();
    assert!(Config::load_from_file(&profile).is_err());
    let mut modified: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    modified
        .as_object_mut()
        .unwrap()
        .remove("identity_protection");
    fs::write(&profile, serde_json::to_vec(&modified).unwrap()).unwrap();
    assert!(Config::load_from_file(&profile).is_err());
}

#[cfg(windows)]
#[test]
fn windows_dpapi_round_trips_profile_for_current_user() {
    let root = TestDirectory::new();
    let profile = root.0.join("config.json");
    let original = Config::generate_default("https://example.test", "default").unwrap();
    original.save_to_file(&profile).unwrap();
    Config::protect_identity_file(&profile, IdentityProtection::WindowsDpapi).unwrap();
    let stored = fs::read_to_string(&profile).unwrap();
    assert!(!stored.contains(&original.node.private_key));
    assert!(!stored.contains(&original.node.ed25519_private_key));
    let restored = Config::load_from_file(&profile).unwrap();
    assert_eq!(restored.node.public_key, original.node.public_key);
    assert_eq!(restored.node.private_key, original.node.private_key);
    assert_eq!(
        restored.node.ed25519_private_key,
        original.node.ed25519_private_key
    );
}
