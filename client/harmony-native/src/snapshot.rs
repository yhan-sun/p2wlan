use std::net::{Ipv4Addr, SocketAddr};

const MAX_SETTINGS_SNAPSHOT_BYTES: usize = 64 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanStringViewV1 {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanStringListV1 {
    pub items: *const P2wlanStringViewV1,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanVpnIdentityV1 {
    pub instance_id: P2wlanStringViewV1,
    pub generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanVpnSettingsV1 {
    pub control_server: P2wlanStringViewV1,
    pub auth_token: P2wlanStringViewV1,
    pub network_id: P2wlanStringViewV1,
    pub manual_mode: u8,
    pub virtual_ip: P2wlanStringViewV1,
    pub device_name: P2wlanStringViewV1,
    pub overlay_cidr: P2wlanStringViewV1,
    pub tun_interface: P2wlanStringViewV1,
    pub mtu: u32,
    pub udp_bind: P2wlanStringViewV1,
    pub udp_advertise: P2wlanStringViewV1,
    pub socket_pool: P2wlanStringViewV1,
    pub relay_servers: P2wlanStringListV1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanVpnSettingsSnapshotV1 {
    pub schema_version: u32,
    pub revision: u64,
    pub settings: P2wlanVpnSettingsV1,
}

/// Borrowed C ABI request passed by N-API. All pointers need only remain valid
/// for the synchronous prepare call; Rust copies validated strings before it
/// returns to JavaScript.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanVpnStartRequestV1 {
    pub version: u32,
    pub identity: P2wlanVpnIdentityV1,
    pub fd: i32,
    pub configured_routes: P2wlanStringListV1,
    pub process_protected: u8,
    pub identity_store_path: P2wlanStringViewV1,
    pub settings_snapshot: P2wlanVpnSettingsSnapshotV1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct P2wlanVpnNetworkRequestV1 {
    pub identity_store_path: P2wlanStringViewV1,
    pub settings_snapshot: P2wlanVpnSettingsSnapshotV1,
}

pub(crate) struct StartRequestV1 {
    pub identity: EngineIdentityV1,
    pub fd: i32,
    pub configured_routes: Vec<String>,
    pub identity_store_path: String,
    pub settings_snapshot: SettingsSnapshotV1,
}

pub(crate) struct VpnNetworkRequestV1 {
    pub identity_store_path: String,
    pub settings_snapshot: SettingsSnapshotV1,
}

pub(crate) struct EngineIdentityV1 {
    pub instance_id: String,
    pub generation: u64,
}

pub(crate) struct SettingsSnapshotV1 {
    pub schema_version: u32,
    pub revision: u64,
    pub settings: EngineSettingsV1,
}

pub(crate) struct EngineSettingsV1 {
    pub control_server: String,
    pub auth_token: String,
    pub network_id: String,
    pub manual_mode: bool,
    pub virtual_ip: String,
    pub device_name: String,
    pub overlay_cidr: String,
    pub tun_interface: String,
    pub mtu: u32,
    pub udp_bind: String,
    pub udp_advertise: Option<String>,
    pub socket_pool: String,
    pub relay_servers: Vec<String>,
}

#[cfg(target_env = "ohos")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct EngineKey {
    pub instance_id: String,
    pub generation: u64,
}

#[cfg(target_env = "ohos")]
impl EngineIdentityV1 {
    pub fn key(&self) -> EngineKey {
        EngineKey {
            instance_id: self.instance_id.clone(),
            generation: self.generation,
        }
    }
}

impl StartRequestV1 {
    /// # Safety
    /// Every non-empty view in `request` must point to readable UTF-8 data and
    /// array pointers must cover the stated number of views for this call.
    pub unsafe fn copy_from_ffi(
        request: *const P2wlanVpnStartRequestV1,
    ) -> Result<Self, &'static str> {
        if request.is_null() {
            return Err("invalid_request");
        }
        // SAFETY: the public function requires a valid request pointer.
        let request = unsafe { *request };
        let identity = EngineIdentityV1 {
            // SAFETY: forwarded from this function's documented pointer contract.
            instance_id: unsafe { copy_required_view(request.identity.instance_id, 1, 128)? },
            generation: request.identity.generation,
        };
        let configured_routes =
            // SAFETY: forwarded from this function's documented pointer contract.
            unsafe { copy_list(request.configured_routes, 256, 1, 128)? };
        let identity_store_path =
            // SAFETY: forwarded from this function's documented pointer contract.
            unsafe { copy_required_view(request.identity_store_path, 1, 4096)? };
        let copied = Self {
            identity,
            fd: request.fd,
            configured_routes,
            identity_store_path,
            // SAFETY: forwarded from this function's documented pointer contract.
            settings_snapshot: unsafe {
                SettingsSnapshotV1::copy_from_ffi(request.settings_snapshot)?
            },
        };
        copied.validate(request.version, request.process_protected)?;
        Ok(copied)
    }

    fn validate(&self, version: u32, process_protected: u8) -> Result<(), &'static str> {
        if version != 1
            || self.identity.instance_id.trim().is_empty()
            || self.identity.instance_id.as_bytes().contains(&0)
            || self.identity.generation == 0
            || self.fd < 0
            || process_protected != 1
            || self.configured_routes.is_empty()
            || self.settings_snapshot.schema_version != 1
            || self.settings_snapshot.revision == 0
        {
            return Err("invalid_request");
        }
        let settings = &self.settings_snapshot.settings;
        let mut total_bytes = self.identity.instance_id.len()
            + self.identity_store_path.len()
            + settings.control_server.len()
            + settings.auth_token.len()
            + settings.network_id.len()
            + settings.virtual_ip.len()
            + settings.device_name.len()
            + settings.overlay_cidr.len()
            + settings.tun_interface.len()
            + settings.udp_bind.len()
            + settings.socket_pool.len()
            + settings.udp_advertise.as_ref().map_or(0, String::len);
        total_bytes = total_bytes.saturating_add(
            self.configured_routes
                .iter()
                .map(String::len)
                .sum::<usize>(),
        );
        total_bytes = total_bytes.saturating_add(
            settings
                .relay_servers
                .iter()
                .map(String::len)
                .sum::<usize>(),
        );
        if total_bytes > MAX_SETTINGS_SNAPSHOT_BYTES {
            return Err("invalid_request");
        }
        validate_identity_path(&self.identity_store_path)?;
        for route in &self.configured_routes {
            validate_text(route, 1, 128)?;
        }

        validate_engine_settings(settings)?;
        Ok(())
    }
}

impl SettingsSnapshotV1 {
    /// # Safety
    /// Every settings view must point to readable UTF-8 data for this call.
    unsafe fn copy_from_ffi(source: P2wlanVpnSettingsSnapshotV1) -> Result<Self, &'static str> {
        let fields = source.settings;
        if fields.manual_mode > 1 || source.schema_version != 1 || source.revision == 0 {
            return Err("invalid_request");
        }
        let settings = EngineSettingsV1 {
            // SAFETY: forwarded from this function's documented pointer contract.
            control_server: unsafe { copy_required_view(fields.control_server, 1, 2048)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            auth_token: unsafe { copy_required_view(fields.auth_token, 0, 8192)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            network_id: unsafe { copy_required_view(fields.network_id, 1, 128)? },
            manual_mode: fields.manual_mode == 1,
            // SAFETY: forwarded from this function's documented pointer contract.
            virtual_ip: unsafe { copy_required_view(fields.virtual_ip, 0, 64)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            device_name: unsafe { copy_required_view(fields.device_name, 1, 128)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            overlay_cidr: unsafe { copy_required_view(fields.overlay_cidr, 1, 64)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            tun_interface: unsafe { copy_required_view(fields.tun_interface, 1, 15)? },
            mtu: fields.mtu,
            // SAFETY: forwarded from this function's documented pointer contract.
            udp_bind: unsafe { copy_required_view(fields.udp_bind, 1, 128)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            udp_advertise: unsafe { copy_view(fields.udp_advertise, 0, 128, true)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            socket_pool: unsafe { copy_required_view(fields.socket_pool, 1, 8)? },
            // SAFETY: forwarded from this function's documented pointer contract.
            relay_servers: unsafe { copy_list(fields.relay_servers, 64, 1, 2048)? },
        };
        validate_engine_settings(&settings)?;
        Ok(Self {
            schema_version: source.schema_version,
            revision: source.revision,
            settings,
        })
    }
}

impl VpnNetworkRequestV1 {
    /// # Safety
    /// The request and all nested string views must remain readable for this call.
    pub unsafe fn copy_from_ffi(
        request: *const P2wlanVpnNetworkRequestV1,
    ) -> Result<Self, &'static str> {
        if request.is_null() {
            return Err("invalid_request");
        }
        // SAFETY: the public function requires a valid request pointer.
        let request = unsafe { *request };
        let copied = Self {
            // SAFETY: forwarded from this function's documented pointer contract.
            identity_store_path: unsafe {
                copy_required_view(request.identity_store_path, 1, 4096)?
            },
            // SAFETY: forwarded from this function's documented pointer contract.
            settings_snapshot: unsafe {
                SettingsSnapshotV1::copy_from_ffi(request.settings_snapshot)?
            },
        };
        validate_identity_path(&copied.identity_store_path)?;
        let settings = &copied.settings_snapshot.settings;
        let total_bytes = settings.control_server.len()
            + settings.auth_token.len()
            + settings.network_id.len()
            + settings.virtual_ip.len()
            + settings.device_name.len()
            + settings.overlay_cidr.len()
            + settings.tun_interface.len()
            + settings.udp_bind.len()
            + settings.socket_pool.len()
            + settings.udp_advertise.as_ref().map_or(0, String::len)
            + settings
                .relay_servers
                .iter()
                .map(String::len)
                .sum::<usize>();
        if total_bytes > MAX_SETTINGS_SNAPSHOT_BYTES {
            return Err("invalid_request");
        }
        Ok(copied)
    }
}

fn validate_engine_settings(settings: &EngineSettingsV1) -> Result<(), &'static str> {
    validate_text(&settings.control_server, 1, 2048)?;
    validate_text(&settings.auth_token, 0, 8192)?;
    validate_text(&settings.network_id, 1, 128)?;
    validate_text(&settings.virtual_ip, 0, 64)?;
    validate_text(&settings.device_name, 1, 128)?;
    validate_text(&settings.overlay_cidr, 1, 64)?;
    validate_text(&settings.tun_interface, 1, 15)?;
    validate_text(&settings.udp_bind, 1, 128)?;
    if let Some(advertise) = &settings.udp_advertise {
        validate_text(advertise, 0, 128)?;
    }
    if settings.socket_pool_config().is_none()
        || settings
            .relay_servers
            .iter()
            .any(|server| server.is_empty())
    {
        return Err("invalid_request");
    }
    if !settings.manual_mode && settings.auth_token.trim().is_empty()
        || settings.manual_mode && !settings.auth_token.is_empty()
        || !(settings.control_server.starts_with("https://")
            || settings.control_server.starts_with("http://"))
        || settings
            .tun_interface
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
        || !(576..=9000).contains(&settings.mtu)
    {
        return Err("invalid_request");
    }
    settings
        .udp_bind
        .parse::<SocketAddr>()
        .map_err(|_| "invalid_request")?;
    if let Some(advertise) = settings
        .udp_advertise
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        advertise
            .parse::<SocketAddr>()
            .map_err(|_| "invalid_request")?;
    }
    let (network, prefix) = parse_ipv4_cidr(&settings.overlay_cidr)?;
    if settings.virtual_ip.is_empty() {
        if settings.manual_mode {
            return Err("invalid_request");
        }
    } else {
        let virtual_ip = settings
            .virtual_ip
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid_request")?;
        let mask = prefix_mask(prefix);
        if (u32::from(virtual_ip) & mask) != (u32::from(network) & mask) {
            return Err("invalid_request");
        }
    }
    Ok(())
}

impl EngineSettingsV1 {
    pub fn socket_pool_config(&self) -> Option<(bool, usize)> {
        match self.socket_pool.as_str() {
            "off" => Some((false, 3)),
            "2" => Some((true, 2)),
            "3" => Some((true, 3)),
            "4" => Some((true, 4)),
            _ => None,
        }
    }
}

unsafe fn copy_view(
    view: P2wlanStringViewV1,
    min_bytes: usize,
    max_bytes: usize,
    optional: bool,
) -> Result<Option<String>, &'static str> {
    if view.data.is_null() {
        return if optional && view.len == 0 {
            Ok(None)
        } else {
            Err("invalid_request")
        };
    }
    if view.len < min_bytes || view.len > max_bytes {
        return Err("invalid_request");
    }
    // SAFETY: the FFI request contract guarantees readable storage for `len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(view.data, view.len) };
    let value = std::str::from_utf8(bytes).map_err(|_| "invalid_request")?;
    if value.as_bytes().contains(&0) || (min_bytes > 0 && value.trim().is_empty()) {
        return Err("invalid_request");
    }
    Ok(Some(value.to_string()))
}

unsafe fn copy_required_view(
    view: P2wlanStringViewV1,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<String, &'static str> {
    // SAFETY: forwarded from this function's documented pointer contract.
    unsafe { copy_view(view, min_bytes, max_bytes, false)? }.ok_or("invalid_request")
}

unsafe fn copy_list(
    list: P2wlanStringListV1,
    max_count: usize,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<String>, &'static str> {
    if list.len > max_count || (list.len > 0 && list.items.is_null()) {
        return Err("invalid_request");
    }
    if list.len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: the FFI request contract guarantees `len` readable views.
    let views = unsafe { std::slice::from_raw_parts(list.items, list.len) };
    let mut values = Vec::with_capacity(list.len);
    for view in views {
        // SAFETY: each view is covered by the caller's FFI pointer contract.
        values.push(unsafe { copy_view(*view, min_bytes, max_bytes, false)? }.unwrap_or_default());
    }
    Ok(values)
}

fn validate_text(value: &str, min_bytes: usize, max_bytes: usize) -> Result<(), &'static str> {
    if value.len() < min_bytes || value.len() > max_bytes || value.as_bytes().contains(&0) {
        return Err("invalid_request");
    }
    if min_bytes > 0 && value.trim().is_empty() {
        return Err("invalid_request");
    }
    Ok(())
}

fn validate_identity_path(value: &str) -> Result<(), &'static str> {
    validate_text(value, 1, 4096)?;
    // This DTO describes an OHOS path even when host tests run on Windows.
    // Host Path semantics would reject valid Unix roots or accept drive paths.
    if !value.starts_with('/')
        || value.contains('\\')
        || value.rsplit('/').next() != Some("vpn-engine-identity-v1.bin")
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err("invalid_request");
    }
    Ok(())
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), &'static str> {
    let (address, prefix) = value.split_once('/').ok_or("invalid_request")?;
    let address = address.parse::<Ipv4Addr>().map_err(|_| "invalid_request")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "invalid_request")?;
    if prefix > 32 {
        return Err("invalid_request");
    }
    Ok((address, prefix))
}

pub(crate) fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(value: &str) -> P2wlanStringViewV1 {
        P2wlanStringViewV1 {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn request() -> StartRequestV1 {
        StartRequestV1 {
            identity: EngineIdentityV1 {
                instance_id: "vpn-instance".to_string(),
                generation: 3,
            },
            fd: 8,
            configured_routes: vec!["10.20.0.0/16".to_string()],
            identity_store_path: "/app/files/p2wlan/vpn-engine-identity-v1.bin".to_string(),
            settings_snapshot: SettingsSnapshotV1 {
                schema_version: 1,
                revision: 9,
                settings: EngineSettingsV1 {
                    control_server: "https://control.example.test".to_string(),
                    auth_token: "private-token".to_string(),
                    network_id: "network-a".to_string(),
                    manual_mode: false,
                    virtual_ip: "10.20.1.8".to_string(),
                    device_name: "Harmony device".to_string(),
                    overlay_cidr: "10.20.0.0/16".to_string(),
                    tun_interface: "p2wlan0".to_string(),
                    mtu: 1420,
                    udp_bind: "0.0.0.0:0".to_string(),
                    udp_advertise: None,
                    socket_pool: "3".to_string(),
                    relay_servers: Vec::new(),
                },
            },
        }
    }

    #[test]
    fn copies_the_versioned_ffi_request_before_the_borrow_ends() {
        let instance_id = "vpn-instance".to_string();
        let identity_store_path = "/app/files/p2wlan/vpn-engine-identity-v1.bin".to_string();
        let route = "10.20.0.0/16".to_string();
        let route_views = [view(&route)];
        let control_server = "https://control.example.test".to_string();
        let auth_token = "private-token".to_string();
        let network_id = "network-a".to_string();
        let virtual_ip = String::new();
        let device_name = "Harmony device".to_string();
        let overlay_cidr = "10.20.0.0/16".to_string();
        let tun_interface = "p2wlan0".to_string();
        let udp_bind = "0.0.0.0:0".to_string();
        let socket_pool = "4".to_string();
        let request = P2wlanVpnStartRequestV1 {
            version: 1,
            identity: P2wlanVpnIdentityV1 {
                instance_id: view(&instance_id),
                generation: 3,
            },
            fd: 8,
            configured_routes: P2wlanStringListV1 {
                items: route_views.as_ptr(),
                len: route_views.len(),
            },
            process_protected: 1,
            identity_store_path: view(&identity_store_path),
            settings_snapshot: P2wlanVpnSettingsSnapshotV1 {
                schema_version: 1,
                revision: 9,
                settings: P2wlanVpnSettingsV1 {
                    control_server: view(&control_server),
                    auth_token: view(&auth_token),
                    network_id: view(&network_id),
                    manual_mode: 0,
                    virtual_ip: view(&virtual_ip),
                    device_name: view(&device_name),
                    overlay_cidr: view(&overlay_cidr),
                    tun_interface: view(&tun_interface),
                    mtu: 1420,
                    udp_bind: view(&udp_bind),
                    udp_advertise: P2wlanStringViewV1 {
                        data: std::ptr::null(),
                        len: 0,
                    },
                    socket_pool: view(&socket_pool),
                    relay_servers: P2wlanStringListV1 {
                        items: std::ptr::null(),
                        len: 0,
                    },
                },
            },
        };

        // SAFETY: every nonempty view above points to a live string and the
        // route list covers its declared length for this synchronous copy.
        let copied = unsafe { StartRequestV1::copy_from_ffi(&request) }.unwrap();
        assert_eq!(copied.identity.instance_id, instance_id);
        assert_eq!(copied.settings_snapshot.revision, 9);
        assert_eq!(copied.configured_routes, vec![route]);
        assert_eq!(copied.settings_snapshot.settings.udp_advertise, None);
        assert_eq!(copied.settings_snapshot.settings.auth_token, auth_token);
        assert!(copied.settings_snapshot.settings.virtual_ip.is_empty());
        assert_eq!(copied.settings_snapshot.settings.socket_pool, "4");

        let mut network_request = P2wlanVpnNetworkRequestV1 {
            identity_store_path: request.identity_store_path,
            settings_snapshot: request.settings_snapshot,
        };
        // SAFETY: the same live views are copied synchronously for preflight.
        let network = unsafe { VpnNetworkRequestV1::copy_from_ffi(&network_request) }.unwrap();
        assert_eq!(network.identity_store_path, identity_store_path);
        assert_eq!(network.settings_snapshot.revision, 9);
        network_request.settings_snapshot.schema_version = 2;
        // SAFETY: invalid schema is data; the backing pointers remain valid.
        assert_eq!(
            unsafe { VpnNetworkRequestV1::copy_from_ffi(&network_request) }.err(),
            Some("invalid_request")
        );
    }

    #[test]
    fn accepts_valid_managed_snapshot() {
        assert!(request().validate(1, 1).is_ok());
    }

    #[test]
    fn identity_paths_use_ohos_syntax_on_every_host() {
        assert!(validate_identity_path("/app/files/p2wlan/vpn-engine-identity-v1.bin").is_ok());
        for invalid in [
            "app/files/vpn-engine-identity-v1.bin",
            "C:/app/files/vpn-engine-identity-v1.bin",
            "C:\\app\\files\\vpn-engine-identity-v1.bin",
            "/app/files/../vpn-engine-identity-v1.bin",
            "/app/files/./vpn-engine-identity-v1.bin",
            "/app/files\\p2wlan/vpn-engine-identity-v1.bin",
            "/app/files/identity.bin",
        ] {
            assert_eq!(validate_identity_path(invalid), Err("invalid_request"));
        }
    }

    #[test]
    fn accepts_empty_managed_virtual_ip_but_rejects_empty_manual_virtual_ip() {
        let mut managed = request();
        managed.settings_snapshot.settings.virtual_ip.clear();
        assert!(managed.validate(1, 1).is_ok());

        let mut manual = request();
        manual.settings_snapshot.settings.manual_mode = true;
        manual.settings_snapshot.settings.auth_token.clear();
        manual.settings_snapshot.settings.virtual_ip.clear();
        assert_eq!(manual.validate(1, 1), Err("invalid_request"));
    }

    #[test]
    fn rejects_unprotected_process_and_invalid_token_mode_pairs() {
        assert_eq!(request().validate(1, 0), Err("invalid_request"));
        let mut missing_token = request();
        missing_token.settings_snapshot.settings.auth_token.clear();
        assert_eq!(missing_token.validate(1, 1), Err("invalid_request"));

        let mut unexpected_manual_token = request();
        unexpected_manual_token
            .settings_snapshot
            .settings
            .manual_mode = true;
        assert_eq!(
            unexpected_manual_token.validate(1, 1),
            Err("invalid_request")
        );

        let mut valid_manual = request();
        valid_manual.settings_snapshot.settings.manual_mode = true;
        valid_manual.settings_snapshot.settings.auth_token.clear();
        assert!(valid_manual.validate(1, 1).is_ok());
    }

    #[test]
    fn rejects_invalid_identity_path_and_out_of_range_virtual_ip() {
        let mut wrong_path = request();
        wrong_path.identity_store_path = "/app/files/identity.bin".to_string();
        assert_eq!(wrong_path.validate(1, 1), Err("invalid_request"));

        let mut outside = request();
        outside.settings_snapshot.settings.virtual_ip = "10.21.1.8".to_string();
        assert_eq!(outside.validate(1, 1), Err("invalid_request"));
    }

    #[test]
    fn rejects_unknown_api_version_and_invalid_network_fields() {
        assert_eq!(request().validate(2, 1), Err("invalid_request"));
        let mut invalid_mtu = request();
        invalid_mtu.settings_snapshot.settings.mtu = 0;
        assert_eq!(invalid_mtu.validate(1, 1), Err("invalid_request"));

        let mut oversized = request();
        oversized.settings_snapshot.settings.relay_servers = vec!["r".repeat(2048); 64];
        assert_eq!(oversized.validate(1, 1), Err("invalid_request"));

        let mut invalid_socket_pool = request();
        invalid_socket_pool.settings_snapshot.settings.socket_pool = "5".to_string();
        assert_eq!(invalid_socket_pool.validate(1, 1), Err("invalid_request"));
    }

    #[test]
    fn maps_socket_pool_choices_to_daemon_settings() {
        for (value, expected) in [
            ("off", Some((false, 3))),
            ("2", Some((true, 2))),
            ("3", Some((true, 3))),
            ("4", Some((true, 4))),
            ("5", None),
        ] {
            let mut settings = request().settings_snapshot.settings;
            settings.socket_pool = value.to_string();
            assert_eq!(settings.socket_pool_config(), expected);
        }
    }
}
