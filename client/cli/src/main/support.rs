use flate2::{write::GzEncoder, Compression};
use std::io::{Seek, SeekFrom};

const SUPPORT_LOG_SCHEMA_VERSION: u32 = 2;
const MAX_SUPPORT_ROOM_INSTANCES: usize = 8;
const DEFAULT_SUPPORT_LOG_BYTES: u64 = 1024 * 1024;
const MAX_SUPPORT_LOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SUPPORT_EXPANDED_BYTES: usize = 32 * 1024 * 1024;
const MAX_SUPPORT_COMPRESSED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Args, Debug)]
struct SupportBundleArgs {
    /// Write the gzip-compressed JSON bundle to this path
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Upload the same bundle to the configured control server
    #[arg(long)]
    upload: bool,
    /// Include local room profiles and their daemon logs (enabled by default)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    include_rooms: bool,
    /// Maximum tail size per daemon log
    #[arg(long, default_value_t = DEFAULT_SUPPORT_LOG_BYTES)]
    max_log_bytes: u64,
    /// Print bundle metadata as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug)]
struct SupportLogTail {
    content: String,
    truncated: bool,
}

async fn support_bundle(config_path: &Path, args: SupportBundleArgs) -> Result<(), String> {
    let mut config = load_config(config_path)?;
    if args.upload {
        hydrate_cli_session_token(config_path, &mut config)?;
        require_control_auth(&config)?;
    }
    if args.max_log_bytes == 0 || args.max_log_bytes > MAX_SUPPORT_LOG_BYTES {
        return Err(format!(
            "max-log-bytes 必须在 1 到 {} 之间",
            MAX_SUPPORT_LOG_BYTES
        ));
    }

    let output = args.output.unwrap_or_else(|| {
        state_dir().join(format!(
            "p2wlan-support-{}.json.gz",
            support_unix_timestamp()
        ))
    });
    let main_state = state_dir();
    let mut instances = Vec::with_capacity(1 + MAX_SUPPORT_ROOM_INSTANCES);
    let main_status = fetch_status_at(&status_url(&config), &main_state)
        .await
        .ok();
    let main_log = read_support_log(&main_state.join("p2wlan-daemon.log"), args.max_log_bytes);
    let main_summary = support_status_summary(&config, main_status.as_ref());
    let daemon_version = main_status
        .as_ref()
        .and_then(|value| value.get("version"))
        .and_then(Value::as_str)
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .to_string();
    instances.push(serde_json::json!({
        "instance_type": "main",
        "network_id": config.network.network_id,
        "build": {"version": daemon_version},
        "started_at": support_unix_timestamp(),
        "truncated": main_log.truncated,
        "status_summary": main_summary,
        "log": main_log.content,
    }));

    let mut omitted_room_instances = 0usize;
    if args.include_rooms {
        let room_root = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("rooms");
        let mut room_profiles = discover_room_profiles(&room_root);
        room_profiles.sort();
        for (index, (profile, room_path)) in room_profiles.into_iter().enumerate() {
            if index >= MAX_SUPPORT_ROOM_INSTANCES {
                omitted_room_instances += 1;
                continue;
            }
            let room_config = match Config::load_from_file(&room_path) {
                Ok(value) => value,
                Err(error) => {
                    instances.push(serde_json::json!({
                        "instance_type": "room",
                        "profile_id": profile,
                        "build": {"version": env!("CARGO_PKG_VERSION")},
                        "truncated": false,
                        "status_summary": redact_support_text(&format!(
                            "room config could not be loaded: {error}"
                        )),
                        "log": "",
                    }));
                    continue;
                }
            };
            let room_state = main_state.join("rooms").join(&profile);
            let room_status = fetch_status_at(&status_url(&room_config), &room_state)
                .await
                .ok();
            let room_log =
                read_support_log(&room_state.join("p2wlan-daemon.log"), args.max_log_bytes);
            instances.push(serde_json::json!({
                "instance_type": "room",
                "network_id": room_config.network.network_id,
                "profile_id": profile,
                "build": {"version": env!("CARGO_PKG_VERSION")},
                "started_at": support_unix_timestamp(),
                "truncated": room_log.truncated,
                "status_summary": support_status_summary(&room_config, room_status.as_ref()),
                "log": room_log.content,
            }));
        }
    }

    let network_ids = instances
        .iter()
        .filter_map(|instance| instance.get("network_id").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let room_count = instances.len().saturating_sub(1);
    let bundle = serde_json::json!({
        "schema_version": SUPPORT_LOG_SCHEMA_VERSION,
        "uploaded_at": support_unix_timestamp(),
        "device_name": config.node.device_name,
        "platform": "linux-cli",
        "client_build": {"version": env!("CARGO_PKG_VERSION")},
        "daemon_build": {"version": daemon_version},
        "manifest": {
            "total_instances": instances.len(),
            "network_ids": network_ids,
            "has_room_logs": room_count > 0,
            "retained_room_instances": room_count,
            "omitted_room_instances": omitted_room_instances,
            "omitted_reason": if omitted_room_instances > 0 { "room_instance_budget" } else { "" },
        },
        "instances": instances,
    });
    let encoded = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("无法生成支持包 JSON：{error}"))?;
    if encoded.len() > MAX_SUPPORT_EXPANDED_BYTES {
        return Err(format!(
            "支持包展开后超过服务端上限 {} 字节，请降低 max-log-bytes",
            MAX_SUPPORT_EXPANDED_BYTES
        ));
    }
    let compressed = gzip_bytes(&encoded)?;
    if compressed.len() > MAX_SUPPORT_COMPRESSED_BYTES {
        return Err(format!(
            "支持包压缩后超过服务端上限 {} 字节，请降低 max-log-bytes",
            MAX_SUPPORT_COMPRESSED_BYTES
        ));
    }
    write_binary_file(&output, &compressed)?;

    let upload = if args.upload {
        Some(upload_support_bundle(&config, &compressed).await?)
    } else {
        None
    };
    if args.json {
        let result = serde_json::json!({
            "path": output,
            "instances": bundle.get("manifest").and_then(|value| value.get("total_instances")),
            "omitted_room_instances": omitted_room_instances,
            "upload": upload,
        });
        print_json(&result)
    } else {
        println!("支持包已写入：{}", output.display());
        if let Some(upload) = upload {
            println!("支持包已上传：{}", upload);
        }
        Ok(())
    }
}

fn discover_room_profiles(root: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let profile = entry.file_name().to_string_lossy().to_string();
            if !is_hex_profile_id(&profile) {
                return None;
            }
            let path = entry.path().join("p2wlan-config.json");
            path.is_file().then_some((profile, path))
        })
        .collect()
}

fn is_hex_profile_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_support_log(path: &Path, max_bytes: u64) -> SupportLogTail {
    let Ok(mut file) = File::open(path) else {
        return SupportLogTail {
            content: format!("log file unavailable: {}", path.display()),
            truncated: false,
        };
    };
    let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    let truncated = length > max_bytes;
    let start = length.saturating_sub(max_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return SupportLogTail {
            content: format!("could not seek log file: {}", path.display()),
            truncated: false,
        };
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return SupportLogTail {
            content: format!("could not read log file: {}", path.display()),
            truncated,
        };
    }
    let mut content = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        content = format!("[p2wlan] log tail starts at byte {start}\n{content}");
    }
    SupportLogTail {
        content: redact_support_text(&content),
        truncated,
    }
}

fn support_status_summary(config: &Config, status: Option<&Value>) -> String {
    let value = serde_json::json!({
        "network_id": config.network.network_id,
        "cidr": config.network.cidr,
        "interface": config.network.interface,
        "diagnostics": config.diagnostics.bind,
        "status": status,
    });
    redact_support_text(&serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string()))
}

fn redact_support_text(input: &str) -> String {
    let mut output = input.to_string();
    for prefix in [
        "Bearer ",
        "token=",
        "token:",
        "auth_token=",
        "auth_token:",
        "device_credential=",
        "device_credential:",
        "invite_token=",
        "invite_token:",
        "private_key=",
        "private_key:",
        "ed25519_private_key=",
        "ed25519_private_key:",
        "password=",
        "password:",
        "secret=",
        "secret:",
        "authorization=",
        "authorization:",
        "\"token\": \"",
        "\"auth_token\": \"",
        "\"device_credential\": \"",
        "\"invite_token\": \"",
        "\"private_key\": \"",
        "\"ed25519_private_key\": \"",
        "\"password\": \"",
        "\"secret\": \"",
        "\"authorization\": \"",
    ] {
        output = redact_after_prefix(&output, prefix);
    }
    output
}

fn redact_after_prefix(input: &str, prefix: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let prefix_lower = prefix.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find(&prefix_lower) {
        let start = cursor + relative;
        let value_start = start + prefix.len();
        output.push_str(&input[cursor..value_start]);
        let value_end = input[value_start..]
            .char_indices()
            .find(|(_, ch)| ch.is_whitespace() || matches!(*ch, ',' | ';' | '"' | '\'' | '}' | ']'))
            .map(|(index, _)| value_start + index)
            .unwrap_or(input.len());
        if value_end > value_start {
            output.push_str("<redacted>");
        }
        cursor = value_end;
        if cursor == input.len() {
            break;
        }
    }
    output.push_str(&input[cursor..]);
    output
}

fn gzip_bytes(content: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, content)
        .map_err(|error| format!("无法压缩支持包：{error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("无法完成支持包压缩：{error}"))
}

fn write_binary_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建支持包目录 {}：{error}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("无法创建支持包 {}：{error}", path.display()))?;
    make_private_file(&file)?;
    std::io::Write::write_all(&mut file, content)
        .map_err(|error| format!("无法写入支持包：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("无法同步支持包：{error}"))
}

#[cfg(unix)]
fn make_private_file(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = file
        .metadata()
        .map_err(|error| error.to_string())?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .map_err(|error| format!("无法设置支持包权限：{error}"))
}

#[cfg(not(unix))]
fn make_private_file(_file: &File) -> Result<(), String> {
    Ok(())
}

async fn upload_support_bundle(config: &Config, content: &[u8]) -> Result<String, String> {
    let server = normalize_room_control_server(&config.control.server_url)?;
    let endpoint = format!("{server}/api/v1/support/logs");
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("p2wlan-cli/{}", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none());
    if config.control.proxy_mode.as_label() == "direct" {
        builder = builder.no_proxy();
    }
    let response = builder
        .build()
        .map_err(|error| format!("无法初始化支持包上传：{error}"))?
        .post(endpoint)
        .bearer_auth(&config.control.auth_token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .body(content.to_vec())
        .send()
        .await
        .map_err(|error| format!("上传支持包失败：{error}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("读取支持包上传响应失败：{error}"))?;
    if !status.is_success() {
        return Err(format!("支持包上传返回 HTTP {status}：{}", body.trim()));
    }
    let value = serde_json::from_str::<Value>(&body)
        .map_err(|error| format!("支持包上传响应无效：{error}"))?;
    Ok(value
        .get("upload_id")
        .and_then(Value::as_str)
        .unwrap_or("accepted")
        .to_string())
}

fn support_unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| format!("unix-{}", duration.as_secs()))
        .unwrap_or_else(|_| "unix-0".to_string())
}

#[cfg(test)]
mod support_tests {
    #[test]
    fn redacts_common_support_secrets() {
        let redacted = super::redact_support_text(
            "Authorization: Bearer abc.def token=secret123 password:pass123",
        );
        assert!(!redacted.contains("abc.def"));
        assert!(!redacted.contains("secret123"));
        assert!(!redacted.contains("pass123"));
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn profile_discovery_only_accepts_complete_hex_ids() {
        assert!(super::is_hex_profile_id(&"a".repeat(64)));
        assert!(!super::is_hex_profile_id(&"g".repeat(64)));
        assert!(!super::is_hex_profile_id(&"a".repeat(63)));
    }
}
