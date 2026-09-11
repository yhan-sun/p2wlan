#[derive(Subcommand, Debug)]
enum RoomCommand {
    /// List rooms available to the logged-in account
    List {
        /// Print the complete control-plane response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show a room roster, devices, and bans
    Show {
        /// Room ID (`room-...`) or eight-digit room code
        room: String,
        /// Print the complete roster as JSON
        #[arg(long)]
        json: bool,
    },
    /// Create a room owned by the logged-in account
    Create {
        /// Human-readable room name
        #[arg(long)]
        name: String,
        /// Room password. Omit to enter it without terminal echo.
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Print the server response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Join a room by its eight-digit code
    Join {
        /// Eight-digit room code
        #[arg(long)]
        code: String,
        /// Room password. Omit to enter it without terminal echo.
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Optional 64-character invitation token
        #[arg(long)]
        invite_token: Option<String>,
        /// Print the server response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Create or update an independent local daemon profile and connect it
    Connect {
        /// Room ID or eight-digit room code
        room: String,
    },
    /// Stop the local daemon for a room without leaving it
    Disconnect {
        /// Room ID or eight-digit room code
        room: String,
    },
    /// Leave a room, stopping its local daemon first when necessary
    Leave {
        /// Room ID or eight-digit room code
        room: String,
    },
    /// Delete a room permanently (owner only). Requires --yes in scripts.
    Delete {
        /// Room ID or eight-digit room code
        room: String,
        /// Confirm the destructive deletion without an interactive prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Rename a room (owner only)
    Rename {
        room: String,
        #[arg(long)]
        name: String,
    },
    /// Change a room password (owner only)
    Password {
        room: String,
        /// New password. Omit to enter it without terminal echo.
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Create an invitation token for a room
    Invite {
        room: String,
        /// Invitation lifetime in hours
        #[arg(long, default_value_t = 24)]
        ttl_hours: u64,
        /// Maximum number of successful joins
        #[arg(long, default_value_t = 10)]
        max_uses: u32,
    },
    /// List active and revoked invitations
    Invites {
        room: String,
        #[arg(long)]
        json: bool,
    },
    /// Revoke an invitation
    RevokeInvite {
        room: String,
        #[arg(long)]
        invite: String,
    },
    /// Remove a member from a room (owner only)
    #[command(name = "member-remove", alias = "remove-member")]
    RemoveMember {
        room: String,
        #[arg(long)]
        user: String,
    },
    /// Ban a member from a room (owner only)
    Ban {
        room: String,
        #[arg(long)]
        user: String,
    },
    /// Remove a room ban (owner only)
    Unban {
        room: String,
        #[arg(long)]
        user: String,
    },
    /// Disconnect, block, unblock, or approve one room device (access ID from room show)
    DeviceAccess {
        room: String,
        #[arg(long)]
        access: String,
        #[arg(long, value_parser = ["disconnect", "block", "unblock", "approve"])]
        action: String,
    },
    /// Require owner approval for new devices; existing decisions are preserved
    DeviceApproval {
        room: String,
        #[arg(long, action = clap::ArgAction::Set)]
        required: bool,
    },
    /// Assign a fixed virtual IPv4 address to a room device
    DeviceIp {
        #[arg(name = "room")]
        room: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        ip: String,
    },
    /// Remove a fixed virtual IPv4 address from a room device
    DeviceRemove {
        #[arg(name = "room")]
        room: String,
        #[arg(long)]
        device: String,
    },
}

#[derive(Debug, Clone)]
struct RoomInfo {
    id: String,
    code: String,
    name: String,
    cidr: String,
    role: String,
    join_locked: bool,
}

async fn room_command(config_path: &Path, command: RoomCommand) -> Result<(), String> {
    let mut config = load_config(config_path)?;
    if !matches!(&command, RoomCommand::Disconnect { .. }) {
        hydrate_cli_session_token(config_path, &mut config)?;
    }

    match command {
        RoomCommand::DeviceAccess {
            room,
            access,
            action,
        } => {
            let info = resolve_room(&config, &room).await?;
            validate_path_segment("access", &access)?;
            room_control_request(
                &config,
                reqwest::Method::POST,
                &format!("/{}/device-access/{}/{}", info.id, access, action),
                None,
            )
            .await?;
            println!("设备操作完成；账号成员资格和其他设备不受影响。");
            Ok(())
        }
        RoomCommand::DeviceApproval { room, required } => {
            let info = resolve_room(&config, &room).await?;
            room_control_request(
                &config,
                reqwest::Method::PUT,
                &format!("/{}/device-policy", info.id),
                Some(serde_json::json!({"require_approval": required})),
            )
            .await?;
            println!("新设备审批设置已更新。");
            Ok(())
        }
        RoomCommand::List { json } => {
            let response = room_control_request(&config, reqwest::Method::GET, "", None).await?;
            if json {
                return print_json(&response);
            }
            let user_id = response
                .get("user_id")
                .and_then(Value::as_str)
                .unwrap_or("?");
            println!("账号：{user_id}");
            let rooms = response
                .get("rooms")
                .and_then(Value::as_array)
                .ok_or_else(|| "服务器房间响应缺少 rooms".to_string())?;
            if rooms.is_empty() {
                println!("暂无房间。");
                return Ok(());
            }
            for value in rooms {
                let room = room_info_from_value(value)?;
                let profile = room_profile_id(&config.control.server_url, user_id, &room.id);
                let local = room_config_path_for(config_path, &profile).exists();
                println!(
                    "{}  {}  {}  {}  {}{}",
                    room.id,
                    room.code,
                    room.name,
                    room.role,
                    room.cidr,
                    if local { "  [local profile]" } else { "" }
                );
            }
            Ok(())
        }
        RoomCommand::Show { room, json } => {
            let info = resolve_room(&config, &room).await?;
            let response = room_control_request(
                &config,
                reqwest::Method::GET,
                &format!("/{}", info.id),
                None,
            )
            .await?;
            if json {
                return print_json(&response);
            }
            print_room_details(&response)?;
            Ok(())
        }
        RoomCommand::Create {
            name,
            password,
            json,
        } => {
            let password = required_password(password, "房间密码：")?;
            let response = room_control_request(
                &config,
                reqwest::Method::POST,
                "",
                Some(serde_json::json!({"name": name, "password": password})),
            )
            .await?;
            if json {
                return print_json(&response);
            }
            let room = room_info_from_value(
                response
                    .get("room")
                    .ok_or_else(|| "创建房间响应缺少 room".to_string())?,
            )?;
            println!(
                "房间已创建：{}（房间号 {}，网段 {}）",
                room.name, room.code, room.cidr
            );
            Ok(())
        }
        RoomCommand::Join {
            code,
            password,
            invite_token,
            json,
        } => {
            validate_room_code(&code)?;
            let invite_token = invite_token
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            if password.is_some() && invite_token.is_some() {
                return Err("password 与 invite-token 不能同时使用".to_string());
            }
            let password = match (password, invite_token.is_some()) {
                (Some(value), _) => Some(value),
                (None, true) => None,
                (None, false) => Some(required_password(None, "房间密码：")?),
            };
            let response = room_control_request(
                &config,
                reqwest::Method::POST,
                "/join",
                Some(serde_json::json!({
                    "room_code": code,
                    "password": password,
                    "invite_token": invite_token,
                })),
            )
            .await?;
            if json {
                return print_json(&response);
            }
            let room = room_info_from_value(
                response
                    .get("room")
                    .ok_or_else(|| "加入房间响应缺少 room".to_string())?,
            )?;
            println!("已加入房间：{}（房间号 {}）", room.name, room.code);
            Ok(())
        }
        RoomCommand::Connect { room } => connect_room(config_path, &config, &room).await,
        RoomCommand::Disconnect { room } => disconnect_room(config_path, &config, &room).await,
        RoomCommand::Leave { room } => leave_room(config_path, &config, &room).await,
        RoomCommand::Delete { room, yes } => {
            if !yes {
                return Err("删除房间是不可逆操作，请再次确认并添加 --yes".to_string());
            }
            delete_room(config_path, &config, &room).await
        }
        RoomCommand::Rename { room, name } => {
            let info = resolve_room(&config, &room).await?;
            if name.trim().is_empty() {
                return Err("房间名称不能为空".to_string());
            }
            room_control_request(
                &config,
                reqwest::Method::PATCH,
                &format!("/{}", info.id),
                Some(serde_json::json!({"name": name.trim()})),
            )
            .await?;
            println!("房间名称已更新。");
            Ok(())
        }
        RoomCommand::Password { room, password } => {
            let info = resolve_room(&config, &room).await?;
            let password = required_password(password, "新房间密码：")?;
            room_control_request(
                &config,
                reqwest::Method::PATCH,
                &format!("/{}", info.id),
                Some(serde_json::json!({"password": password})),
            )
            .await?;
            println!("房间密码已更新。");
            Ok(())
        }
        RoomCommand::Invite {
            room,
            ttl_hours,
            max_uses,
        } => {
            let info = resolve_room(&config, &room).await?;
            if !(1..=24 * 7).contains(&ttl_hours) {
                return Err("ttl-hours 必须在 1 到 168 小时之间".to_string());
            }
            if !(1..=1000).contains(&max_uses) {
                return Err("max-uses 必须在 1 到 1000 之间".to_string());
            }
            let response = room_control_request(
                &config,
                reqwest::Method::POST,
                &format!("/{}/invites", info.id),
                Some(serde_json::json!({
                    "ttl_seconds": ttl_hours * 3600,
                    "max_uses": max_uses,
                })),
            )
            .await?;
            let token = response
                .get("invite_token")
                .and_then(Value::as_str)
                .ok_or_else(|| "创建邀请响应缺少 invite_token".to_string())?;
            println!("邀请 token：{token}");
            println!(
                "邀请链接：{}",
                room_invitation_uri(&config.control.server_url, &info.code, token)?
            );
            Ok(())
        }
        RoomCommand::Invites { room, json } => {
            let info = resolve_room(&config, &room).await?;
            let response = room_control_request(
                &config,
                reqwest::Method::GET,
                &format!("/{}/invites", info.id),
                None,
            )
            .await?;
            if json {
                return print_json(&response);
            }
            let invites = response
                .get("invites")
                .and_then(Value::as_array)
                .ok_or_else(|| "邀请响应缺少 invites".to_string())?;
            for invite in invites {
                println!(
                    "{}  expires={}  uses={}/{}  {}",
                    invite.get("id").and_then(Value::as_str).unwrap_or("?"),
                    invite
                        .get("expires_at")
                        .and_then(Value::as_i64)
                        .unwrap_or(0),
                    invite.get("uses").and_then(Value::as_i64).unwrap_or(0),
                    invite.get("max_uses").and_then(Value::as_i64).unwrap_or(0),
                    if invite.get("revoked").and_then(Value::as_bool) == Some(true) {
                        "revoked"
                    } else {
                        "active"
                    }
                );
            }
            Ok(())
        }
        RoomCommand::RevokeInvite { room, invite } => {
            let info = resolve_room(&config, &room).await?;
            validate_path_segment("invite", &invite)?;
            room_control_request(
                &config,
                reqwest::Method::DELETE,
                &format!("/{}/invites/{}", info.id, invite),
                None,
            )
            .await?;
            println!("邀请已撤销。");
            Ok(())
        }
        RoomCommand::RemoveMember { room, user } => {
            room_member_action(&config, &room, &user, "members", reqwest::Method::DELETE).await
        }
        RoomCommand::Ban { room, user } => {
            room_member_action(&config, &room, &user, "bans", reqwest::Method::PUT).await
        }
        RoomCommand::Unban { room, user } => {
            room_member_action(&config, &room, &user, "bans", reqwest::Method::DELETE).await
        }
        RoomCommand::DeviceIp { room, device, ip } => {
            let info = resolve_room(&config, &room).await?;
            validate_path_segment("device", &device)?;
            validate_room_ip(&ip, &info.cidr)?;
            room_control_request(
                &config,
                reqwest::Method::PATCH,
                &format!("/{}/devices/{}", info.id, device),
                Some(serde_json::json!({"virtual_ip": ip})),
            )
            .await?;
            println!("设备虚拟 IP 已更新；设备需要重新连接。");
            Ok(())
        }
        RoomCommand::DeviceRemove { room, device } => {
            let info = resolve_room(&config, &room).await?;
            validate_path_segment("device", &device)?;
            room_control_request(
                &config,
                reqwest::Method::DELETE,
                &format!("/{}/devices/{}", info.id, device),
                None,
            )
            .await?;
            println!("设备固定虚拟 IP 已移除；设备需要重新连接。");
            Ok(())
        }
    }
}

async fn room_control_request(
    config: &Config,
    method: reqwest::Method,
    suffix: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    require_control_auth(config)?;
    let server = normalize_room_control_server(&config.control.server_url)?;
    let endpoint = format!(
        "{}/api/v1/rooms{}",
        server,
        if suffix.is_empty() {
            String::new()
        } else {
            suffix.to_string()
        }
    );
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent(format!("p2wlan-cli/{}", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none());
    if config.control.proxy_mode.as_label() == "direct" {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|error| format!("无法初始化房间请求：{error}"))?;
    let mut request = client
        .request(method, endpoint)
        .bearer_auth(&config.control.auth_token)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("无法访问房间服务：{error}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("读取房间服务响应失败：{error}"))?;
    let value = serde_json::from_str::<Value>(&text).unwrap_or_else(
        |_| serde_json::json!({"error": text.trim().chars().take(240).collect::<String>()}),
    );
    if !status.is_success() {
        return Err(room_api_error(status, &value));
    }
    Ok(value)
}

fn require_control_auth(config: &Config) -> Result<(), String> {
    if config.control.auth_token.trim().is_empty() {
        Err("尚未登录，请先运行 p2wlan login -u <邮箱>".to_string())
    } else {
        Ok(())
    }
}

fn normalize_room_control_server(input: &str) -> Result<String, String> {
    let server = normalize_control_server(input)?;
    let parsed = Url::parse(&server).map_err(|_| "控制服务器地址无效".to_string())?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("房间控制服务器不能包含用户信息、查询参数或 fragment".to_string());
    }
    Ok(server)
}

fn room_api_error(status: reqwest::StatusCode, value: &Value) -> String {
    let code = value
        .get("error_code")
        .and_then(Value::as_str)
        .unwrap_or("");
    let fallback = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("房间操作失败");
    let message = match code {
        "room_exists" => "每个账号最多创建一个房间",
        "room_join" => "无法加入：房间号、密码、邀请或成员资格无效",
        "room_access" => "无权操作该房间，或你已不再是成员",
        "room_invalid" => "房间参数无效",
        "room_conflict" => "房间资源冲突，请换一个虚拟 IP",
        "room_exhausted" => "服务器没有可用房间网段或地址",
        "room_rate_limit" => "加入尝试过于频繁，请稍后重试",
        _ if status == reqwest::StatusCode::UNAUTHORIZED => "登录状态已失效，请重新登录",
        _ if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::UPGRADE_REQUIRED =>
        {
            "当前服务器不支持好友房间，请升级服务器"
        }
        _ => fallback,
    };
    format!("{message}（HTTP {status}）")
}

async fn resolve_room(config: &Config, argument: &str) -> Result<RoomInfo, String> {
    validate_room_selector(argument)?;
    let response = room_control_request(config, reqwest::Method::GET, "", None).await?;
    let rooms = response
        .get("rooms")
        .and_then(Value::as_array)
        .ok_or_else(|| "服务器房间响应缺少 rooms".to_string())?;
    rooms
        .iter()
        .map(room_info_from_value)
        .find(|result| {
            result
                .as_ref()
                .map(|room| room.id == argument || room.code == argument)
                .unwrap_or(false)
        })
        .transpose()?
        .ok_or_else(|| format!("找不到房间 {argument}，请先运行 p2wlan room list"))
}

fn room_info_from_value(value: &Value) -> Result<RoomInfo, String> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "房间响应缺少 id".to_string())?
        .to_string();
    let code = value
        .get("room_code")
        .and_then(Value::as_str)
        .ok_or_else(|| "房间响应缺少 room_code".to_string())?
        .to_string();
    let cidr = value
        .get("cidr")
        .and_then(Value::as_str)
        .ok_or_else(|| "房间响应缺少 cidr".to_string())?
        .to_string();
    validate_room_id(&id)?;
    validate_room_code(&code)?;
    validate_room_cidr(&cidr)?;
    Ok(RoomInfo {
        id,
        code,
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        cidr,
        role: value
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("member")
            .to_string(),
        join_locked: value
            .get("join_locked")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn print_room_details(value: &Value) -> Result<(), String> {
    let room = room_info_from_value(
        value
            .get("room")
            .ok_or_else(|| "房间详情响应缺少 room".to_string())?,
    )?;
    println!(
        "{}  {}  {}  {}  role={}  locked={}",
        room.id, room.code, room.name, room.cidr, room.role, room.join_locked
    );
    if let Some(members) = value.get("members").and_then(Value::as_array) {
        println!("成员（{}）：", members.len());
        for member in members {
            println!(
                "  {}  {}  {}",
                member.get("user_id").and_then(Value::as_str).unwrap_or("?"),
                member
                    .get("username")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                member
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("member")
            );
        }
    }
    if let Some(access) = value.get("device_access").and_then(Value::as_array) {
        println!(
            "设备权限（新设备审批：{}）：",
            value
                .get("device_approval_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        );
        for item in access {
            println!(
                "  {}  {}  {}",
                item.get("id").and_then(Value::as_str).unwrap_or("?"),
                item.get("device_name")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                item.get("state").and_then(Value::as_str).unwrap_or("?")
            );
        }
    }
    if let Some(devices) = value.get("devices").and_then(Value::as_array) {
        println!("设备（{}）：", devices.len());
        for device in devices {
            println!(
                "  {}  {}  ip={}  online={}",
                device.get("id").and_then(Value::as_str).unwrap_or("?"),
                device.get("name").and_then(Value::as_str).unwrap_or("?"),
                device
                    .get("virtual_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("(auto)"),
                device
                    .get("online")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            );
        }
    }
    if let Some(banned) = value.get("banned_user_ids").and_then(Value::as_array) {
        if !banned.is_empty() {
            println!(
                "封禁账号：{}",
                banned
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

async fn room_member_action(
    config: &Config,
    room: &str,
    user: &str,
    collection: &str,
    method: reqwest::Method,
) -> Result<(), String> {
    let info = resolve_room(config, room).await?;
    validate_path_segment("user", user)?;
    room_control_request(
        config,
        method,
        &format!("/{}/{}/{}", info.id, collection, user),
        None,
    )
    .await?;
    println!("房间成员操作已完成。");
    Ok(())
}

async fn connect_room(config_path: &Path, config: &Config, selector: &str) -> Result<(), String> {
    let response = room_control_request(config, reqwest::Method::GET, "", None).await?;
    let user_id = response
        .get("user_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "服务器未返回当前 user_id，无法生成独立房间身份".to_string())?;
    let rooms = response
        .get("rooms")
        .and_then(Value::as_array)
        .ok_or_else(|| "服务器房间响应缺少 rooms".to_string())?;
    let room = rooms
        .iter()
        .map(room_info_from_value)
        .find(|result| {
            result
                .as_ref()
                .map(|item| item.id == selector || item.code == selector)
                .unwrap_or(false)
        })
        .transpose()?
        .ok_or_else(|| format!("找不到房间 {selector}，请先运行 p2wlan room list 或 room join"))?;
    let profile = room_profile_id(&config.control.server_url, user_id, &room.id);
    let config_file = room_config_path_for(config_path, &profile);
    let room_config = prepare_room_config(config, &room, &profile, &config_file)?;
    save_config(&room_config, &config_file)?;
    if rooms.iter().any(|value| {
        value.get("id").and_then(Value::as_str) == Some(&room.id)
            && value.get("device_controls_version").and_then(Value::as_u64) == Some(1)
    }) {
        room_control_request(
            config,
            reqwest::Method::POST,
            &format!("/{}/device-access", room.id),
            Some(serde_json::json!({
                "public_key": room_config.node.public_key,
                "device_name": room_config.node.device_name,
                "platform": room_config.node.platform,
                "resume": true,
            })),
        )
        .await?;
    }
    let runtime = room_state_dir_for_config(config_path, &profile);
    start_with_state_dir(&config_file, &runtime).await?;
    set_room_connection_intent(&runtime, true)?;
    println!("房间已连接：{}（profile {profile}）", room.name);
    Ok(())
}

async fn disconnect_room(
    config_path: &Path,
    config: &Config,
    selector: &str,
) -> Result<(), String> {
    // Stopping a local process must remain possible while the control server
    // or account session is offline.  Room IDs are stable, so use the local
    // profile index before falling back to the online room lookup.
    if let Some((config_file, runtime)) = find_local_room_profile(config_path, selector)? {
        let stopped = stop_with_state_dir(&config_file, &runtime).await;
        set_room_connection_intent(&runtime, false)?;
        return stopped;
    }

    let response = room_control_request(config, reqwest::Method::GET, "", None).await?;
    let user_id = response
        .get("user_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "服务器未返回当前 user_id".to_string())?;
    let room = find_room_in_response(&response, selector)?;
    let profile = room_profile_id(&config.control.server_url, user_id, &room.id);
    let config_file = room_config_path_for(config_path, &profile);
    if !config_file.exists() {
        set_room_connection_intent(&room_state_dir_for_config(config_path, &profile), false)?;
        println!("房间没有本地 profile，未运行。");
        return Ok(());
    }
    let runtime = room_state_dir_for_config(config_path, &profile);
    let stopped = stop_with_state_dir(&config_file, &runtime).await;
    set_room_connection_intent(&runtime, false)?;
    stopped
}

fn find_local_room_profile(
    config_path: &Path,
    selector: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let Some(root) = config_path.parent().map(|parent| parent.join("rooms")) else {
        return Ok(None);
    };
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(None);
    };
    for entry in entries.flatten() {
        let profile = entry.path();
        let config_file = profile.join("p2wlan-config.json");
        if !config_file.is_file() {
            continue;
        }
        let candidate = load_config(&config_file)?;
        if candidate.network.network_id == selector {
            let profile_id = profile
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "本地房间 profile 名称无效".to_string())?;
            return Ok(Some((
                config_file,
                room_state_dir_for_config(config_path, profile_id),
            )));
        }
    }
    Ok(None)
}

fn set_room_connection_intent(runtime: &Path, wanted: bool) -> Result<(), String> {
    let path = runtime.join("connection.json");
    if !path.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "invalid local room preferences".to_string())?;
    object.insert("wanted".into(), Value::Bool(wanted));
    let temp = runtime.join("connection.cli.tmp");
    std::fs::write(
        &temp,
        serde_json::to_vec(&value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(temp, path).map_err(|e| e.to_string())
}

async fn leave_room(config_path: &Path, config: &Config, selector: &str) -> Result<(), String> {
    let response = room_control_request(config, reqwest::Method::GET, "", None).await?;
    let user_id = response
        .get("user_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "服务器未返回当前 user_id".to_string())?;
    let room = find_room_in_response(&response, selector)?;
    let profile = room_profile_id(&config.control.server_url, user_id, &room.id);
    let config_file = room_config_path_for(config_path, &profile);
    if config_file.exists() {
        let runtime = room_state_dir_for_config(config_path, &profile);
        stop_with_state_dir(&config_file, &runtime).await?;
        set_room_connection_intent(&runtime, false)?;
    }
    room_control_request(
        config,
        reqwest::Method::POST,
        &format!("/{}/leave", room.id),
        None,
    )
    .await?;
    println!("已离开房间：{}。", room.name);
    Ok(())
}

async fn delete_room(config_path: &Path, config: &Config, selector: &str) -> Result<(), String> {
    let response = room_control_request(config, reqwest::Method::GET, "", None).await?;
    let user_id = response
        .get("user_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "服务器未返回当前 user_id".to_string())?;
    let room = find_room_in_response(&response, selector)?;
    if room.role != "owner" {
        return Err("只有房主可以删除房间；成员请使用 room leave".to_string());
    }
    room_control_request(
        config,
        reqwest::Method::DELETE,
        &format!("/{}", room.id),
        None,
    )
    .await?;
    // A deleted room must not leave a reconnecting local daemon behind. Keep
    // cleanup after the remote mutation so a transient control failure does
    // not erase a still-valid local profile.
    let profile = room_profile_id(&config.control.server_url, user_id, &room.id);
    let config_file = room_config_path_for(config_path, &profile);
    let runtime = room_state_dir_for_config(config_path, &profile);
    if config_file.exists() {
        if let Err(error) = stop_with_state_dir(&config_file, &runtime).await {
            eprintln!("警告：房间已删除，但本地 daemon 停止失败：{error}");
        }
    }
    if let Some(profile_dir) = config_file.parent() {
        if let Err(error) = fs::remove_dir_all(profile_dir) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("警告：房间已删除，但本地 profile 清理失败：{error}");
            }
        }
    }
    if let Err(error) = fs::remove_dir_all(&runtime) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("警告：房间已删除，但本地运行状态清理失败：{error}");
        }
    }
    println!("房间已删除：{}。", room.name);
    Ok(())
}

fn find_room_in_response(response: &Value, selector: &str) -> Result<RoomInfo, String> {
    validate_room_selector(selector)?;
    response
        .get("rooms")
        .and_then(Value::as_array)
        .ok_or_else(|| "服务器房间响应缺少 rooms".to_string())?
        .iter()
        .map(room_info_from_value)
        .find(|result| {
            result
                .as_ref()
                .map(|room| room.id == selector || room.code == selector)
                .unwrap_or(false)
        })
        .transpose()?
        .ok_or_else(|| format!("找不到房间 {selector}"))
}

fn prepare_room_config(
    main: &Config,
    room: &RoomInfo,
    profile: &str,
    path: &Path,
) -> Result<Config, String> {
    let existing_profile = path.exists();
    let mut room_config = if existing_profile {
        load_config(path)?
    } else {
        Config::generate_default(&main.control.server_url, &room.id)
            .map_err(|error| format!("无法生成房间身份：{error}"))?
    };
    if room_config.network.network_id != room.id {
        return Err(format!(
            "本地房间 profile 的 network_id 为 {}，不是 {}；请移走 {} 后重试",
            room_config.network.network_id,
            room.id,
            path.display()
        ));
    }
    let server = normalize_control_server(&main.control.server_url)?;
    room_config.control = main.control.clone();
    room_config.control.server_url = server;
    clear_device_credential(&mut room_config);
    room_config.node.device_name = main.node.device_name.clone();
    room_config.network.network_id = room.id.clone();
    room_config.network.manual = false;
    room_config.network.virtual_ip.clear();
    room_config.network.cidr = room.cidr.clone();
    room_config.network.ipv6_cidr = None;
    room_config.network.netmask = "255.255.255.0".to_string();
    room_config.network.interface = format!("p2r{}", &profile[..12]);
    room_config.network.udp_bind = "0.0.0.0:0".to_string();
    room_config.network.udp_advertise = None;
    room_config.relay = main.relay.clone();
    room_config.port_mappings.clear();
    room_config.diagnostics.enabled = true;
    room_config.diagnostics.bind = room_diagnostics_bind_with_existing(
        profile,
        existing_profile.then_some(room_config.diagnostics.bind.as_str()),
    )?;
    room_config.diagnostics.log_path = None;
    room_config.diagnostics.auth_token = None;
    room_config.diagnostics.auth_token_path = None;
    Ok(room_config)
}

fn room_profile_id(server: &str, user_id: &str, network_id: &str) -> String {
    let server = normalize_control_server(server)
        .unwrap_or_else(|_| server.trim_end_matches('/').to_string());
    let encoded = serde_json::to_vec(&[server, user_id.to_string(), network_id.to_string()])
        .expect("room profile tuple is serializable");
    hex::encode(sha2::Sha256::digest(encoded))
}

fn room_config_path_for(main_config_path: &Path, profile: &str) -> PathBuf {
    main_config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("rooms")
        .join(profile)
        .join("p2wlan-config.json")
}

fn room_state_dir_for_config(main_config_path: &Path, profile: &str) -> PathBuf {
    state_dir_for_config(main_config_path)
        .join("rooms")
        .join(profile)
}

fn room_diagnostics_bind_with_existing(
    profile: &str,
    existing: Option<&str>,
) -> Result<String, String> {
    let Some(existing) = existing else {
        return Ok(room_diagnostics_bind(profile));
    };
    let address = existing
        .parse::<SocketAddr>()
        .map_err(|_| "本地房间诊断地址无效".to_string())?;
    if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || !(40000..60000).contains(&address.port())
    {
        return Err("本地房间诊断地址必须使用 127.0.0.1 和 40000–59999 端口".to_string());
    }
    Ok(address.to_string())
}

fn room_diagnostics_bind(profile: &str) -> String {
    let prefix = u32::from_str_radix(&profile[..8], 16).unwrap_or(0);
    format!("127.0.0.1:{}", 40000 + prefix % 20000)
}

fn room_invitation_uri(server: &str, code: &str, token: &str) -> Result<String, String> {
    let mut uri = Url::parse("p2wlan://join").map_err(|error| error.to_string())?;
    uri.query_pairs_mut()
        .append_pair("server", &normalize_room_control_server(server)?)
        .append_pair("room", code);
    uri.set_fragment(Some(&format!("invite={token}")));
    Ok(uri.to_string())
}

fn required_password(password: Option<String>, prompt: &str) -> Result<String, String> {
    let value = match password {
        Some(value) => value,
        None => {
            rpassword::prompt_password(prompt).map_err(|error| format!("读取密码失败：{error}"))?
        }
    };
    if value.trim().is_empty() {
        return Err("密码不能为空".to_string());
    }
    if value.len() < 8 {
        return Err("房间密码至少需要 8 个字节".to_string());
    }
    if value.len() > 72 {
        return Err("房间密码过长（最多 72 个字节）".to_string());
    }
    Ok(value)
}

fn validate_room_selector(value: &str) -> Result<(), String> {
    if is_valid_room_id(value) || is_valid_room_code(value) {
        Ok(())
    } else {
        Err("房间参数必须是 room- 后跟 32 位小写十六进制 ID，或 8 位房间号".to_string())
    }
}

fn validate_room_id(value: &str) -> Result<(), String> {
    if is_valid_room_id(value) {
        Ok(())
    } else {
        Err(format!("无效房间 ID：{value}"))
    }
}

fn validate_room_code(value: &str) -> Result<(), String> {
    if is_valid_room_code(value) {
        Ok(())
    } else {
        Err(format!("无效房间号：{value}（需要 8 位数字）"))
    }
}

fn is_valid_room_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("room-")
        && value[5..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

fn is_valid_room_code(value: &str) -> bool {
    value.len() == 8 && value.chars().all(|ch| ch.is_ascii_digit())
}

fn validate_room_cidr(value: &str) -> Result<(), String> {
    let Some((address, prefix)) = value.split_once('/') else {
        return Err(format!("无效房间网段：{value}"));
    };
    let ip = address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("无效房间网段：{value}"))?;
    if prefix != "24" || ip.octets()[0] != 10 || ip.octets()[1] != 21 || ip.octets()[3] != 0 {
        return Err(format!("无效房间网段：{value}"));
    }
    Ok(())
}

fn validate_room_ip(value: &str, cidr: &str) -> Result<(), String> {
    validate_room_cidr(cidr)?;
    let ip = value
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("无效虚拟 IP：{value}"))?;
    let network = cidr
        .split_once('/')
        .and_then(|(address, _)| address.parse::<std::net::Ipv4Addr>().ok())
        .ok_or_else(|| format!("无效房间网段：{cidr}"))?;
    if ip.octets()[0] != network.octets()[0]
        || ip.octets()[1] != network.octets()[1]
        || ip.octets()[2] != network.octets()[2]
        || !(1..=254).contains(&ip.octets()[3])
    {
        return Err(format!("虚拟 IP {value} 不属于房间网段 {cidr}"));
    }
    Ok(())
}

fn validate_path_segment(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(format!("{label} 包含无效字符"));
    }
    Ok(())
}

#[cfg(test)]
mod room_tests {
    #[test]
    fn preserves_desktop_allocated_room_diagnostics_port() {
        let profile = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            super::room_diagnostics_bind_with_existing(profile, Some("127.0.0.1:45678")).unwrap(),
            "127.0.0.1:45678"
        );
        assert_eq!(
            super::room_diagnostics_bind_with_existing(profile, None).unwrap(),
            super::room_diagnostics_bind(profile)
        );
        for invalid in ["0.0.0.0:45678", "127.0.0.1:80", "broken", "[::1]:45678"] {
            assert!(super::room_diagnostics_bind_with_existing(profile, Some(invalid)).is_err());
        }
    }

    #[test]
    fn profile_id_matches_the_desktop_shape() {
        let actual = super::room_profile_id(
            "http://example.test",
            "user-1",
            "room-0123456789abcdef0123456789abcdef",
        );
        assert_eq!(actual.len(), 64);
        assert!(actual.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn selectors_and_room_ips_are_strict() {
        assert!(super::is_valid_room_code("12345678"));
        assert!(!super::is_valid_room_code("1234"));
        assert!(super::is_valid_room_id(
            "room-0123456789abcdef0123456789abcdef"
        ));
        assert!(!super::is_valid_room_id(
            "room-0123456789ABCDEF0123456789abcdef"
        ));
        assert!(super::validate_room_ip("10.21.7.42", "10.21.7.0/24").is_ok());
        assert!(super::validate_room_ip("10.20.7.42", "10.21.7.0/24").is_err());
        assert!(super::required_password(Some("short".to_string()), "").is_err());
        assert!(super::required_password(Some("12345678".to_string()), "").is_ok());
    }
}
use sha2::Digest;
