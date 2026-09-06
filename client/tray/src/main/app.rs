struct TrafficSample {
    total_bytes: u64,
    observed_at: Instant,
}

struct TrayApp {
    tray_icon: TrayIcon<UserEvent>,
    last_state: DaemonState,
    previous_traffic: Option<TrafficSample>,
    proxy: EventLoopProxy<UserEvent>,
    refresh_in_flight: Arc<AtomicBool>,
}

impl TrayApp {
    fn apply_state_update(&mut self, mut state: DaemonState) {
        state.busy = self.last_state.busy;
        state.speed_bytes_per_second = self.update_traffic_rate(&state);
        self.last_state = state;
        self.apply_state();
    }

    fn update_traffic_rate(&mut self, state: &DaemonState) -> Option<u64> {
        let Some(total_bytes) = state.total_bytes else {
            self.previous_traffic = None;
            return None;
        };

        let now = Instant::now();
        let previous = self.previous_traffic.replace(TrafficSample {
            total_bytes,
            observed_at: now,
        });
        let previous = previous?;
        if total_bytes < previous.total_bytes {
            return None;
        }

        let elapsed_nanos = now.duration_since(previous.observed_at).as_nanos();
        if elapsed_nanos == 0 {
            return None;
        }
        let delta = u128::from(total_bytes - previous.total_bytes);
        Some(
            (delta * 1_000_000_000 / elapsed_nanos)
                .min(u128::from(u64::MAX)) as u64,
        )
    }

    fn apply_state(&mut self) {
        let menu = build_tray_menu(&self.last_state);
        if let Err(error) = self.tray_icon.set_menu(&menu) {
            eprintln!("p2wlan-tray menu update failed: {error}");
        }
        for id in [
            UserEvent::StatusInfo,
            UserEvent::NetworkInfo,
            UserEvent::NoDevices,
        ] {
            let _ = self.tray_icon.set_menu_item_disabled(id, true);
        }
        let _ = self.tray_icon.set_menu_item_disabled(
            UserEvent::StartDaemon,
            self.last_state.running || self.last_state.busy,
        );
        let _ = self.tray_icon.set_menu_item_disabled(
            UserEvent::StopDaemon,
            !self.last_state.running || self.last_state.busy,
        );

        let icon = tray_icon_image(self.last_state.running)
            .expect("static tray icon should be valid");
        let _ = self.tray_icon.set_icon(&icon);

        let latency = format_tray_latency(self.last_state.latency_ms);
        let speed = format_tray_rate(self.last_state.speed_bytes_per_second);
        let title = tray_performance_title(&self.last_state);
        let tooltip = if self.last_state.running {
            format!(
                "{} · 本端平均 RTT：{latency} · 速度：{speed}",
                self.last_state.tooltip
            )
        } else {
            self.last_state.tooltip.clone()
        };
        let _ = self.tray_icon.set_title(&title);
        let _ = self.tray_icon.set_tooltip(&tooltip);
    }

    fn start_daemon(&mut self) {
        if self.last_state.busy {
            return;
        }
        self.last_state.busy = true;
        self.last_state.status_label = "正在启动".to_string();
        self.apply_state();
        self.set_status("状态：正在启动");
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let error = start_daemon().err().map(|error| error.to_string());
            let _ = proxy.send_event(UserEvent::DaemonActionFinished {
                action: DaemonAction::Start,
                error,
            });
        });
    }

    fn stop_daemon(&mut self) {
        if self.last_state.busy {
            return;
        }
        self.last_state.busy = true;
        self.last_state.status_label = "正在停止".to_string();
        self.apply_state();
        self.set_status("状态：正在停止");
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let error = stop_daemon().err().map(|error| error.to_string());
            let _ = proxy.send_event(UserEvent::DaemonActionFinished {
                action: DaemonAction::Stop,
                error,
            });
        });
    }

    fn finish_daemon_action(&mut self, action: DaemonAction, error: Option<String>) {
        self.last_state.busy = false;
        let status = match (action, error) {
            (DaemonAction::Start, None) => {
                self.last_state.status_label = "正在建立虚拟网络".to_string();
                "状态：正在建立虚拟网络".to_string()
            }
            (DaemonAction::Stop, None) => {
                self.last_state.status_label = "停止请求已发送".to_string();
                "状态：停止请求已发送".to_string()
            }
            (DaemonAction::Start, Some(error)) => {
                eprintln!("p2wlan-tray start failed: {error}");
                self.last_state.status_label = "启动失败".to_string();
                format!("启动失败：{error}")
            }
            (DaemonAction::Stop, Some(error)) => {
                self.last_state.status_label = "停止失败".to_string();
                format!("停止失败：{error}")
            }
        };
        self.apply_state();
        self.set_status(status);
    }

    fn open_client(&mut self) {
        if let Err(error) = open_flutter_client() {
            eprintln!("p2wlan-tray open client failed: {error}");
            self.set_status(format!("打开控制台失败：{error}"));
        }
    }

    fn open_logs(&mut self) {
        if let Err(error) = open_log_directory() {
            self.set_status(format!("打开日志失败：{error}"));
        }
    }

    fn copy_peer_ip(&mut self, ip: &str) {
        if let Err(error) = copy_to_clipboard(ip) {
            self.set_status(format!("复制失败：{error}"));
        }
    }

    fn quit_p2wlan(&mut self) {
        self.set_status("状态：正在退出");
        let _ = stop_daemon();
    }

    fn set_status(&mut self, text: impl AsRef<str>) {
        let text = text.as_ref();
        self.last_state.status_label = text
            .strip_prefix("状态：")
            .unwrap_or(text)
            .to_string();
        self.apply_state();
        let _ = self.tray_icon.set_tooltip(text);
    }

    fn refresh_state(&self) {
        spawn_state_refresh(self.proxy.clone(), self.refresh_in_flight.clone());
    }
}

impl ApplicationHandler<UserEvent> for TrayApp {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
        self.refresh_state();
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Refresh => self.refresh_state(),
            UserEvent::State(state) => self.apply_state_update(state),
            UserEvent::DaemonActionFinished { action, error } => {
                self.finish_daemon_action(action, error);
                self.refresh_state();
            }
            UserEvent::StartDaemon => self.start_daemon(),
            UserEvent::StopDaemon => self.stop_daemon(),
            UserEvent::OpenClient => self.open_client(),
            UserEvent::OpenLogs => self.open_logs(),
            UserEvent::CopyPeerIp(ip) => self.copy_peer_ip(&ip),
            UserEvent::Quit => {
                self.quit_p2wlan();
                event_loop.exit();
            }
            UserEvent::StatusInfo | UserEvent::NetworkInfo | UserEvent::NoDevices => {}
        }
    }
}

#[cfg(target_os = "macos")]
fn tray_performance_title(_state: &DaemonState) -> String {
    String::new()
}

#[cfg(not(target_os = "macos"))]
fn tray_performance_title(state: &DaemonState) -> String {
    if !state.running {
        return "P2WLAN".to_string();
    }
    format!(
        "P2WLAN · {} · {}",
        format_tray_latency(state.latency_ms),
        format_tray_rate(state.speed_bytes_per_second)
    )
}

fn format_tray_latency(latency_ms: Option<u64>) -> String {
    latency_ms
        .map(|value| format!("{value} ms"))
        .unwrap_or_else(|| "—".to_string())
}

fn format_tray_rate(bytes_per_second: Option<u64>) -> String {
    let Some(bytes_per_second) = bytes_per_second else {
        return "—".to_string();
    };
    let value = bytes_per_second as f64;
    let (value, unit) = if value >= 1024.0 * 1024.0 * 1024.0 {
        (value / (1024.0 * 1024.0 * 1024.0), "G/S")
    } else if value >= 1024.0 * 1024.0 {
        (value / (1024.0 * 1024.0), "M/S")
    } else {
        (value / 1024.0, "K/S")
    };
    let text = if value.fract() == 0.0 || value >= 100.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    };
    format!("{text} {unit}")
}
