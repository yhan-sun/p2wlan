struct TrayApp {
    menu: TrayMenu,
    tray_icon: TrayIcon,
    last_state: DaemonState,
}

impl TrayApp {
    fn refresh_state(&mut self) {
        self.last_state = query_daemon_state();
        self.apply_state();
    }

    fn apply_state(&mut self) {
        self.menu
            .status
            .set_text(format!("状态：{}", self.last_state.status_label));
        self.menu.network.set_text(match self.last_state.online {
            Some(count) => format!(
                "虚拟 IP：{} · 在线设备：{count}",
                self.last_state.virtual_ip
            ),
            None => "虚拟 IP：— · 在线设备：—".to_string(),
        });
        self.menu.stop_daemon.set_enabled(self.last_state.running);
        self.menu
            .start_daemon
            .set_enabled(!self.last_state.running && !self.last_state.busy);
        rebuild_device_menu(&self.menu.devices, &self.last_state.devices);
        let _ = self
            .tray_icon
            .set_tooltip(Some(self.last_state.tooltip.as_str()));
        let _ = self.tray_icon.set_icon(Some(
            tray_icon_image(self.last_state.running).expect("static tray icon should be valid"),
        ));
    }

    fn start_daemon(&mut self) {
        self.set_status("状态：正在启动");
        match start_daemon() {
            Ok(()) => self.set_status("状态：正在建立虚拟网络"),
            Err(error) => {
                eprintln!("p2wlan-tray start failed: {error}");
                self.set_status(format!("启动失败：{error}"));
            }
        }
        thread::sleep(Duration::from_millis(700));
        self.refresh_state();
    }

    fn stop_daemon(&mut self) {
        self.set_status("状态：正在停止");
        match stop_daemon() {
            Ok(()) => self.set_status("状态：停止请求已发送"),
            Err(error) => self.set_status(format!("停止失败：{error}")),
        }
        thread::sleep(Duration::from_millis(700));
        self.refresh_state();
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

    fn set_status(&self, text: impl AsRef<str>) {
        self.menu.status.set_text(text.as_ref());
        let _ = self.tray_icon.set_tooltip(Some(text.as_ref()));
    }
}
