fn main() {
    if let Err(error) = run() {
        eprintln!("p2wlan-tray failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    configure_platform_event_loop(&mut event_loop);

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    let proxy = event_loop.create_proxy();
    let refresh_in_flight = Arc::new(AtomicBool::new(false));
    let refresh_proxy = proxy.clone();
    thread::spawn(move || loop {
        // Keep the standalone tray on the same cadence as the Flutter
        // client's foreground presentation metrics.
        thread::sleep(Duration::from_secs(1));
        if refresh_proxy.send_event(UserEvent::Refresh).is_err() {
            break;
        }
    });

    let (menu_items, menu) = TrayMenu::new()?;
    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("P2WLAN")
        // macOS menu bar items are intentionally icon-only; the tooltip still
        // carries the accessible product/status text. Other platforms keep a
        // short title for taskbar discoverability.
        .with_title(if cfg!(target_os = "macos") {
            ""
        } else {
            "P2WLAN"
        })
        .with_icon(tray_icon_image(false)?)
        .with_icon_as_template(false)
        .build()?;

    let mut app = TrayApp {
        menu: menu_items,
        tray_icon,
        last_state: DaemonState::offline(),
        previous_traffic: None,
    };
    app.apply_state();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) | Event::UserEvent(UserEvent::Refresh) => {
                spawn_state_refresh(
                    proxy.clone(),
                    refresh_in_flight.clone(),
                );
            }
            Event::UserEvent(UserEvent::State(state)) => {
                app.apply_state_update(state);
            }
            Event::UserEvent(UserEvent::DaemonActionFinished { action, error }) => {
                app.finish_daemon_action(action, error);
                spawn_state_refresh(
                    proxy.clone(),
                    refresh_in_flight.clone(),
                );
            }
            Event::UserEvent(UserEvent::Menu(event)) => match app.menu.id_for(&event) {
                MenuAction::StartDaemon => app.start_daemon(proxy.clone()),
                MenuAction::StopDaemon => app.stop_daemon(proxy.clone()),
                MenuAction::OpenClient => app.open_client(),
                MenuAction::OpenLogs => app.open_logs(),
                MenuAction::CopyPeerIp(ip) => app.copy_peer_ip(&ip),
                MenuAction::Quit => {
                    app.quit_p2wlan();
                    *control_flow = ControlFlow::Exit;
                }
                MenuAction::None => {}
            },
            _ => {}
        }
    });
}

fn spawn_state_refresh(proxy: EventLoopProxy<UserEvent>, in_flight: Arc<AtomicBool>) {
    if in_flight.swap(true, Ordering::AcqRel) {
        return;
    }
    thread::spawn(move || {
        let state = query_daemon_state();
        let _ = proxy.send_event(UserEvent::State(state));
        in_flight.store(false, Ordering::Release);
    });
}

#[cfg(target_os = "macos")]
fn configure_platform_event_loop(event_loop: &mut tao::event_loop::EventLoop<UserEvent>) {
    use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    event_loop.set_dock_visibility(false);
}

#[cfg(not(target_os = "macos"))]
fn configure_platform_event_loop(_event_loop: &mut tao::event_loop::EventLoop<UserEvent>) {}
