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
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        if proxy.send_event(UserEvent::Refresh).is_err() {
            break;
        }
    });

    let (menu_items, menu) = TrayMenu::new()?;
    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("P2WLAN")
        .with_icon(tray_icon_image(false)?)
        .with_icon_as_template(false)
        .build()?;

    let mut app = TrayApp {
        menu: menu_items,
        tray_icon,
        last_state: DaemonState::offline(),
    };
    app.refresh_state();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) | Event::UserEvent(UserEvent::Refresh) => {
                app.refresh_state();
            }
            Event::UserEvent(UserEvent::Menu(event)) => match app.menu.id_for(&event) {
                MenuAction::StartDaemon => app.start_daemon(),
                MenuAction::StopDaemon => app.stop_daemon(),
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

#[cfg(target_os = "macos")]
fn configure_platform_event_loop(event_loop: &mut tao::event_loop::EventLoop<UserEvent>) {
    use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    event_loop.set_dock_visibility(false);
}

#[cfg(not(target_os = "macos"))]
fn configure_platform_event_loop(_event_loop: &mut tao::event_loop::EventLoop<UserEvent>) {}
