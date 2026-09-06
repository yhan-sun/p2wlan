fn main() {
    if let Err(error) = run() {
        eprintln!("p2wlan-tray failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut event_loop_builder = EventLoop::<UserEvent>::with_user_event();
    #[cfg(target_os = "macos")]
    {
        event_loop_builder
            .with_activation_policy(ActivationPolicy::Accessory)
            .with_default_menu(false);
    }
    let event_loop = event_loop_builder.build()?;
    let proxy = event_loop.create_proxy();

    let initial_state = DaemonState::offline();
    let menu = build_tray_menu(&initial_state);
    let menu_proxy = proxy.clone();
    let tray_icon = TrayIconBuilder::new()
        .sender(move |event: &UserEvent| {
            let _ = menu_proxy.send_event(event.clone());
        })
        .icon(tray_icon_image(false)?)
        .title("P2WLAN")
        .tooltip("P2WLAN")
        .item_is_menu(true)
        .menu(menu)
        .build()?;

    let refresh_in_flight = Arc::new(AtomicBool::new(false));
    let refresh_proxy = proxy.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        if refresh_proxy.send_event(UserEvent::Refresh).is_err() {
            break;
        }
    });

    let mut app = TrayApp {
        tray_icon,
        last_state: initial_state,
        previous_traffic: None,
        proxy,
        refresh_in_flight,
    };
    app.apply_state();
    event_loop.run_app(&mut app)?;
    Ok(())
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
