use super::*;

    fn test_cli(control: Option<&str>, network: Option<&str>) -> Cli {
        Cli {
            build_info: false,
            overlay_burst: 0,
            config: PathBuf::from("p2wlan-config.json"),
            init: false,
            control: control.map(ToString::to_string),
            network: network.map(ToString::to_string),
            status: false,
            token: None,
            token_file: None,
            interface: None,
            address: None,
            manual: false,
            managed: false,
            netmask: None,
            mtu: None,
            heartbeat_interval: None,
            udp_bind: None,
            udp_advertise: None,
            stun: None,
            udp_observer: None,
            stun_timeout_ms: None,
            punch_interval_ms: None,
            punch_attempts: None,
            socket_pool: None,
            keepalive_interval_secs: None,
            relay: None,
            relay_regions: None,
            relay_selection_timeout_ms: None,
            relay_startup_timeout_ms: None,
            diagnostics_bind: None,
            diagnostics_disable: false,
            prefer_relay: false,
            prefer_direct: false,
            relay_only: false,
            fresh_mapping_harness_loopback: false,
            no_host_candidates: false,
            disable_fresh_mapping_punch: false,
            disable_predicted_candidates: false,
            disable_birthday_probing: false,
            validate_overlay: false,

            overlay_any_path: false,

            proxy_mode: None,
            device_name: None,
            diagnostics_url: None,
            log_file: None,
        }
    }

    #[test]
    fn explicit_control_and_network_override_loaded_config() {
        let mut config = Config::generate_default("https://old.example", "old-net").unwrap();
        let cli = test_cli(Some("http://127.0.0.1:18080"), Some("default"));

        apply_cli_overrides(&mut config, &cli);

        assert_eq!(config.control.server_url, "http://127.0.0.1:18080");
        assert_eq!(config.network.network_id, "default");
    }

    #[test]
    fn omitted_control_and_network_preserve_loaded_config() {
        let mut config = Config::generate_default("https://old.example", "old-net").unwrap();
        let cli = test_cli(None, None);

        apply_cli_overrides(&mut config, &cli);

        assert_eq!(config.control.server_url, "https://old.example");
        assert_eq!(config.network.network_id, "old-net");
    }

    #[test]
    fn traversal_ablation_flags_disable_only_the_requested_strategies() {
        let mut config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        let mut cli = test_cli(None, None);
        cli.disable_fresh_mapping_punch = true;
        cli.disable_predicted_candidates = true;
        cli.disable_birthday_probing = true;

        apply_cli_overrides(&mut config, &cli);

        assert!(!config.network.fresh_mapping_punch_enabled);
        assert!(!config.network.predicted_candidates_enabled);
        assert!(!config.network.birthday_probing_enabled);
    }

    #[test]
    fn prefer_relay_keeps_background_direct_upgrade_enabled() {
        let mut config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        config.relay.prefer_direct = false;
        let mut cli = test_cli(None, None);
        cli.prefer_relay = true;

        apply_cli_overrides(&mut config, &cli);

        assert!(config.relay.prefer_direct);

        let mut relay_only_config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        let mut relay_only_cli = test_cli(None, None);
        relay_only_cli.relay_only = true;

        apply_cli_overrides(&mut relay_only_config, &relay_only_cli);

        assert!(!relay_only_config.relay.prefer_direct);
    }

    #[test]
    fn network_arguments_override_generated_config() {
        let mut config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        let cli = Cli {
            build_info: false,
            overlay_burst: 0,
            config: PathBuf::from("p2wlan-config.json"),
            init: false,
            control: Some("http://127.0.0.1".to_string()),
            network: Some("default".to_string()),
            status: false,
            token: None,
            token_file: None,
            interface: None,
            address: None,
            manual: false,
            managed: false,
            netmask: Some("255.255.255.255".to_string()),
            mtu: None,
            heartbeat_interval: None,
            udp_bind: None,
            udp_advertise: None,
            stun: None,
            udp_observer: None,
            stun_timeout_ms: None,
            punch_interval_ms: None,
            punch_attempts: None,
            socket_pool: Some("3".to_string()),
            keepalive_interval_secs: None,
            relay: Some("cn-east@127.0.0.1:8080,us-west@127.0.0.1:8081".to_string()),
            relay_regions: Some("cn-east,us-west".to_string()),
            relay_selection_timeout_ms: Some(750),
            relay_startup_timeout_ms: None,
            diagnostics_bind: None,
            diagnostics_disable: false,
            prefer_relay: false,
            prefer_direct: false,
            relay_only: false,
            fresh_mapping_harness_loopback: false,
            no_host_candidates: false,
            disable_fresh_mapping_punch: false,
            disable_predicted_candidates: false,
            disable_birthday_probing: false,
            validate_overlay: false,

            overlay_any_path: false,

            proxy_mode: None,
            device_name: None,
            diagnostics_url: None,
            log_file: None,
        };

        apply_cli_overrides(&mut config, &cli);

        assert_eq!(config.network.netmask, "255.255.255.255");
        assert_eq!(
            config.relay.servers,
            vec![
                "cn-east@127.0.0.1:8080".to_string(),
                "us-west@127.0.0.1:8081".to_string()
            ]
        );
        assert_eq!(config.relay.preferred_regions, vec!["cn-east", "us-west"]);
        assert_eq!(config.relay.selection_timeout_ms, 750);
        assert!(config.network.socket_pool_enabled);
        assert_eq!(config.network.socket_pool_size, 3);
    }

    #[test]
    fn test_validate_cli_invalid_cases() {
        // Create base Cli
        let base_cli = Cli {
            build_info: false,
            overlay_burst: 0,
            config: PathBuf::from("p2wlan-config.json"),
            init: false,
            control: Some("https://control.p2wlan.io".to_string()),
            network: Some("default".to_string()),
            status: false,
            token: None,
            token_file: None,
            interface: None,
            address: None,
            manual: false,
            managed: false,
            netmask: None,
            mtu: None,
            heartbeat_interval: None,
            udp_bind: None,
            udp_advertise: None,
            stun: None,
            udp_observer: None,
            stun_timeout_ms: None,
            punch_interval_ms: None,
            punch_attempts: None,
            socket_pool: None,
            keepalive_interval_secs: None,
            relay: None,
            relay_regions: None,
            relay_selection_timeout_ms: None,
            relay_startup_timeout_ms: None,
            diagnostics_bind: None,
            diagnostics_disable: false,
            prefer_relay: false,
            prefer_direct: false,
            relay_only: false,
            fresh_mapping_harness_loopback: false,
            no_host_candidates: false,
            disable_fresh_mapping_punch: false,
            disable_predicted_candidates: false,
            disable_birthday_probing: false,
            validate_overlay: false,

            overlay_any_path: false,

            proxy_mode: None,
            device_name: None,
            diagnostics_url: None,
            log_file: None,
        };

        // 1. Invalid control URL
        let mut cli = base_cli.clone();
        cli.control = Some("not-a-url".to_string());
        assert!(validate_cli(&cli).is_err());

        // 2. Invalid address
        let mut cli = base_cli.clone();
        cli.address = Some("999.999.999.999".to_string());
        assert!(validate_cli(&cli).is_err());

        // 3. Invalid netmask
        let mut cli = base_cli.clone();
        cli.netmask = Some("bad-netmask".to_string());
        assert!(validate_cli(&cli).is_err());

        // 4. Invalid MTU
        let mut cli = base_cli.clone();
        cli.mtu = Some(100);
        assert!(validate_cli(&cli).is_err());

        // 5. Invalid udp-bind
        let mut cli = base_cli.clone();
        cli.udp_bind = Some("bad-bind".to_string());
        assert!(validate_cli(&cli).is_err());

        // 6. Invalid udp-advertise
        let mut cli = base_cli.clone();
        cli.udp_advertise = Some("bad:99999".to_string());
        assert!(validate_cli(&cli).is_err());

        // 7. Invalid relay server endpoint format
        let mut cli = base_cli.clone();
        cli.relay = Some("bad:99999".to_string());
        assert!(validate_cli(&cli).is_err());

        let mut cli = base_cli.clone();
        cli.relay = Some("cn-east@bad:99999".to_string());
        assert!(validate_cli(&cli).is_err());

        // 8. Empty region in relay spec
        let mut cli = base_cli.clone();
        cli.relay = Some("@127.0.0.1:8080".to_string());
        assert!(validate_cli(&cli).is_err());

        // 9. Invalid control scheme (non-http/https)
        let mut cli = base_cli.clone();
        cli.control = Some("ftp://127.0.0.1".to_string());
        assert!(validate_cli(&cli).is_err());

        // Valid cases should pass
        let mut cli = base_cli.clone();
        cli.control = Some("http://127.0.0.1:18080".to_string());
        cli.address = Some("10.20.0.2".to_string());
        cli.netmask = Some("255.255.255.0".to_string());
        cli.mtu = Some(1420);
        cli.udp_bind = Some("0.0.0.0:51820".to_string());
        cli.udp_advertise = Some("203.0.113.10:51820".to_string());
        cli.stun = Some("stun.l.google.com:19302,stun.example.com:19302".to_string());
        cli.udp_observer = Some("127.0.0.1:18082".to_string());
        cli.relay = Some("cn-east@127.0.0.1:8080,us-west@127.0.0.1:8081".to_string());
        assert!(validate_cli(&cli).is_ok());

        cli.stun = Some("not-a-stun-server".to_string());
        assert!(validate_cli(&cli).is_err());

        cli.stun = None;
        cli.udp_observer = Some("bad-observer".to_string());
        assert!(validate_cli(&cli).is_err());

        cli.udp_observer = None;
        cli.socket_pool = Some("4".to_string());
        assert!(validate_cli(&cli).is_ok());
        cli.socket_pool = Some("5".to_string());
        assert!(validate_cli(&cli).is_err());

        cli.socket_pool = None;
        cli.manual = true;
        cli.managed = true;
        assert!(validate_cli(&cli).is_err());
    }

    #[test]
    fn managed_argument_overrides_existing_manual_config() {
        let mut config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        config.network.manual = true;

        let cli = Cli {
            build_info: false,
            overlay_burst: 0,
            config: PathBuf::from("p2wlan-config.json"),
            init: false,
            control: Some("http://127.0.0.1".to_string()),
            network: Some("default".to_string()),
            status: false,
            token: Some("test-token".to_string()),
            token_file: None,
            interface: None,
            address: None,
            manual: false,
            managed: true,
            netmask: None,
            mtu: None,
            heartbeat_interval: None,
            udp_bind: None,
            udp_advertise: None,
            stun: None,
            udp_observer: None,
            stun_timeout_ms: None,
            punch_interval_ms: None,
            punch_attempts: None,
            socket_pool: None,
            keepalive_interval_secs: None,
            relay: None,
            relay_regions: None,
            relay_selection_timeout_ms: None,
            relay_startup_timeout_ms: None,
            diagnostics_bind: None,
            diagnostics_disable: false,
            prefer_relay: false,
            prefer_direct: false,
            relay_only: false,
            fresh_mapping_harness_loopback: false,
            no_host_candidates: false,
            disable_fresh_mapping_punch: false,
            disable_predicted_candidates: false,
            disable_birthday_probing: false,
            validate_overlay: false,

            overlay_any_path: false,

            proxy_mode: None,
            device_name: None,
            diagnostics_url: None,
            log_file: None,
        };

        apply_cli_overrides(&mut config, &cli);

        assert!(!config.network.manual);
        assert_eq!(config.control.auth_token, "test-token");
    }

    #[test]
    fn test_clap_parsing() {
        use clap::Parser;

        // Verify valid parsing
        let parsed = Cli::try_parse_from([
            "p2wlan-daemon",
            "--config",
            "custom.json",
            "--control",
            "http://127.0.0.1:8080",
            "--network",
            "testnet",
            "--init",
        ]);
        assert!(parsed.is_ok());
        let cli = parsed.unwrap();
        assert_eq!(cli.config, PathBuf::from("custom.json"));
        assert_eq!(cli.control.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(cli.network.as_deref(), Some("testnet"));
        assert!(cli.init);

        // Verify version and help parse cleanly
        let parsed_help = Cli::try_parse_from(["p2wlan-daemon", "--help"]);
        assert!(parsed_help.is_err()); // Clap returns an Error of kind DisplayHelp
        assert_eq!(
            parsed_help.unwrap_err().kind(),
            clap::error::ErrorKind::DisplayHelp
        );

        let relay_first = Cli::try_parse_from(["p2wlan-daemon", "--prefer-relay"]);
        assert!(relay_first.is_ok());
        let relay_only = Cli::try_parse_from(["p2wlan-daemon", "--relay-only"]);
        assert!(relay_only.is_ok());
        let conflicting_paths = Cli::try_parse_from([
            "p2wlan-daemon",
            "--prefer-relay",
            "--relay-only",
        ]);
        assert!(conflicting_paths.is_err());

        let parsed_version = Cli::try_parse_from(["p2wlan-daemon", "--version"]);
        assert!(parsed_version.is_err());
        assert_eq!(
            parsed_version.unwrap_err().kind(),
            clap::error::ErrorKind::DisplayVersion
        );
    }

    #[test]
    fn daemon_instance_lock_rejects_second_owner_for_same_config() {
        let unique = format!(
            "p2wlan-instance-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&directory).unwrap();
        let config_path = directory.join("p2wlan-config.json");
        std::fs::write(&config_path, b"{}").unwrap();

        let first = DaemonInstanceLock::acquire(&config_path).unwrap();
        let error = DaemonInstanceLock::acquire(&config_path).unwrap_err();
        assert!(error
            .to_string()
            .contains("another P2WLAN daemon is already running"));

        drop(first);
        assert!(DaemonInstanceLock::acquire(&config_path).is_ok());
        let _ = std::fs::remove_dir_all(directory);
    }
