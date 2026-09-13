#[test]
fn windows_icmp_rules_are_scoped_to_both_room_and_interface() {
    let first = windows_icmp_echo_rule_name("10.21.1.0/24", "p2rfirst");
    assert_ne!(
        first,
        windows_icmp_echo_rule_name("10.21.2.0/24", "p2rfirst")
    );
    assert_ne!(
        first,
        windows_icmp_echo_rule_name("10.21.1.0/24", "p2rsecond")
    );
    assert_eq!(
        first,
        windows_icmp_echo_rule_name("10.21.1.0/24", "P2RFIRST")
    );
    assert!(first.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
}

#[test]
fn windows_icmp_update_repairs_filters_instead_of_only_enabling_a_shared_rule() {
    let script = windows_icmp_echo_firewall_script("10.21.2.0/24", "p2r'quoted");
    assert!(script.contains("$interface = 'p2r''quoted'"));
    assert!(script.contains("LocalAddress = $cidr"));
    assert!(script.contains("RemoteAddress = $cidr"));
    assert!(script.contains("InterfaceAlias ="));
    assert!(script.contains("IcmpType = '8'"));
    assert!(script.contains("Set-NetFirewallRule @parameters"));
    assert!(!script.contains("-DisplayName $name"));
    assert!(!script.contains("Enable-NetFirewallRule"));
}
