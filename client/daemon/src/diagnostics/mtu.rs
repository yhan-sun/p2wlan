fn mtu_profile(mtu: u32) -> &'static str {
    match mtu {
        0..=1279 => "low",
        1280..=RELAY_SAFE_MTU => "relay_safe",
        1381..=WIREGUARD_STYLE_MTU => "default",
        1421..=COMMON_ETHERNET_MTU => "high",
        _ => "jumbo_high_risk",
    }
}

fn suggested_safe_mtu(mtu: u32, relay_path_observed: bool) -> Option<u32> {
    if mtu < IPV6_SAFE_MIN_MTU {
        Some(IPV6_SAFE_MIN_MTU)
    } else if relay_path_observed && mtu > RELAY_SAFE_MTU {
        Some(RELAY_SAFE_MTU)
    } else if mtu > WIREGUARD_STYLE_MTU {
        Some(WIREGUARD_STYLE_MTU)
    } else {
        None
    }
}

fn mtu_risks(mtu: u32, relay_path_observed: bool) -> Vec<MtuRiskDiagnostics> {
    let mut risks = Vec::new();
    if mtu < IPV6_SAFE_MIN_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "below_ipv6_safe_min".to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Configured MTU {mtu} is below the IPv6 minimum {IPV6_SAFE_MIN_MTU}; use it only as a temporary PMTU blackhole workaround."
            ),
            suggested_mtu: Some(IPV6_SAFE_MIN_MTU),
        });
    }
    if relay_path_observed && mtu > RELAY_SAFE_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "relay_path_high_mtu".to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Relay path observed with MTU {mtu}; if large flows stall, try lowering MTU to {RELAY_SAFE_MTU} before changing the default globally."
            ),
            suggested_mtu: Some(RELAY_SAFE_MTU),
        });
    }
    if mtu > COMMON_ETHERNET_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "jumbo_mtu_high_risk".to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Configured MTU {mtu} exceeds common Ethernet MTU {COMMON_ETHERNET_MTU}; require end-to-end jumbo-frame validation or lower to {WIREGUARD_STYLE_MTU}."
            ),
            suggested_mtu: Some(WIREGUARD_STYLE_MTU),
        });
    } else if mtu > WIREGUARD_STYLE_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "above_wireguard_style_default".to_string(),
            severity: "notice".to_string(),
            message: format!(
                "Configured MTU {mtu} is above the WireGuard-style default {WIREGUARD_STYLE_MTU}; mobile, CGNAT, or enterprise paths may blackhole large packets."
            ),
            suggested_mtu: Some(WIREGUARD_STYLE_MTU),
        });
    }
    risks
}
