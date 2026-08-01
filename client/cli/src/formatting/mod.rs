//! Doctor/diagnostics output formatting: snapshot summarization helpers that
//! render NAT, relay, peer, traversal-history, MTU and UDP socket-pool state
//! into human-readable text.
//!
//! This module is a facade: the formatting helpers live in the
//! `mtu` / `relay` / `peer` / `nat` submodules and are re-exported here so the
//! crate root can `use formatting::*`.

use serde_json::Value;

use super::is_clear_value;

mod mtu;
mod nat;
mod peer;
mod relay;

pub(crate) use mtu::*;
pub(crate) use nat::*;
pub(crate) use peer::*;
pub(crate) use relay::*;

pub(crate) fn protocol_boundary_summary(snapshot: &Value) -> Option<String> {
    let protocol = snapshot.get("protocol")?.as_object()?;
    let data_plane = protocol
        .get("data_plane")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let handshake = protocol
        .get("handshake")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let aead = protocol
        .get("aead")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let wireguard_interop = yes_no(
        protocol
            .get("wireguard_interop")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let turn_compatible = yes_no(
        protocol
            .get("turn_compatible")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let audit = protocol
        .get("security_audit")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Some(format!(
        "{data_plane} handshake={handshake} aead={aead} wg-interop={wireguard_interop} turn={turn_compatible} audit={audit}"
    ))
}
pub(crate) fn protocol_boundary_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(protocol) = snapshot.get("protocol").and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut suggestions = Vec::new();
    if protocol
        .get("security_audit")
        .and_then(Value::as_str)
        .is_some_and(|audit| audit != "completed")
    {
        suggestions.push(
            "协议安全审计未完成；发布 Production 前需要独立审计、威胁建模和互操作边界复核。"
                .to_string(),
        );
    }
    if protocol
        .get("wireguard_interop")
        .and_then(Value::as_bool)
        .is_some_and(|interop| !interop)
    {
        suggestions.push("当前数据面是 WireGuard-like Noise，不是官方 WireGuard 互通实现；文档和部署脚本应避免承诺 WireGuard 客户端兼容。".to_string());
    }
    suggestions
}
fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
pub(crate) fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}
pub(crate) fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}
