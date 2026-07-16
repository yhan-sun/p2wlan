//! Access Control List (ACL) engine.
//!
//! Determines whether network traffic between nodes is allowed:
//! - Default: allow all traffic
//! - Rules can restrict by source/destination node, protocol, port
//! - Supports allow/deny actions with first-match semantics
//!
//! ## Rule Format
//!
//! ```json
//! {
//!   "action": "deny",
//!   "src": "node-abc",
//!   "dst": "*",
//!   "proto": "tcp",
//!   "port": "22"
//! }
//! ```

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::AclConfig;

// ============================================================
// ACL Rule
// ============================================================

/// A single ACL rule (mirrors config::AclRule with parsed fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule action.
    pub action: Action,
    /// Source matcher.
    pub src: Matcher,
    /// Destination matcher.
    pub dst: Matcher,
    /// Protocol matcher.
    pub proto: ProtocolMatcher,
    /// Port matcher.
    pub port: PortMatcher,
}

/// ACL action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
}

/// Node ID matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Matcher {
    /// Match any node.
    #[serde(rename = "*")]
    Any,
    /// Match a specific node ID.
    Node(String),
}

impl Matcher {
    /// Parse a matcher from a string.
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            Matcher::Any
        } else {
            Matcher::Node(s.to_string())
        }
    }

    /// Check if this matcher matches the given node ID.
    pub fn matches(&self, node_id: &str) -> bool {
        match self {
            Matcher::Any => true,
            Matcher::Node(id) => id == node_id,
        }
    }
}

/// Protocol matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMatcher {
    /// Match any protocol.
    Any,
    /// Match a specific protocol.
    Protocol(String),
}

impl ProtocolMatcher {
    /// Parse from string.
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            ProtocolMatcher::Any
        } else {
            ProtocolMatcher::Protocol(s.to_lowercase())
        }
    }

    /// Check if this matcher matches the given protocol.
    pub fn matches(&self, proto: &str) -> bool {
        match self {
            ProtocolMatcher::Any => true,
            ProtocolMatcher::Protocol(p) => p == &proto.to_lowercase(),
        }
    }
}

/// Port matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortMatcher {
    /// Match any port.
    Any,
    /// Match a specific port.
    Port(u16),
    /// Match a range of ports (inclusive).
    Range(u16, u16),
}

impl PortMatcher {
    /// Parse from string.
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            PortMatcher::Any
        } else if let Some(idx) = s.find('-') {
            let start: u16 = s[..idx].parse().unwrap_or(0);
            let end: u16 = s[idx + 1..].parse().unwrap_or(65535);
            PortMatcher::Range(start, end)
        } else if let Ok(port) = s.parse() {
            PortMatcher::Port(port)
        } else {
            PortMatcher::Any
        }
    }

    /// Check if this matcher matches the given port.
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatcher::Any => true,
            PortMatcher::Port(p) => p == &port,
            PortMatcher::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

// ============================================================
// ACL Engine
// ============================================================

/// The ACL engine that evaluates rules.
pub struct AclEngine {
    /// Whether ACL is enabled.
    enabled: bool,
    /// Ordered list of rules (first match wins).
    rules: Vec<Rule>,
}

impl AclEngine {
    /// Create a new ACL engine from config.
    pub fn from_config(config: &AclConfig) -> Self {
        let rules = config
            .rules
            .iter()
            .map(|r| Rule {
                action: match r.action.as_str() {
                    "allow" => Action::Allow,
                    "deny" => Action::Deny,
                    _ => Action::Allow,
                },
                src: Matcher::parse(&r.src),
                dst: Matcher::parse(&r.dst),
                proto: ProtocolMatcher::parse(&r.proto),
                port: PortMatcher::parse(&r.port),
            })
            .collect();

        Self {
            enabled: config.enabled,
            rules,
        }
    }

    /// Create an ACL engine that allows everything.
    pub fn allow_all() -> Self {
        Self {
            enabled: false,
            rules: vec![Rule {
                action: Action::Allow,
                src: Matcher::Any,
                dst: Matcher::Any,
                proto: ProtocolMatcher::Any,
                port: PortMatcher::Any,
            }],
        }
    }

    /// Whether ACL is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check whether traffic is allowed.
    ///
    /// Returns `true` if the traffic should be allowed, `false` if denied.
    /// Uses first-match semantics: the first rule that matches wins.
    /// If no rule matches, the default is **deny** when ACL is enabled.
    pub fn check(&self, src_node: &str, dst_node: &str, proto: &str, port: u16) -> bool {
        if !self.enabled {
            return true;
        }

        for rule in &self.rules {
            if rule.src.matches(src_node)
                && rule.dst.matches(dst_node)
                && rule.proto.matches(proto)
                && rule.port.matches(port)
            {
                debug!(
                    "ACL match: {} {} → {}:{} (action: {:?})",
                    proto, src_node, dst_node, port, rule.action
                );
                return rule.action == Action::Allow;
            }
        }

        // Default deny when ACL is enabled but no rule matched
        warn!(
            "ACL no match (default deny): {} {} → {}:{}",
            proto, src_node, dst_node, port
        );
        false
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: Rule) {
        info!(
            "ACL add rule: {:?} {} → {} (proto={}, port={:?})",
            rule.action,
            match &rule.src {
                Matcher::Any => "*".to_string(),
                Matcher::Node(id) => id.clone(),
            },
            match &rule.dst {
                Matcher::Any => "*".to_string(),
                Matcher::Node(id) => id.clone(),
            },
            match &rule.proto {
                ProtocolMatcher::Any => "*".to_string(),
                ProtocolMatcher::Protocol(p) => p.clone(),
            },
            rule.port,
        );
        self.rules.push(rule);
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_any() {
        let m = Matcher::Any;
        assert!(m.matches("anything"));
        assert!(m.matches(""));
    }

    #[test]
    fn test_matcher_node() {
        let m = Matcher::Node("node1".to_string());
        assert!(m.matches("node1"));
        assert!(!m.matches("node2"));
    }

    #[test]
    fn test_protocol_matcher() {
        let any = ProtocolMatcher::Any;
        assert!(any.matches("tcp"));
        assert!(any.matches("udp"));

        let tcp = ProtocolMatcher::Protocol("tcp".to_string());
        assert!(tcp.matches("tcp"));
        assert!(tcp.matches("TCP"));
        assert!(!tcp.matches("udp"));
    }

    #[test]
    fn test_port_matcher() {
        let any = PortMatcher::Any;
        assert!(any.matches(80));

        let port = PortMatcher::Port(80);
        assert!(port.matches(80));
        assert!(!port.matches(443));

        let range = PortMatcher::Range(80, 443);
        assert!(range.matches(80));
        assert!(range.matches(443));
        assert!(range.matches(200));
        assert!(!range.matches(79));
        assert!(!range.matches(444));
    }

    #[test]
    fn test_port_matcher_parse() {
        assert_eq!(PortMatcher::parse("*"), PortMatcher::Any);
        assert_eq!(PortMatcher::parse("80"), PortMatcher::Port(80));
        assert_eq!(PortMatcher::parse("80-443"), PortMatcher::Range(80, 443));
    }

    #[test]
    fn test_acl_allow_all() {
        let acl = AclEngine::allow_all();
        assert!(acl.check("node1", "node2", "tcp", 80));
    }

    #[test]
    fn test_acl_disabled_allows_all() {
        let config = AclConfig {
            enabled: false,
            rules: vec![crate::config::AclRule {
                action: "deny".to_string(),
                src: "*".to_string(),
                dst: "*".to_string(),
                proto: "*".to_string(),
                port: "*".to_string(),
            }],
        };
        let acl = AclEngine::from_config(&config);
        // When disabled, everything is allowed
        assert!(acl.check("node1", "node2", "tcp", 80));
    }

    #[test]
    fn test_acl_enabled_deny_ssh() {
        let config = AclConfig {
            enabled: true,
            rules: vec![
                crate::config::AclRule {
                    action: "deny".to_string(),
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    proto: "tcp".to_string(),
                    port: "22".to_string(),
                },
                crate::config::AclRule {
                    action: "allow".to_string(),
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    proto: "*".to_string(),
                    port: "*".to_string(),
                },
            ],
        };
        let acl = AclEngine::from_config(&config);

        // SSH is denied
        assert!(!acl.check("node1", "node2", "tcp", 22));

        // HTTP is allowed
        assert!(acl.check("node1", "node2", "tcp", 80));
    }

    #[test]
    fn test_acl_specific_node() {
        let config = AclConfig {
            enabled: true,
            rules: vec![
                crate::config::AclRule {
                    action: "deny".to_string(),
                    src: "untrusted".to_string(),
                    dst: "*".to_string(),
                    proto: "*".to_string(),
                    port: "*".to_string(),
                },
                crate::config::AclRule {
                    action: "allow".to_string(),
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    proto: "*".to_string(),
                    port: "*".to_string(),
                },
            ],
        };
        let acl = AclEngine::from_config(&config);

        // Untrusted node is denied
        assert!(!acl.check("untrusted", "server", "tcp", 80));

        // Trusted node is allowed
        assert!(acl.check("trusted", "server", "tcp", 80));
    }

    #[test]
    fn test_acl_default_deny() {
        let acl = AclEngine {
            enabled: true,
            rules: vec![],
        };
        // No rules + ACL enabled = default deny
        assert!(!acl.check("node1", "node2", "tcp", 80));
    }

    #[test]
    fn test_acl_add_rule() {
        let mut acl = AclEngine::allow_all();
        assert_eq!(acl.rule_count(), 1);
        acl.add_rule(Rule {
            action: Action::Deny,
            src: Matcher::Node("bad".to_string()),
            dst: Matcher::Any,
            proto: ProtocolMatcher::Any,
            port: PortMatcher::Any,
        });
        assert_eq!(acl.rule_count(), 2);
    }

    #[test]
    fn test_acl_port_range() {
        let config = AclConfig {
            enabled: true,
            rules: vec![
                crate::config::AclRule {
                    action: "deny".to_string(),
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    proto: "tcp".to_string(),
                    port: "1-1023".to_string(),
                },
                crate::config::AclRule {
                    action: "allow".to_string(),
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    proto: "*".to_string(),
                    port: "*".to_string(),
                },
            ],
        };
        let acl = AclEngine::from_config(&config);

        // Privileged ports denied
        assert!(!acl.check("a", "b", "tcp", 22));
        assert!(!acl.check("a", "b", "tcp", 80));

        // High ports allowed
        assert!(acl.check("a", "b", "tcp", 8080));
    }
}
