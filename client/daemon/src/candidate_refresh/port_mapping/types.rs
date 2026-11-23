#[derive(Debug, Clone, PartialEq, Eq)]
struct PortMappingCandidate {
    endpoint: String,
    source: &'static str,
    lease_seconds: u32,
}
