#[derive(Debug, Clone, PartialEq, Eq)]
struct PortMappingCandidate {
    endpoint: String,
    source: &'static str,
}
