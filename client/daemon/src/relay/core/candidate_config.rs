/// A relay candidate after control-plane/catalog normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidateConfig {
    pub region: String,
    pub audience: Option<String>,
    pub endpoint: String,
}

impl RelayCandidateConfig {
    pub fn catalog(
        region: impl Into<String>,
        audience: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            region: region.into(),
            audience: Some(audience.into()),
            endpoint: endpoint.into(),
        }
    }

    pub fn legacy(spec: impl Into<String>) -> Self {
        Self {
            region: String::new(),
            audience: None,
            endpoint: spec.into(),
        }
    }
}
