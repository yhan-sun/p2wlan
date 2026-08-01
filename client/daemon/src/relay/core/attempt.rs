enum RelayAttemptError {
    Relay(p2pnet_relay::RelayError),
    Daemon(DaemonError),
}

impl RelayAttemptError {
    fn error_code(&self) -> String {
        match self {
            RelayAttemptError::Relay(error) => error
                .error_code()
                .map(|code| code.to_snake_case().to_string())
                .unwrap_or_else(|| error.to_snake_case().to_string()),
            RelayAttemptError::Daemon(error) => match error {
                DaemonError::Auth(_) => "permanent_auth".to_string(),
                DaemonError::ControlPlane(message) if message.contains("permanent auth") => {
                    "permanent_auth".to_string()
                }
                DaemonError::ControlPlane(_) => "ticket_fetch_failed".to_string(),
                _ => "connect_failed".to_string(),
            },
        }
    }
}

impl fmt::Display for RelayAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayAttemptError::Relay(error) => write!(f, "{error}"),
            RelayAttemptError::Daemon(error) => write!(f, "{error}"),
        }
    }
}

fn parse_candidate(
    index: usize,
    spec: &RelayCandidateConfig,
    preferred_regions: &[String],
) -> std::result::Result<RelayCandidate, String> {
    let raw_endpoint = spec.endpoint.trim();
    if raw_endpoint.is_empty() {
        return Err("empty relay candidate".to_string());
    }

    let (region, endpoint) = if spec.region.trim().is_empty() {
        match raw_endpoint.split_once('@') {
            Some((region, endpoint)) if !region.trim().is_empty() => {
                (region.trim().to_string(), endpoint.trim())
            }
            Some(_) => {
                return Err(format!(
                    "relay candidate '{}' has an empty region",
                    spec.endpoint
                ))
            }
            None => ("default".to_string(), raw_endpoint),
        }
    } else {
        (spec.region.trim().to_string(), raw_endpoint)
    };

    // Endpoints now support tls://host:port, tcp://host:port, or bare host:port.
    // Validation is done by the relay client's endpoint parser.
    if endpoint.is_empty() {
        return Err(format!(
            "relay candidate '{}' has an empty endpoint",
            spec.endpoint
        ));
    }

    let audience = spec
        .audience
        .as_ref()
        .map(|audience| audience.trim().to_string())
        .filter(|audience| !audience.is_empty());

    let preference_rank = preferred_regions
        .iter()
        .position(|preferred| preferred.eq_ignore_ascii_case(&region))
        .unwrap_or(preferred_regions.len());

    Ok(RelayCandidate {
        index,
        region,
        audience,
        endpoint: endpoint.to_string(),
        preference_rank,
    })
}
