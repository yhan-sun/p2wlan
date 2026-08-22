use crate::error::{Error, Result};

const MAX_COMMAND_OUTPUT_CHARS: usize = 2048;

/// Convert a Windows command result into a hard failure when the command did
/// not complete successfully. Keeping this boundary independent of
/// `std::process::Output` makes the failure semantics testable without
/// changing the host's network configuration.
pub(crate) fn require_success(
    stage: &str,
    interface: &str,
    success: bool,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<()> {
    if success {
        return Ok(());
    }

    Err(Error::WindowsCommandFailed {
        stage: stage.to_string(),
        interface: interface.to_string(),
        exit_code,
        stdout: sanitize_output(stdout),
        stderr: sanitize_output(stderr),
    })
}

fn sanitize_output(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    if raw.split_whitespace().any(matches_sensitive_word) {
        return "[redacted sensitive command output]".to_string();
    }

    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return "<empty>".to_string();
    }
    compact.chars().take(MAX_COMMAND_OUTPUT_CHARS).collect()
}

fn matches_sensitive_word(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    ["token", "password", "secret", "authorization", "bearer"]
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::require_success;

    #[test]
    fn zero_exit_status_is_ok() {
        assert!(require_success(
            "IPv4 configuration",
            "My Windows PC",
            true,
            Some(0),
            b"ok",
            b""
        )
        .is_ok());
    }

    #[test]
    fn non_zero_exit_status_is_an_error_with_stage_interface_and_exit_code() {
        let error = require_success(
            "IPv4 configuration",
            "My Windows PC",
            false,
            Some(87),
            b"The parameter is incorrect.",
            b"netsh failed",
        )
        .expect_err("a failed command must not be treated as successful");
        let text = error.to_string();
        assert!(text.contains("IPv4 configuration"));
        assert!(text.contains("My Windows PC"));
        assert!(text.contains("87"));
        assert!(text.contains("The parameter is incorrect."));
        assert!(text.contains("netsh failed"));
    }

    #[test]
    fn sensitive_output_is_redacted() {
        let error = require_success(
            "MTU configuration",
            "p2pnet0",
            false,
            Some(1),
            b"password=do-not-log",
            b"",
        )
        .expect_err("the command should fail");
        assert!(!error.to_string().contains("do-not-log"));
        assert!(error.to_string().contains("redacted"));
    }
}
