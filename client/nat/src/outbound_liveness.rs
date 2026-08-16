//! Outbound UDP liveness probing via a well-formed DNS A query.
//!
//! Field evidence: the NetEase UU remote implementation decided "outbound UDP
//! blocked" by firing EMPTY datagrams (`sendto(b"\x00"*16)`) and waiting on
//! `recvfrom`. Public DNS servers almost never answer a malformed/empty
//! datagram, so the "got a response" path was effectively unreachable and the
//! verdict was unreliable. We instead send a minimal legal DNS A query, which
//! a public resolver answers whether the answer is NOERROR or NXDOMAIN — so
//! "any response" is a dependable outbound+inbound-UDP-reachable signal.

use std::net::SocketAddr;
use std::time::Duration;

/// Conservative three-state verdict for outbound UDP reachability.
///
/// Only `Blocked` may accelerate the recovery path into relay fallback and
/// stamp the `firewall_blocked` attribution. `Unknown` (socket/system error)
/// must NEVER drive a decision — a socket that cannot be created says nothing
/// about whether UDP egress is firewalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessVerdict {
    /// At least one target answered within its round timeout: outbound UDP
    /// is reachable; the punch failure has another cause (window miss / C=0).
    Ok,
    /// Every target × every round produced no response: outbound UDP is
    /// likely firewalled.
    Blocked,
    /// Socket creation / system error: not used for any decision, recorded
    /// only.
    Unknown,
}

/// One target's probe outcome within a single round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProbeResult {
    /// A response datagram arrived before the round timeout.  We do NOT parse
    /// the answer body: NOERROR and NXDOMAIN both prove UDP round-trip reach.
    Responded { elapsed: Duration },
    /// The round timeout elapsed with no datagram.
    NoResponse,
    /// send/recv hit an OS-level I/O error (distinct from a silent timeout).
    SocketError,
}

#[derive(Debug, Clone)]
pub struct LivenessTargetResult {
    pub target: SocketAddr,
    pub responded: bool,
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LivenessOutcome {
    pub per_target: Vec<LivenessTargetResult>,
    pub verdict: LivenessVerdict,
    pub total_elapsed_ms: u64,
}

/// Probe parameters. `retries` = number of PARALLEL ROUNDS (each round fans
/// out to every target concurrently, bounded by `timeout`), so total probe
/// latency is bounded by `retries * timeout` (2 rounds × 1500ms = 3s), never
/// `targets * retries * timeout` (sequential would be ~18s).
#[derive(Debug, Clone)]
pub struct LivenessConfig {
    pub targets: Vec<SocketAddr>,
    pub timeout: Duration,
    pub retries: u32,
}

/// Build a minimal legal DNS A-record query: 12-byte header (RD set,
/// QDCOUNT=1) + one single-label question of `type A, class IN`.
pub fn build_dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 1 + name.len() + 1 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD bit set (0x0100)
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    q.extend_from_slice(&[0u8, 0, 0, 0, 0, 0]); // ANCOUNT/NSCOUNT/ARCOUNT
    q.push(name.len() as u8); // single label length
    q.extend_from_slice(name.as_bytes());
    q.push(0); // root terminator
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS IN
    q
}

/// Core orchestration.  `run_target` is injected so tests script per-target
/// outcomes without real sockets.  It is invoked once per target per round,
/// concurrently within a round; the current round index is passed in as the
/// first argument (so a stub can index a `[round][target]` script table).
pub async fn probe<R, Fut>(
    cfg: &LivenessConfig,
    mut run_target: R,
) -> LivenessOutcome
where
    R: FnMut(usize, SocketAddr) -> Fut,
    Fut: std::future::Future<Output = TargetProbeResult> + Send + 'static,
{
    let started = std::time::Instant::now();
    let mut any_responded = false;
    let mut any_socket_error = false;
    let mut per_target: Vec<LivenessTargetResult> = cfg
        .targets
        .iter()
        .map(|target| LivenessTargetResult {
            target: *target,
            responded: false,
            elapsed_ms: None,
        })
        .collect();

    // always probe at least one round even if retries is misconfigured to 0
    let rounds = cfg.retries.max(1) as usize;
    for round in 0..rounds {
        let mut set = tokio::task::JoinSet::new();
        for (idx, target) in cfg.targets.iter().enumerate() {
            let target = *target;
            let fut = run_target(round, target); // FnMut borrow; returns Fut
            set.spawn(async move { (idx, fut.await) }); // Fut: Send + 'static
        }
        while let Some(result) = set.join_next().await {
            match result {
                Ok((idx, res)) => match res {
                    TargetProbeResult::Responded { elapsed } => {
                        any_responded = true;
                        per_target[idx].responded = true;
                        per_target[idx].elapsed_ms = Some(elapsed.as_millis() as u64);
                    }
                    TargetProbeResult::NoResponse => {}
                    TargetProbeResult::SocketError => {
                        any_socket_error = true;
                    }
                },
                Err(_) => {
                    // A spawned probe future panicked: classify as a socket/system
                    // fault (Unknown), never as silence — silence is what certifies
                    // Blocked, and a panic is not silence.
                    any_socket_error = true;
                }
            }
        }
        if any_responded {
            break; // early stop: reachable is proven
        }
    }

    let verdict = if any_responded {
        LivenessVerdict::Ok
    } else if any_socket_error {
        LivenessVerdict::Unknown // a socket fault cannot certify a firewall
    } else {
        LivenessVerdict::Blocked
    };

    LivenessOutcome {
        per_target,
        verdict,
        total_elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, PartialEq)]
    enum Script {
        Respond,
        Timeout,
        IoErr,
    }

    fn two_targets() -> [SocketAddr; 2] {
        ["10.0.0.1:53".parse().unwrap(), "10.0.0.2:53".parse().unwrap()]
    }

    /// Map a probe target back to its script index (test-only; full-string match).
    fn target_idx(target: SocketAddr) -> usize {
        match target {
            t if t.to_string() == "10.0.0.1:53" => 0,
            _ => 1,
        }
    }

    /// Row-major script table: cells[round * 2 + target].
    fn cell(cells: &[Script], round: usize, target: usize) -> Script {
        cells[round * 2 + target]
    }

    fn cfg_2(cells: &[Script]) -> LivenessConfig {
        LivenessConfig {
            targets: two_targets().to_vec(),
            timeout: Duration::from_millis(10),
            retries: (cells.len() / 2) as u32,
        }
    }

    /// Stub run_target: returns an owned future resolving to the scripted cell.
    /// `Box<dyn Future + Send + 'static>` owns everything it holds (the captured
    /// `Script` is `Copy`), so the erased future satisfies `probe`'s
    /// `Fut: Send + 'static` bound. The `+ 'a` limits only the stub closure's
    /// borrow of the script table, not the futures it returns.
    fn stub<'a>(
        cells: &'a [Script],
    ) -> impl FnMut(usize, SocketAddr)
           -> std::pin::Pin<
                Box<dyn std::future::Future<Output = TargetProbeResult> + Send + 'static>,
            >
           + 'a {
        |round, target| {
            let s = cell(cells, round, target_idx(target));
            Box::pin(async move {
                match s {
                    Script::Respond => TargetProbeResult::Responded {
                        elapsed: Duration::from_millis(1),
                    },
                    Script::Timeout => TargetProbeResult::NoResponse,
                    Script::IoErr => TargetProbeResult::SocketError,
                }
            })
        }
    }

    #[test]
    fn dns_query_is_well_formed() {
        let q = build_dns_a_query(0x1234, "a");
        // 12-byte header + question (1 len byte + "a" + 0 terminator + 2 type + 2 class)
        assert_eq!(q.len(), 19, "DNS A query for single-label 'a' is 19 bytes");
        // header
        assert_eq!(&q[0..2], &[0x12, 0x34], "transaction id");
        // RD bit set (0x0100 at bytes 2..4), QDCOUNT=1
        assert_eq!(q[2], 0x01, "RD bit");
        assert_eq!(q[3], 0x00, "flags high byte zero");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT == 1");
        assert_eq!(&q[6..12], &[0, 0, 0, 0, 0, 0], "ANCOUNT/NSCOUNT/ARCOUNT zero");
        // question
        assert_eq!(q[12], 1, "single label length 1");
        assert_eq!(q[13], b'a', "label byte 'a'");
        assert_eq!(q[14], 0, "name terminator");
        assert_eq!(&q[15..17], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&q[17..19], &[0x00, 0x01], "QCLASS IN");
    }

    #[tokio::test]
    async fn verdict_ok_on_single_response_stops_early() {
        // round 0: t0 silent, t1 responds -> Ok after round 0.
        // To PROVE round 1 never ran: cells[1][0] is Respond (it WOULD mark t0
        // responded if round 1 executed). Assert t0 stayed un-responded.
        let cells = [
            Script::Timeout, Script::Respond, // round 0
            Script::Respond, Script::Timeout, // round 1 (must NOT run)
        ];
        let outcome = probe(&cfg_2(&cells), stub(&cells)).await;
        assert_eq!(outcome.verdict, LivenessVerdict::Ok);
        assert!(outcome.per_target[1].responded);
        assert!(
            !outcome.per_target[0].responded,
            "round 1 was skipped, so t0's scripted round-1 respond never fired"
        );
    }

    #[tokio::test]
    async fn verdict_blocked_on_all_timeouts() {
        let cells = [Script::Timeout; 4]; // 2 rounds × 2 targets, all silent
        let outcome = probe(&cfg_2(&cells), stub(&cells)).await;
        assert_eq!(outcome.verdict, LivenessVerdict::Blocked);
        assert!(outcome.per_target.iter().all(|t| !t.responded));
    }

    #[tokio::test]
    async fn verdict_unknown_when_socket_error_without_any_response() {
        // All cells IoErr (no response anywhere): a socket fault is NOT proof of a firewall.
        let cells = [Script::IoErr; 4];
        let outcome = probe(&cfg_2(&cells), stub(&cells)).await;
        assert_eq!(outcome.verdict, LivenessVerdict::Unknown);
    }

    #[tokio::test]
    async fn nxdomain_style_response_still_counts_as_reachable() {
        // A single Responded cell (mock does not parse the answer body) -> Ok.
        let cells = [Script::Timeout, Script::Respond, Script::Timeout, Script::Timeout];
        let outcome = probe(&cfg_2(&cells), stub(&cells)).await;
        assert_eq!(outcome.verdict, LivenessVerdict::Ok);
    }

    #[tokio::test]
    async fn panicked_probe_future_maps_to_unknown_not_blocked() {
        // A run_target whose future panics must be classified Unknown (socket/system
        // fault), never Blocked (firewall proof).  Use a fresh socket per target so
        // no real network is touched; the panic is injected at await time.
        let targets: Vec<SocketAddr> =
            ["10.9.9.1:53".parse().unwrap(), "10.9.9.2:53".parse().unwrap()].to_vec();
        let cfg = LivenessConfig {
            targets,
            timeout: Duration::from_millis(10),
            retries: 1,
        };
        let outcome = probe(&cfg, |_round, _target| {
            Box::pin(async move { panic!("injected probe panic") })
        })
        .await;
        assert_eq!(
            outcome.verdict,
            LivenessVerdict::Unknown,
            "a panicked probe is a system fault, not firewall proof"
        );
        assert!(
            outcome.per_target.iter().all(|t| !t.responded),
            "no target marked responded"
        );
    }
}
