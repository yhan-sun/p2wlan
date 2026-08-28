/// Legacy NAT classifier: the pre-R1 five-substring heuristic on the raw
/// `nat_type`.
///
/// This is byte-for-byte the body of the historical
/// `PeerConnection::remote_nat_requires_port_scatter` (candidates.rs).  R1
/// keeps it as the fallback for any label that does not parse as a
/// structured `p2:`/`p2v2:` hint (bare `"symmetric"`, empty, or corrupted),
/// so a new client's behavior on those inputs is provably identical to the
/// old client's.  Do not "clean up" these substrings: the wide
/// `address_or_port_dependent` match is exactly what makes the legacy
/// classifier a superset that the structured decision restates, and the
/// snapshot / structural regression tests below depend on these tokens
/// being unchanged.
fn legacy_nat_classifier(nat_type: &str) -> bool {
    let nat_type = nat_type.trim().to_ascii_lowercase();
    nat_type.contains("address_or_port_dependent")
        || nat_type.contains("symmetric")
        || nat_type.contains("a=linear")
        || nat_type.contains("a=random")
        || nat_type.contains("a=blocked")
}

/// Decide whether the remote peer requires bounded port scattering.
///
/// R1: parse the peer's `nat_type` into a structured NAT hint and apply the
/// `m=`/`a=`/`f=` predicate.  `f=`/`h=` come from the new `p2v2:` label; an
/// old `p2:` label simply has `f`/`h == Unknown`.
///
/// Conservative invariants (PROVEN in the tests, not merely asserted):
/// - `f == Unknown` — the R1-typical case, since active filtering probing is
///   R1b — leaves the decision byte-identical to the legacy classifier.
/// - The only f-axis term is `f == AddressOrPortDependent`, and it is a
///   restatement of the legacy *wide* `contains("address_or_port_dependent")`:
///   any well-formed label whose `f` token is that substring already scatters
///   under legacy, so the f term can never newly enable scatter in R1 (it is
///   the lever R1b's per-axis logic will act on, not a behavior change now).
/// - `f == Unknown` must never *widen* scatter relative to legacy: unknown is
///   never a reason to scatter more.
///
/// Exposed (not `pub(crate)`) so the CLI can render the peer's NAT hint with
/// the *same* scatter verdict the daemon acts on — a single source of truth,
/// no duplicated decision logic in the display path.
pub fn scatter_decision(nat_type: &str) -> bool {
    let raw = nat_type.trim().to_ascii_lowercase();
    let hint = p2pnet_nat::parse_nat_hint(&raw);
    if !hint.parsed {
        return legacy_nat_classifier(&raw);
    }
    let base = hint.mapping == p2pnet_nat::MappingBehavior::AddressOrPortDependent
        || matches!(
            hint.allocation,
            p2pnet_nat::NatAllocation::Linear
                | p2pnet_nat::NatAllocation::Random
                | p2pnet_nat::NatAllocation::Blocked
        );
    base
        || hint.filtering == p2pnet_nat::FilteringBehavior::AddressOrPortDependent
}

/// Whether a structured peer profile explicitly reports high-entropy/random
/// port allocation.
///
/// Unlike `scatter_decision`, this deliberately has no legacy substring
/// fallback: a bare `symmetric` label does not contain enough evidence to
/// discard an advertised prediction window.  Only the authenticated
/// structured `a=random` profile authorizes the immediate birthday lane and
/// vetoes peer-signaled predicted candidates.
fn random_allocation_decision(nat_type: &str) -> bool {
    let hint = p2pnet_nat::parse_nat_hint(nat_type);
    hint.parsed && hint.allocation == p2pnet_nat::NatAllocation::Random
}

#[cfg(test)]
mod nat_hint_tests {
    use super::*;
    use p2pnet_nat::{FilteringBehavior as FB, MappingBehavior as MB};

    /// Legacy snapshot regression (new client consumes old `p2:` labels +
    /// bare words): the R1 decision must equal the pre-R1 classifier on every
    /// input, byte-for-byte.  The three `address_or_port_dependent` labels
    /// are the same fixtures the daemon integration tests use.
    #[test]
    fn scatter_decision_matches_legacy_on_old_label_snapshot() {
        let old_labels = [
            "p2:m=address_or_port_dependent;a=linear;d=32;c=90",
            "p2:m=address_or_port_dependent;a=random;d=32;c=90",
            "p2:m=endpoint_independent;a=stable;d=0;c=70",
            "p2:m=open;a=stable;d=?;c=40",
            "p2:m=unknown;a=unknown;d=?;c=0",
            "p2:m=blocked;a=blocked;d=?;c=60",
            "p2:m=endpoint_independent;a=stable;d=12;c=85",
            "symmetric",
            "address_or_port_dependent",
            "Confluence",
            "Unknown",
            "",
            "a=linear",
            "nattype=weird",
        ];
        for label in old_labels {
            assert_eq!(
                scatter_decision(label),
                legacy_nat_classifier(label),
                "new client on input diverged from legacy: {label:?}"
            );
        }
    }

    /// Structural no-regression (stronger than a snapshot): for EVERY
    /// (mapping, allocation, filtering) triple — including synthetic combos
    /// R1's static inference cannot produce, e.g. `m=EIM` + `f=apd` — emit
    /// the `p2v2` label and assert the R1 decision equals the legacy
    /// classifier on that same label.  This proves the new code path cannot
    /// move the decision for any well-formed input: zero regression is a
    /// structural guarantee, not an observed one.
    #[test]
    fn scatter_decision_is_structurally_invariant_to_f_axis() {
        let mappings = [
            ("unknown", MB::Unknown),
            ("blocked", MB::UdpBlocked),
            ("open", MB::OpenInternet),
            ("endpoint_independent", MB::EndpointIndependent),
            ("address_or_port_dependent", MB::AddressOrPortDependent),
        ];
        let allocations = ["unknown", "linear", "stable", "random", "blocked"];
        let filterings = [
            ("unknown", FB::Unknown),
            ("endpoint_independent", FB::EndpointIndependent),
            ("likely_endpoint_independent", FB::LikelyEndpointIndependent),
            ("address_dependent", FB::AddressDependent),
            ("address_or_port_dependent", FB::AddressOrPortDependent),
            ("udp_blocked", FB::UdpBlocked),
        ];
        for (mtok, mb) in mappings {
            for atok in allocations {
                for (ftok, fb) in filterings {
                    let label = format!(
                        "p2v2:m={mtok};a={atok};d=?;c=0;f={ftok};h=unknown"
                    );
                    assert_eq!(
                        scatter_decision(&label),
                        legacy_nat_classifier(&label),
                        "structured decision moved for (m={mb:?}, a={atok}, f={fb:?})"
                    );
                }
            }
        }
    }

    /// The f-axis term is a restatement of the legacy wide match: even the
    /// synthetic `m=EIM, a=stable, f=apd` label — the first combo where the
    /// f term would look like a "new enable" — already scatters under legacy
    /// because the label contains the `address_or_port_dependent` substring
    /// (in the f field).  So `f == apd` is provably a no-op in R1.
    #[test]
    fn f_apd_stable_is_a_legacy_restatement() {
        let label = "p2v2:m=endpoint_independent;a=stable;d=0;c=70;f=address_or_port_dependent;h=unknown";
        assert!(
            legacy_nat_classifier(label),
            "legacy's wide contains already scatters this label, so f==apd is provably a no-op in R1"
        );
        assert!(scatter_decision(label));
    }

    /// `a=stable` + `f=unknown` is locked to NON-scatter: an unknown
    /// filtering never widens scatter.
    #[test]
    fn stable_unknown_never_scatters() {
        let label = "p2v2:m=endpoint_independent;a=stable;d=0;c=70;f=unknown;h=unknown";
        assert!(!scatter_decision(label));
    }

    /// `f=unknown` reproduces legacy exactly per (m, a) combo (locks the
    /// "f==unknown == old behavior" contract item by item).
    #[test]
    fn f_unknown_matches_legacy_per_combo() {
        let labels = [
            "p2v2:m=address_or_port_dependent;a=linear;d=32;c=90;f=unknown;h=unknown",
            "p2v2:m=endpoint_independent;a=stable;d=0;c=70;f=unknown;h=unknown",
            "p2v2:m=open;a=stable;d=?;c=40;f=unknown;h=unknown",
            "p2v2:m=unknown;a=random;d=?;c=20;f=unknown;h=unknown",
            "p2v2:m=unknown;a=unknown;d=?;c=0;f=unknown;h=unknown",
        ];
        for label in labels {
            assert_eq!(
                scatter_decision(label),
                legacy_nat_classifier(label),
                "f=unknown diverged for {label:?}"
            );
        }
    }

    /// Corrupted / non-prefix inputs fall back to the legacy classifier on the
    /// raw string — never panic, never change behavior.
    #[test]
    fn corrupted_inputs_fall_back_to_legacy() {
        for label in ["p2v2:garbage", "p2:!!!", "totally not a label a=random", "   "] {
            assert_eq!(
                scatter_decision(label),
                legacy_nat_classifier(label),
                "corrupted input did not fall back: {label:?}"
            );
        }
    }

    #[test]
    fn only_structured_random_allocation_authorizes_random_lane() {
        assert!(random_allocation_decision(
            "p2v2:m=address_or_port_dependent;a=random;d=?;c=90;f=unknown;h=unknown"
        ));
        assert!(!random_allocation_decision(
            "p2v2:m=address_or_port_dependent;a=linear;d=2;c=90;f=unknown;h=unknown"
        ));
        assert!(!random_allocation_decision("symmetric"));
        assert!(!random_allocation_decision(
            "not-a-profile a=random"
        ));
    }
}
