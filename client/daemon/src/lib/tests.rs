include!("tests/part01a.rs");
include!("tests/part01c.rs");
include!("tests/part01b.rs");
include!("tests/part02a.rs");
include!("tests/part02b.rs");
include!("tests/part03.rs");
include!("tests/part04.rs");
include!("tests/part05.rs");
include!("tests/part06.rs");
include!("tests/part07.rs");
include!("tests/business_budget.rs");
include!("tests/mobile_lifecycle_evidence.rs");
// The exact-path acceptance fixture deliberately names every generation,
// validation, socket and outer-family dimension in one test-only constructor.
// Its helper carries the test-only Clippy exception locally, leaving include!
// attribute-clean for workspace-wide `-D warnings` validation.
include!("tests/dplpmtud_final_acceptance.rs");
