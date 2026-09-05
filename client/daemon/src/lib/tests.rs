#![allow(clippy::too_many_arguments)]
// The daemon's test-only acceptance fixtures deliberately enumerate every
// independent path, generation, validation and socket identity dimension.
// Keep this exception inside the test module: production code remains under
// workspace-wide `-D warnings`, while exact fixture call sites stay explicit.

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
include!("tests/dplpmtud_final_acceptance.rs");
