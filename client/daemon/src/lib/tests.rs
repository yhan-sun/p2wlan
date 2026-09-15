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
#[path = "tests/daemon_e2e/mod.rs"]
mod daemon_e2e;

include!("tests/part04.rs");
include!("tests/part05.rs");
include!("tests/part06.rs");
#[path = "tests/synchronized_punch_e2e/mod.rs"]
mod synchronized_punch_e2e;

include!("tests/business_budget.rs");
include!("tests/mobile_lifecycle_evidence.rs");
include!("tests/dplpmtud_final_acceptance.rs");

// `lib/direct_runtime/hard_hard.rs` reaches this serialisation gate by
// absolute path; keep that path valid now that the fixture moved into a
// real module.
pub(crate) use synchronized_punch_e2e::HARD_HARD_E2E_SERIAL;

// `tests/business_budget.rs` and `tests/part05.rs` are still flat include!-ed
// files; they used these helpers through the old shared scope.
use daemon_e2e::{
    part03_establish_sessions, part03_outbound_transport, start_handshake_control_capture,
};
