include!("tests/part01a.rs");
include!("tests/part01b.rs");
include!("tests/part02a.rs");
include!("tests/part02b.rs");
include!("tests/part03a.rs");
include!("tests/part03b.rs");
include!("tests/part04a.rs");
include!("tests/part04b.rs");
include!("tests/part05a.rs");
include!("tests/part05b.rs");
include!("tests/part06a.rs");
include!("tests/part06b.rs");
include!("tests/part07.rs");
include!("tests/part08.rs");
include!("tests/part09.rs");
include!("tests/part10.rs");
include!("tests/part11.rs");
include!("tests/part12.rs");
include!("tests/part13.rs");
include!("tests/part14.rs");
include!("tests/part15.rs");
include!("tests/part16.rs");
include!("tests/part17.rs");
include!("tests/part18.rs");
include!("tests/part19.rs");
include!("tests/room_connectivity.rs");

#[path = "tests/history_contention.rs"]
mod history_contention;

#[path = "tests/direct_first.rs"]
mod direct_first;

#[path = "tests/capabilities.rs"]
mod capabilities;

#[path = "tests/traversal_context.rs"]
mod traversal_context;

#[path = "tests/candidate_validation_handover.rs"]
mod candidate_validation_handover;

#[path = "tests/capability_publication.rs"]
mod capability_publication;

#[path = "tests/b28_direct_commit_sequence.rs"]
mod b28_direct_commit_sequence;

#[path = "tests/relay_only_diagnostics.rs"]
mod relay_only_diagnostics;

#[path = "tests/peer_update_resources.rs"]
mod peer_update_resources;

#[path = "tests/heartbeat_metadata.rs"]
mod heartbeat_metadata;

#[path = "tests/emit_preparation_logging.rs"]
mod emit_preparation_logging;
#[path = "tests/path_selection_logging.rs"]
mod path_selection_logging;

#[cfg(unix)]
#[path = "tests/epoch_lock_callers.rs"]
mod epoch_lock_callers;

#[cfg(unix)]
#[path = "tests/relay_admission_reader.rs"]
mod relay_admission_reader;

#[cfg(unix)]
#[path = "tests/kernel_read_view.rs"]
mod kernel_read_view;

#[cfg(unix)]
#[path = "tests/authenticated_endpoint_learning.rs"]
mod authenticated_endpoint_learning;

#[cfg(unix)]
#[path = "tests/kernel_read_retention.rs"]
mod kernel_read_retention;
