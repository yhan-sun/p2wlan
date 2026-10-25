//! Actual metadata mutexes only; no fabricated KernelRead, Full or owner.
use super::super::{expected, selection};
use super::*;

#[tokio::test]
async fn window_metadata_owner_never_occupies_the_original_single_try_input_registry() {
    let (setup, _parent) = digest_scope().await;
    {
        let _window = setup.session.window_commands.try_lock().unwrap();
        assert!(setup.session.state.try_original_read_lock(23).is_ok());
        assert!(setup.session.try_source_metadata_versions().is_err());
    }
    assert!(setup.session.try_source_metadata_versions().is_ok());
    digest_no_credit(&setup.session);
}

#[tokio::test]
async fn published_selection_keeps_exact_original_plan_arc_and_producer_fences() {
    let (first, _first_parent) = digest_scope().await;
    let (other, _other_parent) = digest_scope().await;
    let expected = expected::prepare(&first.session, [0x22; 16]).unwrap();
    let foreign = expected::prepare(&other.session, [0x22; 16]).unwrap();
    let _window = first.session.window_commands.try_lock().unwrap();
    let selected = selection::current_published_source(&expected, &first.session.sources).unwrap();
    assert!(Arc::ptr_eq(&selected.plan, &expected.plan));
    assert!(matches!(
        selection::current_published_source(&foreign, &first.session.sources),
        Err(CaptureFailure::InvalidPlan)
    ));
    drop(_window);
    digest_no_credit(&first.session);
    digest_no_credit(&other.session);
}

#[tokio::test]
async fn source_completion_versions_fence_each_partition_without_an_even_parity_alias() {
    let (setup, _parent) = digest_scope().await;
    let before = setup.session.try_source_metadata_versions().unwrap();
    {
        let _input = setup.session.state.try_lock().unwrap();
        let _window = setup.session.window_commands.try_lock().unwrap();
        assert!(setup.session.try_source_metadata_versions().is_err());
    }
    let after = setup.session.try_source_metadata_versions().unwrap();
    assert_eq!(after, (before.0 + 2, before.1 + 2, before.2));
    digest_no_credit(&setup.session);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_window_installation_uses_same_canonical_cell_while_input_registry_is_held() {
    let (setup, _parent) = digest_scope().await;
    let wire = super::expected::current_wire(&setup.session, 1_000_000_000);
    let state = setup.session.state.try_lock().unwrap();
    setup
        .session
        .observe_original_write_window(wire)
        .await
        .unwrap();
    let expected = expected::prepare(&setup.session, [0x22; 16]).unwrap();
    let published = selection::current_published_source(&expected, &setup.session.sources).unwrap();
    let from_read = state.flows[0].requests[0]
        .original_write_window
        .as_ref()
        .unwrap();
    assert!(std::ptr::eq(
        from_read,
        published.requests[0].window.as_ref().unwrap()
    ));
    assert!(!from_read.native_os_write_verified && !from_read.canonical_current_owner_verified);
    drop(state);
    digest_no_credit(&setup.session);
}
