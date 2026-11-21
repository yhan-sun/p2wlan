//! Finite original REQUEST -> remote decrypt/echo -> local decrypt/ACK controls.
//! No OriginalSome/source, crypto success, physical Full, or once is fabricated.
//! All explicitly spawned fixture workers are owned and cancel+joined; the
//! RelayClient's native reader/writer handles remain private to that client.
use super::*;
use std::result::Result;

#[path = "original_ack_tests/fixture.rs"]
mod fixture;

use fixture::{
    exercise, exercise_bootstrap_runtime_vip, AckContentionCase, EchoCase, EchoContentionCase,
    IdentityCase, LifecycleCase, PathKind, RuntimeVipCase, Scenario,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_request_contention_retains_original_before_tun_echo(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::RequestContention(AckContentionCase::Current),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_request_contention_retains_original_before_tun_echo(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::RequestContention(AckContentionCase::Current),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_request_contention_session_replacement_rejects_old_source(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::RequestContention(AckContentionCase::SessionReplaced),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_request_contention_session_replacement_rejects_old_source(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::RequestContention(AckContentionCase::SessionReplaced),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_request_contention_cancellation_injects_no_echo() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::RequestContention(AckContentionCase::Cancelled),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_request_contention_cancellation_injects_no_echo() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::RequestContention(AckContentionCase::Cancelled),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_request_contention_stops_at_original_read_window() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::RequestContention(AckContentionCase::Deadline),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_request_contention_stops_at_original_read_window() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::RequestContention(AckContentionCase::Deadline),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_ack_contention_retains_original_once_then_new_request(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::AckContention(AckContentionCase::Current),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_ack_contention_retains_original_once_then_new_request(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::AckContention(AckContentionCase::Current),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_ack_contention_session_replacement_rejects_old_once(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::AckContention(AckContentionCase::SessionReplaced),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_ack_contention_session_replacement_rejects_old_once(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::AckContention(AckContentionCase::SessionReplaced),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_ack_contention_cancellation_preserves_original_once(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::AckContention(AckContentionCase::Cancelled),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_ack_contention_cancellation_preserves_original_once(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::AckContention(AckContentionCase::Cancelled),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_direct_native_ack_contention_stops_at_original_window() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::AckContention(AckContentionCase::Deadline),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_relay_native_ack_contention_stops_at_original_window() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::AckContention(AckContentionCase::Deadline),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_echo_direct_session_contention_retries_current_source_once() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::EchoContention(EchoContentionCase::Current),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_echo_relay_session_contention_retries_current_source_once() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::EchoContention(EchoContentionCase::Current),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_echo_direct_session_contention_then_replacement_rejects_old_source(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::EchoContention(EchoContentionCase::SessionReplaced),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_echo_relay_session_contention_then_replacement_rejects_old_source(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::EchoContention(EchoContentionCase::SessionReplaced),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_echo_direct_session_contention_preserves_delivery_cutoff() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::EchoContention(EchoContentionCase::Deadline),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_echo_relay_session_contention_preserves_delivery_cutoff() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::EchoContention(EchoContentionCase::Deadline),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_fresh_direct_original_request_echo_commits_native_once() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Fresh).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_fresh_relay_original_request_echo_commits_native_once() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Fresh).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_real_echo_duplicate_once_and_new_canonical_are_distinct() -> Result<(), String>
{
    exercise(PathKind::Direct, Scenario::DuplicateAndNew).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_real_echo_duplicate_once_and_new_canonical_are_distinct() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::DuplicateAndNew).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_ack_without_source_cannot_consume_then_actual_source_is_fresh(
) -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::MissingSource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_ack_without_source_cannot_consume_then_actual_source_is_fresh(
) -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::MissingSource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_native_handler_credits_only_the_actual_once_receipt() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::NativeHandler).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_native_handler_credits_only_the_actual_once_receipt() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::NativeHandler).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_final_try_lock_conflicts_release_without_consuming_once() -> Result<(), String>
{
    exercise(PathKind::Direct, Scenario::Contention).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_final_try_lock_conflicts_release_without_consuming_once() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Contention).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_session_replacement_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_session_replacement_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_session_counter_expiry_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::CounterExpiry),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_session_counter_expiry_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::CounterExpiry),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_generation_change_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_generation_change_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_peer_readd_rejects_old_lifecycle_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::RemoveReadd),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_peer_readd_rejects_old_lifecycle_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::RemoveReadd),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_quarantine_rejects_ack_then_new_request_is_fresh() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::Quarantine),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_quarantine_rejects_ack_then_new_request_is_fresh() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::Quarantine),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_publication_withdrawal_rejects_ack_then_new_owner_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::UdpOwnerWithdraw),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_pending_decrypt_cannot_inherit_its_promotion_then_new_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::PendingPromotion),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_pending_decrypt_cannot_inherit_its_promotion_then_new_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::PendingPromotion),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_original_fifteen_second_window_expires_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::OriginalWindow),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_original_fifteen_second_window_expires_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::OriginalWindow),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_actual_unfenced_slow_direct_full_stays_unknown_then_fenced_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::LegacyUnknown),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_other_canonical_ack_cannot_consume_wrong_once() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::OtherCanonicalAck),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_other_canonical_ack_cannot_consume_wrong_once() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::OtherCanonicalAck),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_foreign_wireguard_owner_cannot_borrow_original_sources(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::ForeignWireGuardOwner),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_foreign_wireguard_owner_cannot_borrow_original_sources(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::ForeignWireGuardOwner),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_enabled_room_owner_fails_closed_for_native_credit() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::RoomAuthority),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_enabled_room_owner_fails_closed_for_native_credit() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::RoomAuthority),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_ack_parser_corruption_is_rejected_without_credit() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::ParserCorruption),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_ack_parser_corruption_is_rejected_without_credit() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::ParserCorruption),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_queued_original_echo_rechecks_actual_session_before_send() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::EchoTransfer(EchoCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_queued_original_echo_rechecks_actual_session_before_send() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::EchoTransfer(EchoCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_queued_original_echo_rechecks_actual_generation_before_send(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::EchoTransfer(EchoCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_queued_original_echo_rechecks_actual_generation_before_send(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::EchoTransfer(EchoCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_queued_original_echo_rechecks_actual_publication_before_send(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::EchoTransfer(EchoCase::UdpOwnerWithdraw),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_previous_key_cannot_borrow_current_echo_then_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::PreviousReceive),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_previous_key_cannot_borrow_current_echo_then_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::PreviousReceive),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_actual_ack_before_observable_full_cannot_inherit_later_publication(
) -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::PublicationOrder).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_fresh_marker_once_and_source_rejection() -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::RuntimeVip(RuntimeVipCase::FreshMarkerOnce),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_wrong_request_destination_including_bootstrap_is_rejected(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::RuntimeVip(RuntimeVipCase::WrongRequestDestination),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_stale_generation_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_stale_session_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_fresh_marker_once_and_source_rejection() -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::RuntimeVip(RuntimeVipCase::FreshMarkerOnce),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_wrong_request_destination_including_bootstrap_is_rejected(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::RuntimeVip(RuntimeVipCase::WrongRequestDestination),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_stale_generation_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_stale_session_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_actual_asymmetric_direct_request_uses_verified_return_path_and_native_once(
) -> Result<(), String> {
    fixture::exercise_asymmetric_endpoint().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr209_actual_asymmetric_echo_rejects_revoked_and_compat_return_then_new_canonical_recovers(
) -> Result<(), String> {
    fixture::exercise_asymmetric_invalidation().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r00_actual_common_canonical_native_fresh_duplicate_and_new_request() -> Result<(), String>
{
    fixture::exercise_common_native().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r00_same_outer_common_client_replacement_rejects_old_ack_then_new_request_recovers(
) -> Result<(), String> {
    fixture::exercise_common_replacement().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr212_actual_request_on_other_socket_returns_on_verified_direct_and_native_once(
) -> Result<(), String> {
    fixture::exercise_asymmetric_receive_socket().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr212_other_socket_echo_rejects_revoked_return_then_new_canonical_recovers(
) -> Result<(), String> {
    fixture::exercise_asymmetric_receive_socket_invalidation().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr212_equal_remote_request_on_other_socket_uses_verified_return_and_native_once(
) -> Result<(), String> {
    fixture::exercise_equal_remote_distinct_socket().await
}
