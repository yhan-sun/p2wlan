use super::*;

#[test]
fn revoked_write_boundary_permit_rejects_late_dequeue() {
    let permit = RelayWriteBoundaryPermit::new();
    let registration_called = std::sync::atomic::AtomicBool::new(false);
    permit.revoke();

    assert!(!permit.commit(|| {
        registration_called.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    }));
    assert!(
        !registration_called.load(std::sync::atomic::Ordering::SeqCst),
        "a command dequeued after its deadline must not register an expectation"
    );
}

#[test]
fn deadline_revoke_waits_for_inflight_registration_before_exact_cancel() {
    let permit = RelayWriteBoundaryPermit::new();
    let hook_permit = permit.clone();
    let registered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let registered_in_hook = Arc::clone(&registered);
    let (hook_started_tx, hook_started_rx) = std::sync::mpsc::channel();
    let (release_hook_tx, release_hook_rx) = std::sync::mpsc::channel();
    let hook = std::thread::spawn(move || {
        hook_permit.commit(|| {
            hook_started_tx.send(()).unwrap();
            release_hook_rx.recv().unwrap();
            registered_in_hook.store(true, std::sync::atomic::Ordering::SeqCst);
            true
        })
    });
    hook_started_rx.recv().unwrap();

    let registered_at_timeout = Arc::clone(&registered);
    let (revoke_started_tx, revoke_started_rx) = std::sync::mpsc::channel();
    let (revoke_done_tx, revoke_done_rx) = std::sync::mpsc::channel();
    let revoker = std::thread::spawn(move || {
        revoke_started_tx.send(()).unwrap();
        permit.revoke();
        // Models the timeout branch's exact expectation cancellation,
        // which runs only after revoke has synchronized with the hook.
        registered_at_timeout.store(false, std::sync::atomic::Ordering::SeqCst);
        revoke_done_tx.send(()).unwrap();
    });
    revoke_started_rx.recv().unwrap();
    assert!(
        revoke_done_rx
            .recv_timeout(Duration::from_millis(30))
            .is_err(),
        "revoke must not race past an in-flight manager registration"
    );

    release_hook_tx.send(()).unwrap();
    assert!(hook.join().unwrap());
    revoke_done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("revoke must finish after registration releases the permit");
    revoker.join().unwrap();
    assert!(
        !registered.load(std::sync::atomic::Ordering::SeqCst),
        "exact cancellation after synchronized revoke must remove the just-registered entry"
    );
}
