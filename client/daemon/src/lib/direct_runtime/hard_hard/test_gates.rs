#[cfg(test)]
struct HardHardResponderMeasurementGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
    completed: tokio::sync::Notify,
}

#[cfg(test)]
struct HardHardResponderMeasurementGateCompletion(Option<Arc<HardHardResponderMeasurementGate>>);

#[cfg(test)]
impl Drop for HardHardResponderMeasurementGateCompletion {
    fn drop(&mut self) {
        if let Some(gate) = self.0.take() {
            gate.completed.notify_one();
        }
    }
}

#[cfg(test)]
static HARD_HARD_RESPONDER_MEASUREMENT_GATE: std::sync::LazyLock<
    std::sync::Mutex<Option<Arc<HardHardResponderMeasurementGate>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
fn install_hard_hard_responder_measurement_gate_for_test() -> Arc<HardHardResponderMeasurementGate>
{
    let gate = Arc::new(HardHardResponderMeasurementGate {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        completed: tokio::sync::Notify::new(),
    });
    *HARD_HARD_RESPONDER_MEASUREMENT_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(gate.clone());
    gate
}

#[cfg(test)]
async fn pause_hard_hard_responder_after_measurement_for_test(
) -> HardHardResponderMeasurementGateCompletion {
    let gate = HARD_HARD_RESPONDER_MEASUREMENT_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(gate) = &gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
    HardHardResponderMeasurementGateCompletion(gate)
}

#[cfg(test)]
struct HardHardInitiatorResponseGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static HARD_HARD_INITIATOR_RESPONSE_GATE: std::sync::Mutex<
    Option<Arc<HardHardInitiatorResponseGate>>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
fn install_hard_hard_initiator_response_gate_for_test() -> Arc<HardHardInitiatorResponseGate> {
    let gate = Arc::new(HardHardInitiatorResponseGate {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    *HARD_HARD_INITIATOR_RESPONSE_GATE.lock().unwrap() = Some(gate.clone());
    gate
}

#[cfg(test)]
async fn pause_hard_hard_initiator_response_for_test() {
    let gate = HARD_HARD_INITIATOR_RESPONSE_GATE.lock().unwrap().take();
    if let Some(gate) = gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
}
