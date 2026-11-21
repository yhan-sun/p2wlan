//! A manager keeps its real default bootstrap Config while the actual TUN,
//! minter and native entrance use different resolved runtime addresses.
use super::*;
use crate::overlay_requests::OverlayCreditStale as Stale;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum RuntimeVipCase {
    FreshMarkerOnce,
    WrongRequestDestination,
}

#[derive(Clone, Debug, Default)]
struct VerificationMarker {
    message: String,
    native: Option<bool>,
}

impl Visit for VerificationMarker {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "native_original_ack" {
            self.native = Some(value);
        }
    }
}

#[derive(Clone, Default)]
struct VerificationCapture(Arc<std::sync::Mutex<Vec<VerificationMarker>>>);

impl<S: Subscriber> tracing_subscriber::Layer<S> for VerificationCapture {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut marker = VerificationMarker::default();
        event.record(&mut marker);
        if marker.message.contains("overlay_payload_verified") {
            self.0.lock().unwrap().push(marker);
        }
    }
}

impl VerificationCapture {
    fn markers(&self) -> Vec<VerificationMarker> {
        self.0.lock().unwrap().clone()
    }
}

fn require_marker(
    marker: &VerificationMarker,
    request: &CanonicalOverlayRequest,
    source_vip: &str,
    ingress: &str,
) -> Check {
    require(
        marker.native == Some(true)
            && marker
                .message
                .contains(&format!("peer={}", request.peer_id))
            && marker.message.contains(&format!("src_ip={source_vip}"))
            && marker.message.contains(&format!("seq={} ", request.seq))
            && marker
                .message
                .contains(&format!("nonce={:#x} ", request.nonce))
            && marker.message.contains(&format!("ingress={ingress} ")),
        "verification marker did not name the actual committed receipt/source/identity",
    )
}

async fn fresh_marker_once(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
    capture: &VerificationCapture,
) -> Check {
    let (request, echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    let ingress = match path {
        PathKind::Direct => "direct".to_string(),
        PathKind::Relay => format!(
            "relay:{}",
            ack.source
                .as_ref()
                .and_then(|source| source.relay_endpoint())
                .ok_or("actual Relay ACK lacks its original endpoint")?
        ),
    };
    require(
        capture.markers().is_empty()
            && !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == 0
            && b.stats.verified_round_trips == 0,
        "REQUEST/ordinary ingress emitted verification before a native ACK receipt",
    )?;
    let mut without_source = ack.clone();
    without_source.source = None;
    native_handler(a, without_source, budget).await?;
    require(
        capture.markers().is_empty()
            && !request.native_ack_credited_for_test()
            && a.stats.received_valid == 0
            && a.stats.verified_round_trips == 0,
        "source-withheld ACK emitted verification or consumed original once",
    )?;
    native_fresh(a, &request, ack, path, budget).await?;
    let markers = capture.markers();
    require(
        markers.len() == 1,
        "one Fresh ACK must emit one verification marker",
    )?;
    require_marker(&markers[0], &request, b.vip, &ingress)?;
    let valid = a.stats.received_valid;
    let rounds = a.stats.verified_round_trips;
    // The original sealed echo is encrypted again with a new real counter;
    // this is not a ciphertext replay or a fabricated ACK source.
    let duplicate = repeat_actual_echo(a, b, echo, path, budget).await?;
    require(
        commit(a, &request, &duplicate)? == OverlayCreditOutcome::AlreadyCommitted,
        "actual duplicate changed the canonical once result",
    )?;
    native_handler(a, duplicate, budget).await?;
    require(
        capture.markers().len() == 1
            && a.stats.received_valid == valid
            && a.stats.verified_round_trips == rounds,
        "duplicate native ACK inflated verification/roundtrips",
    )?;
    let (next, _echo, next_ack) = original_request_and_echo(a, b, path, budget).await?;
    require(
        !Arc::ptr_eq(&request, &next) && request.nonce != next.nonce,
        "new runtime-VIP positive reused the previous canonical",
    )?;
    native_fresh(a, &next, next_ack, path, budget).await?;
    let markers = capture.markers();
    require(
        markers.len() == 2 && a.stats.verified_round_trips == rounds + 1,
        "distinct actual canonical did not add exactly one native verification",
    )?;
    require_marker(&markers[1], &next, b.vip, &ingress)
}

async fn wrong_request_destination(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
    capture: &VerificationCapture,
) -> Check {
    let mut rejected_requests = Vec::new();
    for destination in ["10.20.0.1", "10.20.0.254"] {
        let (request, routed) = mint_actual(a, budget).await?;
        let ip = p2pnet_tun::Ipv4Packet::new(&routed.packet).map_err(|e| e.to_string())?;
        let payload = ip
            .payload()
            .get(8..)
            .ok_or("actual REQUEST UDP payload is missing")?;
        let mut raw = (*routed).clone();
        raw.packet = build_udp_overlay_packet(a.vip, destination, 39286, 39287, payload)
            .ok_or("wrong-destination REQUEST framing failed")?;
        raw.dst_ip = destination.to_string();
        let expected = raw.packet.clone();
        // A malformed destination is deliberately sent through the existing
        // untracked raw boundary. It cannot borrow the original canonical's
        // exact carriage/Full permission. The receiver/source still comes
        // from the actual reader and actual authorized key decrypt.
        let sent = budget
            .step(
                "original raw sender carries actual wrong-destination REQUEST",
                crate::network_outbound::send_original_slow_for_test(
                    RawRequestDelivery::from(raw),
                    &a.wireguard,
                    &a.peers,
                    a.peers.current_network_generation_sync(),
                    path == PathKind::Direct,
                    &a.udp,
                    &a.relay,
                    path == PathKind::Relay,
                ),
            )
            .await?;
        require(sent, "actual raw wrong-destination send failed")?;
        // Receive from the original authenticated WG feed. Its independent
        // DataPlane consumer must not write this wrong destination to TUN;
        // the later fresh loop retains the full actual TUN byte comparison.
        let received = actual_rx_delivery_without_tun(b, budget).await?;
        let parsed =
            OriginalOverlayAck::parse_request(&received.event.packet, &received.event.peer_id)
                .ok_or("actual wrong-destination decrypt lost REQUEST identity")?;
        require(
            received.event.packet == expected
                && parsed.local_vip == destination
                && parsed.local_vip != b.vip
                && parsed.nonce == request.nonce
                && parsed.seq == request.seq,
            "actual wrong-destination source/packet did not retain the intended identity",
        )?;
        let owners = b.sourced_owners();
        let outcome = budget
            .step(
                "runtime REQUEST entrance rejects actual wrong destination",
                handle_native_overlay_request(
                    received.event,
                    received.source,
                    &owners,
                    &b.udp,
                    &b.peers,
                    &b.controller,
                    b.vip,
                    true,
                    true,
                    &mut b.seen,
                    &mut b.stats,
                    &mut b.pending,
                ),
            )
            .await?;
        require(
            outcome
                == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Stale(
                    Stale::Identity,
                ))
                && b.seen.is_empty()
                && b.pending.is_empty()
                && b.stats.received_valid == 0
                && b.stats.verified_round_trips == 0
                && !request.native_ack_credited_for_test()
                && capture.markers().is_empty(),
            "wrong runtime destination gained echo, seen state, native credit or verification",
        )?;
        require(
            matches!(b.routed.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "wrong-destination REQUEST emitted an actual routed echo",
        )?;
        rejected_requests.push(request);
    }
    let (fresh, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    native_fresh(a, &fresh, ack, path, budget).await?;
    require(
        rejected_requests
            .iter()
            .all(|request| !request.native_ack_credited_for_test())
            && capture.markers().len() == 1,
        "fresh runtime destination resurrected rejected canonical credit/verification",
    )
}

pub(super) async fn exercise_runtime_vip(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: RuntimeVipCase,
    budget: Budget,
) -> Check {
    require(
        a.vip == "10.20.0.2" && b.vip == "10.20.0.3",
        "runtime-VIP controls must differ from both managers' real default bootstrap",
    )?;
    let capture = VerificationCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    async {
        match case {
            RuntimeVipCase::FreshMarkerOnce => {
                fresh_marker_once(a, b, path, budget, &capture).await
            }
            RuntimeVipCase::WrongRequestDestination => {
                wrong_request_destination(a, b, path, budget, &capture).await
            }
        }
    }
    .with_subscriber(subscriber)
    .await
}
