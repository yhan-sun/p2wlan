use crate::{config::Config, Daemon};
use std::sync::Arc;

fn runtime_config(observe: bool) -> Config {
    let mut config = Config::generate_default("https://control.example.com", "resources").unwrap();
    config.network.manual = true;
    config.diagnostics.enabled = true;
    config.diagnostics.resource_capture = observe;
    config
}

#[tokio::test]
async fn runtime_resource_config_arms_actual_daemon_transport() {
    let mut config = serde_json::to_value(
        Config::generate_default("https://control.example.com", "resources").unwrap(),
    )
    .unwrap();
    config["network"]["manual"] = true.into();
    config["diagnostics"]["enabled"] = true.into();
    config["diagnostics"]["resource_capture"] = true.into();
    let daemon = Daemon::new(serde_json::from_value(config).unwrap());
    assert!(
        daemon.transport.resource_capture().is_some(),
        "explicit runtime opt-in never reached the actual daemon transport"
    );
    assert!(Arc::ptr_eq(
        daemon.transport.resource_capture().unwrap(),
        daemon.resource_capture.as_ref().unwrap().capture(),
    ));
}

#[tokio::test]
async fn runtime_resource_default_disabled_and_unexposed_configs_create_no_capture() {
    let mut legacy = serde_json::to_value(runtime_config(false)).unwrap();
    legacy["diagnostics"]
        .as_object_mut()
        .unwrap()
        .remove("resource_capture");
    let config: Config = serde_json::from_value(legacy).unwrap();
    assert!(!config.diagnostics.resource_capture);
    let daemon = Daemon::new(config);
    assert!(daemon.resource_capture.is_none());
    assert!(daemon.transport.resource_capture().is_none());
    assert!(!daemon.transport.accepts_request_carriage());
    assert!(matches!(
        daemon.outbound_rx,
        Some(crate::request_carriage::RawOutboundReceiver::Tracked(_))
    ));

    let mut unexposed = runtime_config(true);
    unexposed.diagnostics.enabled = false;
    let unexposed = Daemon::new(unexposed);
    assert!(unexposed.resource_capture.is_none());
    assert!(unexposed.transport.resource_capture().is_none());
}

#[tokio::test]
async fn runtime_resource_actual_daemon_dataplane_channel_preserves_bytes_capacity_and_no_binding()
{
    use crate::{control::PeerInfo, dataplane::DataPlane};
    use p2pnet_tun::{Ipv4Packet, MockTunDevice};
    for observe in [false, true] {
        let daemon = Daemon::new(runtime_config(observe));
        daemon
            .peers
            .add_peer(&PeerInfo {
                node_id: "resource-peer".into(),
                virtual_ip: "10.20.0.2".into(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let (tun, controller) = MockTunDevice::new_pair("resources", 1420, "10.20.0.1");
        let (mut plane, mut receiver, inbound) = DataPlane::new_bidirectional_for_daemon(
            tun,
            daemon.peers.clone(),
            false,
            daemon.transport.resource_capture().cloned(),
        );
        eprintln!(
            "runtime_resource_channel_layout {}",
            serde_json::json!({
                "observed":observe,"channel_capacity":1024,
                "legacy_element_bytes":std::mem::size_of::<crate::dataplane::OutboundPacket>(),
                "tracked_element_bytes":std::mem::size_of::<crate::request_carriage::RawRequestDelivery>(),
                "capture_bytes":std::mem::size_of::<crate::dataplane_resources::ResourceCapture>(),
                "allocator_or_container_bytes_measured":false,
            })
        );
        assert_eq!(inbound.max_capacity(), 1024);
        assert_eq!(plane.resource_capture().is_some(), observe);
        assert!(matches!(
            &receiver,
            crate::request_carriage::RawOutboundReceiver::Tracked(_)
        ));
        let original = Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            1,
            1,
            b"real-runtime-channel",
        );
        let mut scratch = [0; 2048];
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            controller.inject(original.clone()).await.unwrap();
            plane.read_and_route_once(&mut scratch).await.unwrap();
        })
        .await
        .unwrap();
        let queued = daemon.resource_capture.as_ref().map(|run| run.readout());
        let packet = receiver.try_recv().unwrap();
        assert_eq!(packet.payload(), original);
        assert_eq!(packet.packet.is_empty(), !observe);
        assert!(
            packet.binding().is_none(),
            "observation must not mint original-request authority"
        );
        if let Some(queued) = queued {
            assert!(Arc::ptr_eq(
                plane.resource_capture().unwrap(),
                daemon.transport.resource_capture().unwrap()
            ));
            let owners = &queued["capture"]["observed_owner_residency"];
            assert_eq!(owners["total"]["live_buffers"], 1);
            assert_eq!(
                owners["total"]["capacity_bytes"],
                packet.packet.capacity() as u64
            );
            assert_eq!(owners["stages"][1]["stage"], "raw_channel");
            assert_eq!(owners["stages"][1]["totals"]["live_buffers"], 1);
            assert_eq!(owners["whole_pipeline_bytes_measured"], false);
            assert!(queued.to_string().len() <= 16 * 1024);
        }
        drop(packet);
        if let Some(run) = &daemon.resource_capture {
            assert_eq!(
                run.capture()
                    .residency_snapshot()
                    .total
                    .unwrap()
                    .live_buffers,
                0
            );
        }
    }
}

#[test]
fn runtime_resource_owner_drop_finishes_capture_but_existing_message_still_drains() {
    use crate::dataplane_resources::{ResidencyLease, ResidencyStage, RuntimeResourceCapture};
    let run = RuntimeResourceCapture::from_config(&runtime_config(true).diagnostics).unwrap();
    let capture = run.capture().clone();
    let bytes = vec![7; 32];
    let lease = ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &bytes).unwrap();
    let old_id = run.readout()["capture"]["id"].as_str().unwrap().to_owned();
    drop(run);
    assert!(capture.is_finished());
    assert!(ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &bytes).is_none());
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 1);
    drop(lease);
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
    let next = RuntimeResourceCapture::from_config(&runtime_config(true).diagnostics).unwrap();
    assert_ne!(old_id, next.readout()["capture"]["id"]);
}

#[test]
fn runtime_resource_fixed_producer_read_workload_reports_actual_availability() {
    use crate::dataplane_resources::{ResidencyLease, ResidencyStage, RuntimeResourceCapture};
    use std::sync::Barrier;
    let run = RuntimeResourceCapture::from_config(&runtime_config(true).diagnostics).unwrap();
    let start = Arc::new(Barrier::new(3));
    let (mut coherent, mut unavailable) = (0, 0);
    let mut read_times = Vec::with_capacity(256);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let start = start.clone();
            let capture = run.capture().clone();
            scope.spawn(move || {
                start.wait();
                for _ in 0..2048 {
                    let mut bytes = Vec::with_capacity(128);
                    bytes.resize(64, 0x45);
                    let mut lease =
                        ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &bytes)
                            .unwrap();
                    lease.relocate(ResidencyStage::DetachedRaw, &bytes);
                    drop(lease);
                    drop(bytes);
                }
            });
        }
        start.wait();
        for _ in 0..256 {
            let began = std::time::Instant::now();
            let value = run.readout();
            read_times.push(began.elapsed().as_nanos());
            let owner = &value["capture"]["observed_owner_residency"];
            if owner["coherent"] == true {
                coherent += 1;
                assert_eq!(owner["valid"], true);
            } else {
                unavailable += 1;
                assert!(owner["total"].is_null());
            }
        }
    });
    assert_eq!(coherent + unavailable, 256);
    assert_eq!(
        run.capture()
            .residency_snapshot()
            .total
            .unwrap()
            .live_buffers,
        0
    );
    eprintln!(
        "runtime_resource_availability {}",
        serde_json::json!({
            "producers":2,"owners_per_producer":2048,"reads":256,
            "coherent":coherent,"unavailable":unavailable,"read_ns":read_times,
            "readout_serialization_and_network_io_timed":false,
            "product_network_rounds":0,"performance_gain_claimed":false,
        })
    );
}
