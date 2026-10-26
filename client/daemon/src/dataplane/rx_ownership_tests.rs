//! Hold the original packet pump at the real TUN write, without a bridge queue.
use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane_resources::{ResidencyStage, ResourceCapture};
use p2pnet_tun::{Ipv4Packet, MockTunDevice};
use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, PartialEq)]
enum WriteResult {
    Full,
    Short,
    Closed,
    Cancel,
}

struct GateTun {
    inner: MockTunDevice,
    entered: Option<oneshot::Sender<usize>>,
    release: Option<oneshot::Receiver<()>>,
    result: WriteResult,
    deadline: tokio::time::Instant,
}

// The same object-safe signatures as VirtualInterface's async-trait expansion.
impl VirtualInterface for GateTun {
    fn read<'a, 'b, 'c>(
        &'a mut self,
        buf: &'b mut [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(self.inner.read(buf))
    }
    fn write<'a, 'b, 'c>(
        &'a mut self,
        buf: &'b [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            self.entered.take().unwrap().send(buf.len()).unwrap();
            tokio::time::timeout_at(self.deadline, self.release.take().unwrap())
                .await
                .map_err(|_| p2pnet_tun::Error::DeviceClosed)?
                .map_err(|_| p2pnet_tun::Error::DeviceClosed)?;
            match self.result {
                WriteResult::Full => self.inner.write(buf).await,
                WriteResult::Short => Ok(buf.len() - 1),
                WriteResult::Closed | WriteResult::Cancel => Err(p2pnet_tun::Error::DeviceClosed),
            }
        })
    }
    fn take_last_read_context(&mut self) -> Option<p2pnet_tun::PacketReadContext> {
        self.inner.take_last_read_context()
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn mtu(&self) -> u32 {
        self.inner.mtu()
    }
    fn address(&self) -> &str {
        self.inner.address()
    }
    fn is_up(&self) -> bool {
        self.inner.is_up()
    }
}

async fn held_tun_write(normalize: bool, result: WriteResult) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let capture = ResourceCapture::new([0xe5; 16]);
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "default").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            node_id: "rx-peer".into(),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let (inner, controller) = MockTunDevice::new_pair("rx-owner0", 1420, "10.20.0.1");
    let (entered, mut arrival) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let tun = GateTun {
        inner,
        entered: Some(entered),
        release: Some(wait),
        result,
        deadline,
    };
    let (mut plane, _outbound, inbound) =
        DataPlane::new_bidirectional_for_daemon(tun, peers.clone(), false, Some(capture.clone()));
    plane = plane.with_overlay_cidr("10.20.0.0/16");
    assert_eq!(inbound.max_capacity(), 1024);
    let source = if normalize {
        Ipv4Addr::new(100, 84, 190, 40)
    } else {
        Ipv4Addr::new(10, 20, 0, 2)
    };
    let packet = Ipv4Packet::build_icmp_echo_request(
        source,
        Ipv4Addr::new(10, 20, 0, 1),
        0x7171,
        1,
        b"original-rx-owner",
    );
    let len = packet.len() as u64;
    let capacity = packet.capacity() as u64;
    inbound
        .send(InboundPacket {
            peer_id: "rx-peer".into(),
            packet,
            session_instance: None,
            from_previous_session: false,
            authenticated_ingress: None,
            trace: None,
        })
        .await
        .unwrap();
    let mut pump = Box::pin(plane.run());
    poll_fn(|cx| {
        assert!(pump.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(arrival.try_recv().unwrap() as u64, len);
    let held = capture.residency_snapshot();
    assert!(held.coherent && held.valid);
    assert_eq!(held.unknown_bits, 0);
    let storage = held.stage(ResidencyStage::TunReaderStorage).unwrap();
    assert_eq!(storage.live_buffers, 1);
    let plaintext = held.stage(ResidencyStage::RxPlaintextActive).unwrap();
    assert_eq!(
        (
            plaintext.live_buffers,
            plaintext.len_bytes,
            plaintext.capacity_bytes
        ),
        (1, len, capacity)
    );
    let copy = held.stage(ResidencyStage::RxTunPacket).unwrap();
    let normalized = held.stage(ResidencyStage::RxTunNormalized).unwrap();
    assert_eq!(copy.live_buffers, u64::from(!normalize));
    assert_eq!(normalized.live_buffers, u64::from(normalize));
    let written = if normalize { normalized } else { copy };
    assert_eq!(written.len_bytes, len);
    assert_eq!(held.total.unwrap().live_buffers, 3);
    assert_eq!(
        held.total.unwrap().capacity_bytes,
        storage.capacity_bytes + capacity + written.capacity_bytes
    );
    assert_eq!(
        held.capacity_high_water_bytes,
        Some(
            storage.capacity_bytes
                + capacity
                + written.capacity_bytes
                + if normalize { len } else { 0 }
        )
    );
    assert!(!held.whole_pipeline_bytes_measured);
    capture.finish();
    assert_eq!(capture.residency_snapshot().total, held.total);
    if result == WriteResult::Cancel {
        drop(pump);
        drop(release);
    } else {
        release.send(()).unwrap();
        if result == WriteResult::Full {
            let bytes = tokio::time::timeout_at(deadline, async {
                tokio::select! {
                    value=controller.recv_written()=>value.unwrap(),
                    value=pump.as_mut()=>panic!("pump ended before full write: {value:?}"),
                }
            })
            .await
            .unwrap();
            let parsed = Ipv4Packet::new(&bytes).unwrap();
            assert!(parsed.verify_checksum());
            assert_eq!(parsed.src_addr(), Ipv4Addr::new(10, 20, 0, 2));
            assert_eq!(parsed.dst_addr(), Ipv4Addr::new(10, 20, 0, 1));
            assert_eq!(bytes.len() as u64, len);
            poll_fn(|cx| {
                assert!(pump.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(capture.residency_snapshot().total, Some(storage));
        } else {
            let error = tokio::time::timeout_at(deadline, pump.as_mut())
                .await
                .unwrap()
                .unwrap_err();
            assert!(matches!(error, DaemonError::Network(_)));
            // Completed futures must retire their owned values without waiting for Drop.
            assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
        }
        drop(pump);
    }
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
    assert_eq!(
        capture.residency_snapshot().total.unwrap().capacity_bytes,
        0
    );
    let received = peers
        .get_connection("rx-peer")
        .await
        .unwrap()
        .bytes_received
        .get();
    assert_eq!(received, if result == WriteResult::Full { len } else { 0 });
}

#[tokio::test]
async fn rx_ownership_original_and_normalized_tun_write_cancel_drain_real_owners() {
    for normalize in [false, true] {
        held_tun_write(normalize, WriteResult::Cancel).await;
    }
}
#[tokio::test]
async fn rx_ownership_original_and_normalized_tun_full_write_drains_after_delivery() {
    for normalize in [false, true] {
        held_tun_write(normalize, WriteResult::Full).await;
    }
}
#[tokio::test]
async fn rx_ownership_original_and_normalized_tun_short_write_drains_without_delivery() {
    for normalize in [false, true] {
        held_tun_write(normalize, WriteResult::Short).await;
    }
}
#[tokio::test]
async fn rx_ownership_original_and_normalized_tun_closed_write_drains_without_delivery() {
    for normalize in [false, true] {
        held_tun_write(normalize, WriteResult::Closed).await;
    }
}
