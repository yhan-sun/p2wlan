use p2pnet_crypto::{packet_buf::BufPool, NodeIdentity};
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    net::UdpSocket,
    time::{Duration, Instant},
};

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountAllocations;

#[global_allocator]
static ALLOCATOR: CountAllocations = CountAllocations;

unsafe impl GlobalAlloc for CountAllocations {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(pointer, layout, size) }
    }
}

fn count() {
    let _ = ALLOCATIONS.try_with(|calls| {
        if let Some(calls_so_far) = calls.get() {
            calls.set(Some(calls_so_far + 1));
        }
    });
}

#[test]
fn pooled_wireguard_roundtrip_over_loopback_has_no_steady_state_heap_allocations() {
    const COUNT: usize = 20_000;
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(a, b.public_key(), None);
    let mut responder = HandshakeResponder::new(b, None);
    let (reply, receive_keys) = responder
        .consume_initiation_and_respond(&initiator.create_initiation().unwrap())
        .unwrap();
    let mut send = TransportSession::new(initiator.consume_response(&reply).unwrap());
    let mut receive = TransportSession::new(receive_keys);
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let dst = rx.local_addr().unwrap();
    let tx_pool = BufPool::default();
    let rx_pool = BufPool::default();
    let mut exchange = |sequence: usize| {
        let mut tx_buf = tx_pool.acquire(1400).unwrap();
        let mut rx_buf = rx_pool.acquire(1432).unwrap();
        tx_buf.read_space().fill(sequence as u8);
        assert!(tx_buf.set_read_len(1400));
        let tx_storage = tx_buf.bytes().as_ptr();
        send.seal_packet(&mut tx_buf).unwrap();
        assert_eq!(tx_buf.bytes().as_ptr().wrapping_add(16), tx_storage);
        assert_eq!(tx.send_to(tx_buf.bytes(), dst).unwrap(), 1432);
        let wire = rx.recv(rx_buf.read_space()).unwrap();
        assert!(rx_buf.set_read_len(wire));
        let rx_storage = rx_buf.bytes().as_ptr();
        receive.open_packet(&mut rx_buf).unwrap();
        assert_eq!(rx_buf.bytes().as_ptr(), rx_storage.wrapping_add(16));
        assert_eq!(rx_buf.bytes(), &[sequence as u8; 1400]);
        (tx_storage, rx_storage)
    };
    let warmed = exchange(0);
    let started = Instant::now();
    ALLOCATIONS.with(|calls| calls.set(Some(0)));
    for sequence in 1..=COUNT {
        assert_eq!(exchange(sequence), warmed);
    }
    let allocations = ALLOCATIONS.with(|calls| calls.replace(None).unwrap());
    let mbps = COUNT as f64 * 1400.0 * 8.0 / started.elapsed().as_secs_f64() / 1e6;
    assert_eq!(allocations, 0);
    eprintln!("{COUNT} WireGuard UDP roundtrips, {mbps:.1} Mbit/s, {allocations} allocations, 100% slab reuse");
}
