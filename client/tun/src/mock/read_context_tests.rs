use super::*;

#[tokio::test]
async fn complete_reads_keep_their_own_context_once() {
    let (device, controller) = MockTunDevice::new_default("context");
    let mut device: Box<dyn VirtualInterface> = Box::new(device);
    controller
        .inject_with_context(vec![1, 2], Box::new(String::from("first")))
        .await
        .unwrap();
    controller
        .inject_with_context(vec![3], Box::new(String::from("second")))
        .await
        .unwrap();
    let mut buffer = [0; 4];
    for (bytes, expected) in [(&[1, 2][..], "first"), (&[3][..], "second")] {
        let length = device.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], bytes);
        let context = device
            .take_last_read_context()
            .unwrap()
            .downcast::<String>()
            .unwrap();
        assert_eq!(*context, expected);
        assert!(device.take_last_read_context().is_none());
    }
}

#[tokio::test]
async fn legacy_read_clears_unconsumed_context() {
    let (mut device, controller) = MockTunDevice::new_default("context");
    controller
        .inject_with_context(vec![1], Box::new(String::from("old")))
        .await
        .unwrap();
    let mut buffer = [0; 4];
    device.read(&mut buffer).await.unwrap();
    controller.inject(vec![2]).await.unwrap();
    assert_eq!(device.read(&mut buffer).await.unwrap(), 1);
    assert_eq!(buffer[0], 2);
    assert!(device.take_last_read_context().is_none());
    device.write(&buffer[..1]).await.unwrap();
    assert_eq!(controller.recv_written().await.unwrap(), vec![2]);
}

#[tokio::test]
async fn truncated_and_empty_reads_discard_context() {
    let (mut device, controller) = MockTunDevice::new_default("context");
    for packet in [vec![1, 2], vec![], vec![3]] {
        controller
            .inject_with_context(packet, Box::new(String::from("untrusted")))
            .await
            .unwrap();
    }
    let mut buffer = [0; 1];
    assert_eq!(device.read(&mut buffer).await.unwrap(), 1);
    assert_eq!(buffer, [1]);
    assert!(device.take_last_read_context().is_none());
    assert_eq!(device.read(&mut buffer).await.unwrap(), 0);
    assert!(device.take_last_read_context().is_none());
    assert_eq!(device.read(&mut []).await.unwrap(), 0);
    assert!(device.take_last_read_context().is_none());
}

#[tokio::test]
async fn cancelled_and_failed_reads_clear_context() {
    let (mut device, controller) = MockTunDevice::new_default("context");
    let mut buffer = [0; 4];
    controller
        .inject_with_context(vec![1], Box::new(String::from("old")))
        .await
        .unwrap();
    device.read(&mut buffer).await.unwrap();
    // Poll the empty read first, then cancel it without a timing sleep.
    tokio::select! {
        biased;
        result = device.read(&mut buffer) => panic!("empty queue read completed: {result:?}"),
        () = std::future::ready(()) => {}
    }
    assert!(device.take_last_read_context().is_none());
    controller
        .inject_with_context(vec![2], Box::new(String::from("fresh")))
        .await
        .unwrap();
    assert_eq!(device.read(&mut buffer).await.unwrap(), 1);
    device.close();
    assert!(device.take_last_read_context().is_none());
    assert!(device.read(&mut buffer).await.is_err());
    assert!(device.take_last_read_context().is_none());
}
