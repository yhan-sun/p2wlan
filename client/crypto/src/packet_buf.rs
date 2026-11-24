//! Bounded packet storage with private ownership across asynchronous handoffs.

use std::sync::{Arc, Mutex};

pub const HEADROOM: usize = 64;
pub const TAILROOM: usize = 16;
const CLASSES: [usize; 2] = [2048, 4096];
const MAX_CACHED_PER_CLASS: usize = 64;

// Cache the entire lease so acquiring one reuses its metadata allocation too.
#[allow(clippy::vec_box)]
type Available = [Mutex<Vec<Box<Storage>>>; CLASSES.len()];

#[derive(Clone, Default)]
pub struct BufPool {
    free: Arc<Available>,
}

impl BufPool {
    pub fn acquire(&self, capacity: usize) -> Option<PacketBuf> {
        if capacity > u16::MAX as usize {
            return None;
        }
        let class = CLASSES.iter().position(|limit| capacity <= *limit);
        let mut storage = class
            .and_then(|index| {
                self.free[index]
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .pop()
            })
            .unwrap_or_default();
        let full_capacity = HEADROOM + class.map_or(capacity, |index| CLASSES[index]) + TAILROOM;
        if storage.bytes.len() != full_capacity {
            storage.bytes.try_reserve_exact(full_capacity).ok()?;
            storage.bytes.resize(full_capacity, 0);
        }
        storage.start = HEADROOM;
        storage.len = 0;
        storage.capacity = capacity;
        Some(PacketBuf {
            storage: Some(storage),
            pool: class.map(|_| self.clone()),
        })
    }
}

#[derive(Default)]
struct Storage {
    bytes: Vec<u8>,
    start: usize,
    len: usize,
    capacity: usize,
}

pub struct PacketBuf {
    storage: Option<Box<Storage>>,
    pool: Option<BufPool>,
}

impl PacketBuf {
    fn storage(&self) -> &Storage {
        self.storage.as_deref().expect("buffer owns its storage")
    }

    fn storage_mut(&mut self) -> &mut Storage {
        self.storage
            .as_deref_mut()
            .expect("buffer owns its storage")
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.bytes().to_vec()
    }

    pub fn storage_capacity(&self) -> usize {
        self.storage().bytes.capacity()
    }

    pub fn len(&self) -> usize {
        self.storage().len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Capacity available to a TUN or datagram read. A reader must explicitly
    /// publish the number of bytes it initialized before using `bytes()`.
    pub fn read_space(&mut self) -> &mut [u8] {
        let storage = self.storage_mut();
        &mut storage.bytes[HEADROOM..HEADROOM + storage.capacity]
    }

    /// Reserve one sentinel byte to distinguish a full datagram from an
    /// oversized one on sockets where recv_from truncates silently.
    pub fn datagram_read_space(&mut self) -> &mut [u8] {
        let storage = self.storage_mut();
        &mut storage.bytes[HEADROOM..=HEADROOM + storage.capacity]
    }

    pub fn set_read_len(&mut self, len: usize) -> bool {
        let storage = self.storage_mut();
        if len > storage.capacity {
            return false;
        }
        storage.start = HEADROOM;
        storage.len = len;
        true
    }

    pub fn bytes(&self) -> &[u8] {
        let storage = self.storage();
        &storage.bytes[storage.start..storage.start + storage.len]
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        let storage = self.storage_mut();
        &mut storage.bytes[storage.start..storage.start + storage.len]
    }

    pub fn prepend(&mut self, prefix: &[u8]) -> bool {
        let storage = self.storage_mut();
        let Some(start) = storage.start.checked_sub(prefix.len()) else {
            return false;
        };
        storage.bytes[start..storage.start].copy_from_slice(prefix);
        storage.start = start;
        storage.len += prefix.len();
        true
    }

    pub fn append(&mut self, suffix: &[u8]) -> bool {
        let storage = self.storage_mut();
        let end = storage.start + storage.len;
        let Some(room) = storage.bytes.get_mut(end..end + suffix.len()) else {
            return false;
        };
        room.copy_from_slice(suffix);
        storage.len += suffix.len();
        true
    }

    pub fn trim(&mut self, head: usize, tail: usize) -> bool {
        let storage = self.storage_mut();
        if head > storage.len || tail > storage.len - head {
            return false;
        }
        storage.start += head;
        storage.len -= head + tail;
        true
    }

    pub fn can_frame(&self, head: usize, tail: usize) -> bool {
        let storage = self.storage();
        head <= storage.start && tail <= storage.bytes.len() - (storage.start + storage.len)
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        if let (Some(pool), Some(storage)) = (self.pool.take(), self.storage.take()) {
            let index = usize::from(storage.capacity > CLASSES[0]);
            let mut free = pool.free[index].lock().unwrap_or_else(|e| e.into_inner());
            if free.len() < MAX_CACHED_PER_CLASS {
                free.push(storage);
            }
        }
    }
}
