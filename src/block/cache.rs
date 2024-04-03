// @author:    olinex
// @time:      2023/11/04

// self mods

// use other mods
use alloc::collections::BTreeMap;
use alloc::boxed::ThinBox;
use alloc::sync::Arc;
use spin::mutex::Mutex;

// use self mods
use super::device::BlockDeviceTracker;
use crate::configs::{BLOCK_BYTE_SIZE, BLOCK_CACHE_COUNT};
use crate::{FFSError, Result};

/// A cache object for data blocks,
/// which manages the writing and reading of data blocks.
/// Modified data in cache will be writed back to block device after the cache object is dropped.
pub(crate) struct BlockCache {
    id: usize,
    /// We should make the cache byte buffer to store into the kernel heap.
    /// If we does't, the task's kernel stack maybe overflow 
    cache: ThinBox<[u8; BLOCK_BYTE_SIZE]>,
    tracker: Arc<BlockDeviceTracker>,
    modified: bool,
}
impl BlockCache {
    /// Create a new block cache object and read data immediately.
    ///
    /// - Arguments
    ///     - id: the block id of the device
    ///     - tracker: the tracker for the block device which was mounted
    ///
    /// - Errors
    ///     - RawDeviceError(error code)
    fn new(id: usize, tracker: Arc<BlockDeviceTracker>) -> Result<Self> {
        let mut cache = ThinBox::new([0u8; BLOCK_BYTE_SIZE]);
        if let Some(err_code) = tracker.read_block(id, &mut *cache) {
            Err(FFSError::RawDeviceError(err_code))
        } else {
            Ok(Self {
                id,
                cache,
                tracker,
                modified: false,
            })
        }
    }

    /// Get the address of the cached data in memory
    ///
    /// - Arguments
    ///     - offset: the offset of the cached bytes which start from zero
    #[inline(always)]
    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }

    /// Get the reference of the <T>
    ///
    /// - Arguments
    ///     - offset: the offset of the cached bytes which start from zero
    #[inline(always)]
    fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    /// Get the mutable reference of the <T>
    ///
    /// - Arguments
    ///     - offset: the offset of the cached bytes which start from zero
    #[inline(always)]
    fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }

    /// Read data from block cache as the reference of the <T> and return the result of the closure.
    /// Be careful, the returned value isn't the copy of the original, but the original value in memory
    ///
    /// - Arguments
    ///     - offset: the offset of the cached bytes which start from zero
    ///     - f: the closure function which receives the reference of the data
    ///
    /// - Errors
    ///     - DataOutOfBounds
    #[inline(always)]
    pub(crate) fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> Result<V> {
        if (offset + core::mem::size_of::<T>()) <= BLOCK_BYTE_SIZE {
            Ok(f(self.get_ref(offset)))
        } else {
            Err(FFSError::DataOutOfBounds)
        }
    }

    /// Read data from block cache as the mutable reference of the <T> and return the result of the closure
    ///
    /// - Arguments
    ///     - offset: the offset of the cached bytes which start from zero
    ///     - f: the closure function which receives the mutable reference of the data
    ///
    /// - Errors
    ///     - DataOutOfBounds
    #[inline(always)]
    pub(crate) fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> Result<V> {
        if (offset + core::mem::size_of::<T>()) <= BLOCK_BYTE_SIZE {
            self.modified = true;
            Ok(f(self.get_mut(offset)))
        } else {
            Err(FFSError::DataOutOfBounds)
        }
    }

    /// Write data into block device
    ///
    /// - Errors
    ///     - RawDeviceError(error code)
    pub(crate) fn sync(&mut self) -> Result<()> {
        if self.modified {
            if let Some(err_code) = self.tracker.write_block(self.id, &*self.cache) {
                return Err(FFSError::RawDeviceError(err_code));
            }
            self.modified = false;
        };
        Ok(())
    }
}
impl Drop for BlockCache {
    fn drop(&mut self) {
        self.sync().unwrap()
    }
}

/// The manager of the block cache
pub(crate) struct BlockCacheManager {
    /// the block caches mapping which key are the block ids
    map: BTreeMap<(usize, usize), Arc<Mutex<BlockCache>>>,
}
impl BlockCacheManager {
    /// Find the droptable block id in the cache list
    /// 
    /// - Returns
    ///     - Some(device id, block id)
    ///     - None
    fn find_droptable_id(&self) -> Option<(usize, usize)> {
        if let Some((key, _)) = self
            .map
            .iter()
            .find(|pair| Arc::strong_count(pair.1) == 1 && !pair.1.is_locked())
        {
            Some((key.0, key.1))
        } else {
            None
        }
    }

    /// Load block cache which was saved in the manager's mapping.
    /// If cache does not exists, it will be loaded from the block device immediately
    ///
    /// - Arguments
    ///     - device_id: the unique id of the device
    ///     - tracker: the tracker for the block device which was mounted
    ///
    /// - Errors
    ///     - NoDroptableBlockCache 
    ///     - RawDeviceError(error code)
    fn load_cache(
        &mut self,
        tracker: &Arc<BlockDeviceTracker>,
        block_id: usize,
    ) -> Result<Arc<Mutex<BlockCache>>> {
        if self.full() {
            if let Some(remove_id) = self.find_droptable_id() {
                self.map.remove(&remove_id);
            } else {
                return Err(FFSError::NoDroptableBlockCache);
            }
        }
        let id = (tracker.device_id(), block_id);
        let cache = Arc::new(Mutex::new(BlockCache::new(block_id, Arc::clone(tracker))?));
        if self.map.insert(id, cache).is_some() {
            panic!("Cache {0} in device {1} already exists", id.1, id.0);
        }
        Ok(Arc::clone(self.map.get(&id).unwrap()))
    }

    /// Check if the cache is full
    fn full(&self) -> bool {
        self.map.len() >= BLOCK_CACHE_COUNT
    }

    /// Create a new cache Manager
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Get block cache which is save in the manager's mapping.
    /// If cache does not exists, it will be loaded from the block device immediately
    ///
    /// - Arguments
    ///     - block_id: the block id of the device
    ///     - tracker: the tracker for the block device which was mounted
    ///
    /// - Errors
    ///     - NoDroptableBlockCache 
    ///     - RawDeviceError(error code)
    pub(crate) fn get(
        &mut self,
        tracker: &Arc<BlockDeviceTracker>,
        block_id: usize,
    ) -> Result<Arc<Mutex<BlockCache>>> {
        let id = (tracker.device_id(), block_id);
        if let Some(cache) = self.map.get(&id) {
            Ok(Arc::clone(cache))
        } else {
            self.load_cache(tracker, block_id)
        }
    }

    /// Clear all caches in the cache manager.
    /// Modified cache will be saved when dropping.
    pub(crate) fn clear(&mut self) {
        while self.map.len() != 0 {
            if let Some(id) = self.find_droptable_id() {
                let cache = Arc::clone(self.map.get(&id).unwrap());
                let lock = cache.try_lock();
                if lock.is_none() {
                    continue;
                }
                self.map.remove(&id).unwrap();
            }
        }
    }
}

lazy_static! {
    pub(crate) static ref BLOCK_CACHE_MANAGER: Arc<Mutex<BlockCacheManager>> =
        Arc::new(Mutex::new(BlockCacheManager::new()));
}

#[cfg(test)]
mod tests {

    use super::super::device::{BlockDevice, MemoryBlockDevice, BLOCK_DEVICE_REGISTER};
    use super::*;

    #[test]
    fn test_block_cache_new() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        assert!(BlockCache::new(0, Arc::clone(&tracker)).is_ok());
        assert!(BlockCache::new(
            MemoryBlockDevice::total_block_count() - 1,
            Arc::clone(&tracker)
        )
        .is_ok());
        assert!(
            BlockCache::new(MemoryBlockDevice::total_block_count(), Arc::clone(&tracker))
                .is_err_and(|e| e.is_rawdeviceerror())
        );
    }

    #[test]
    fn test_block_read_and_modify() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let mut cache = BlockCache::new(0, Arc::clone(&tracker)).unwrap();
        assert!(cache.read(0, |v: &u8| *v == 0).is_ok_and(|v| v));
        assert!(!cache.modified);
        assert!(cache.modify(0, |v: &mut u8| *v = 1).is_ok());

        assert!(cache.modified);
        assert!(cache.read(0, |v: &u8| *v == 1).is_ok_and(|v| v));

        drop(cache);
        let cache = BlockCache::new(0, Arc::clone(&tracker)).unwrap();
        assert!(cache.read(0, |v: &u8| *v == 1).is_ok_and(|v| v));
    }

    #[test]
    fn test_block_cache_manager_find_droptable_id() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let cache1 = BLOCK_CACHE_MANAGER.lock().get(&tracker, 0);
        let cache2 = BLOCK_CACHE_MANAGER.lock().get(&tracker, 0);
        assert!(BLOCK_CACHE_MANAGER.lock().find_droptable_id().is_none());
        drop(cache1);
        assert!(BLOCK_CACHE_MANAGER.lock().find_droptable_id().is_none());
        drop(cache2);
        assert!(BLOCK_CACHE_MANAGER
            .lock()
            .find_droptable_id()
            .is_some_and(|v| v.1 == 0));
    }
}
