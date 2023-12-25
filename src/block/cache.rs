// @author:    olinex
// @time:      2023/11/04

// self mods

// use other mods
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::mutex::Mutex;

// use self mods
use super::BlockDevice;
use crate::configs::{BLOCK_BYTE_SIZE, BLOCK_CACHE_COUNT};
use crate::{FFSError, Result};

/// A cache object for data blocks,
/// which manages the writing and reading of data blocks.
/// Modified data in cache will be writed back to block device after the cache object is dropped.
pub struct BlockCache {
    id: usize,
    cache: [u8; BLOCK_BYTE_SIZE],
    device: Arc<dyn BlockDevice>,
    modified: bool,
}
impl BlockCache {
    /// Create a new block cache object and read data immediately.
    ///
    /// # Arguments
    /// * id: the block id of the device
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(BlockCache)
    /// * Err(FFSError(groups(block)))
    fn new(id: usize, device: &Arc<dyn BlockDevice>) -> Result<Self> {
        let mut cache = [0u8; BLOCK_BYTE_SIZE];
        device.read_block(id, &mut cache)?;
        Ok(Self {
            id,
            cache,
            device: Arc::clone(device),
            modified: false,
        })
    }

    /// Get the address of the cached data in memory
    ///
    /// # Arguments
    /// * offset: the offset of the cached bytes which start from zero
    ///
    /// # Returns
    /// * usize: the pointer addres
    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }

    /// Get the reference of the <T>
    ///
    /// # Arguments
    /// * offset: the offset of the cached bytes which start from zero
    ///
    /// # Returns
    /// * ref T
    fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    /// Get the mutable reference of the <T>
    ///
    /// # Arguments
    /// * offset: the offset of the cached bytes which start from zero
    ///
    /// # Returns
    /// * mutable ref T
    fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        self.modified = true;
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }

    /// Read data from block cache as the reference of the <T> and return the result of the closure.
    /// Be careful, the returned value isn't the copy of the original, but the original value in memory
    ///
    /// # Arguments
    /// * offset: the offset of the cached bytes which start from zero
    /// * f: the closure function which receives the reference of the data
    ///
    /// # Returns
    /// * Ok(the result of the closure)
    /// * Err(FFSError::DataOutOfBounds)
    pub fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> Result<V> {
        if (offset + core::mem::size_of::<T>()) <= BLOCK_BYTE_SIZE {
            Ok(f(self.get_ref(offset)))
        } else {
            Err(FFSError::DataOutOfBounds)
        }
    }

    /// Read data from block cache as the mutable reference of the <T> and return the result of the closure
    ///
    /// # Arguments
    /// * offset: the offset of the cached bytes which start from zero
    /// * f: the closure function which receives the mutable reference of the data
    ///
    /// # Returns
    /// * Ok(the result of the closure)
    /// * Err(FFSError::DataOutOfBounds)
    pub fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> Result<V> {
        if (offset + core::mem::size_of::<T>()) <= BLOCK_BYTE_SIZE {
            Ok(f(self.get_mut(offset)))
        } else {
            Err(FFSError::DataOutOfBounds)
        }
    }

    /// Write data into block device
    pub fn sync(&mut self) -> Result<()> {
        if self.modified {
            self.modified = false;
            self.device.write_block(self.id, &self.cache)
        } else {
            Ok(())
        }
    }
}
impl Drop for BlockCache {
    fn drop(&mut self) {
        self.sync().unwrap()
    }
}

/// The manager of the block cache
pub struct BlockCacheManager {
    /// the block caches mapping which key are the block ids
    map: BTreeMap<usize, Arc<Mutex<BlockCache>>>,
}
impl BlockCacheManager {
    /// Find the droptable block id in the cache list
    ///
    /// # Returns
    /// * Some(block id)
    /// * None: all of the blocks in the cache are using
    fn find_droptable_id(&self) -> Option<usize> {
        if let Some(pair) = self.map.iter().find(|pair| Arc::strong_count(pair.1) == 1) {
            Some(*pair.0)
        } else {
            None
        }
    }

    /// Load block cache which is save in the manager's mapping.
    /// If cache does not exists, it will be loaded from the block device immediately
    ///
    /// # Arguments
    /// * id: the block id of the device
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(Arc<Mutex<BlockDevice>>)
    /// * Err(FFSError::NoDroptableBlockCache)
    fn load_cache(
        &mut self,
        id: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<Arc<Mutex<BlockCache>>> {
        if self.full() {
            if let Some(remove_id) = self.find_droptable_id() {
                self.map.remove(&remove_id);
            } else {
                return Err(FFSError::NoDroptableBlockCache);
            }
        }
        let cache = Arc::new(Mutex::new(BlockCache::new(id, device)?));
        if self.map.insert(id, cache).is_some() {
            panic!("Cache {0} already exists", id);
        }
        Ok(Arc::clone(self.map.get(&id).unwrap()))
    }

    #[inline(always)]
    fn full(&self) -> bool {
        self.map.len() == BLOCK_CACHE_COUNT
    }

    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Get block cache which is save in the manager's mapping.
    /// If cache does not exists, it will be loaded from the block device immediately
    ///
    /// # Arguments
    /// * id: the block id of the device
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(Arc<Mutex<BlockDevice>>)
    /// * Err(FFSError::NoDroptableBlockCache)
    fn get_cache(
        &mut self,
        id: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<Arc<Mutex<BlockCache>>> {
        if let Some(cache) = self.map.get(&id) {
            Ok(Arc::clone(cache))
        } else {
            self.load_cache(id, device)
        }
    }

    fn clear(&mut self) {
        self.map.clear()
    }
}

lazy_static! {
    /// The global block cache manager
    pub static ref BLOCK_CACHE_MANAGER: Mutex<BlockCacheManager> =
        Mutex::new(BlockCacheManager::new());
}
impl BLOCK_CACHE_MANAGER {
    pub fn get_cache(
        &self,
        id: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<Arc<Mutex<BlockCache>>> {
        self.lock().get_cache(id, device)
    }

    pub fn clear(&self) {
        self.lock().clear()
    }
}

#[cfg(test)]
mod tests {
    use super::super::device::MockBlockDevice;
    use super::*;

    #[test]
    fn test_block_cache_new() {
        let mock: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        assert!(BlockCache::new(0, &mock).is_ok());
        assert!(BlockCache::new(MockBlockDevice::total_block_count() - 1, &mock).is_ok());
        assert!(BlockCache::new(MockBlockDevice::total_block_count(), &mock)
            .is_err_and(|e| e.is_blockoutofbounds()));
    }

    #[test]
    fn test_block_read_and_modify() {
        let mock: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut cache = BlockCache::new(0, &mock).unwrap();
        assert!(cache.read(0, |v: &u8| *v == 0).is_ok_and(|v| *v));
        assert!(!cache.modified);
        assert!(cache.modify(0, |v: &mut u8| *v = 1).is_ok());

        assert!(cache.modified);
        assert!(cache.read(0, |v: &u8| *v == 1).is_ok_and(|v| *v));

        drop(cache);
        let cache = BlockCache::new(0, &mock).unwrap();
        assert!(cache.read(0, |v: &u8| *v == 1).is_ok_and(|v| *v));
    }

    #[test]
    fn test_block_cache_manager_find_droptable_id() {
        let mock: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let cache1 = BLOCK_CACHE_MANAGER.get_cache(0, &mock);
        let cache2 = BLOCK_CACHE_MANAGER.get_cache(0, &mock);
        assert!(BLOCK_CACHE_MANAGER.lock().find_droptable_id().is_none());
        drop(cache1);
        assert!(BLOCK_CACHE_MANAGER.lock().find_droptable_id().is_none());
        drop(cache2);
        assert!(BLOCK_CACHE_MANAGER
            .lock()
            .find_droptable_id()
            .is_some_and(|v| *v == 0));
    }
}
