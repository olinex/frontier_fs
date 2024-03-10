// @author:    olinex
// @time:      2023/11/04

// self mods

// use other mods
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::ops::Deref;
use spin::Mutex;

// use self mods
use super::BLOCK_CACHE_MANAGER;
use crate::configs::BLOCK_BYTE_SIZE;
use crate::{FFSError, Result};

const MAX_BLOCK_DEVICE_COUNT: usize = 65535;
const MEMORY_BLOCK_COUNT: usize = 48;

pub trait BlockDevice: Send + Sync + Any {
    /// Read a block of bytes from device and save it into the buffer
    /// the length of the buffer must be same with [`crate::configs::BLOCK_BYTE_SIZE`]
    ///
    /// # Arguments
    /// * id: the unique identifier of the block
    /// * buffer: the buffer which will store the block byte data
    ///
    /// # Returns
    /// * Some(error code): the error code returns when the block device gets corrupted
    /// * None: everything is Ok
    fn read_block(&self, id: usize, buffer: &mut [u8]) -> Option<isize>;

    /// Write a block of bytes to device which was read from the buffer
    /// the length of the buffer must be same with [`crate::configs::BLOCK_BYTE_SIZE`]
    ///
    /// # Arguments
    /// * id: the unique identifier of the block
    /// * buffer: the buffer which will be read and the data will be written to device
    ///
    /// # Returns
    /// * Some(error code): the error code returns when the block device gets corrupted
    /// * None: everything is Ok
    fn write_block(&self, id: usize, buffer: &[u8]) -> Option<isize>;
}

/// The tracker links a device with its corresponding device number,
/// and when a new device registers itself with the file system
pub struct BlockDeviceTracker {
    device_id: usize,
    device: Box<dyn BlockDevice>,
}
impl BlockDeviceTracker {
    /// Create a new block device tracker, this method can only be called by the file system
    ///
    /// # Arguments
    /// * device_id: The unique device number allocated from the file system
    /// * device: The device which was stored in the heap space memory
    fn new(device_id: usize, device: Box<dyn BlockDevice>) -> Self {
        Self { device_id, device }
    }

    /// Get the unique device number
    pub(crate) fn device_id(&self) -> usize {
        self.device_id
    }
}
impl Deref for BlockDeviceTracker {
    type Target = Box<dyn BlockDevice>;
    fn deref(&self) -> &Self::Target {
        &self.device
    }
}

/// The block device register, which contains all the block and its tracker.
/// It is given a device number, and each device number is used only once throughout the life of the register
pub struct BlockDeviceRegister {
    /// the device id will be given to the block device tracker on the next time
    next_id: usize,
    /// the map of the block device and its device id
    map: BTreeMap<usize, Arc<BlockDeviceTracker>>,
}
impl BlockDeviceRegister {
    /// Create a new `BlockDeviceRegister`.
    fn new() -> Self {
        Self {
            next_id: 0,
            map: BTreeMap::new(),
        }
    }

    /// Mount the device into file system and return the unique device identifier.
    ///
    /// # Arguments
    /// * device: the dynamic block device
    ///
    /// # Returns
    /// * Ok(device id)
    /// * Err(DeviceIdExhausted | NoMoreDeviceMountable)
    pub fn mount(&mut self, device: Box<dyn BlockDevice>) -> Result<Arc<BlockDeviceTracker>> {
        if self.next_id == usize::MAX {
            Err(FFSError::DeviceIdExhausted)
        } else if self.map.len() >= MAX_BLOCK_DEVICE_COUNT {
            Err(FFSError::NoMoreDeviceMountable)
        } else {
            let device_id = self.next_id;
            let tracker = Arc::new(BlockDeviceTracker::new(device_id, device));
            self.map.insert(device_id, Arc::clone(&tracker));
            self.next_id += 1;
            Ok(tracker)
        }
    }

    /// Unmount the device from file system
    ///
    /// # Arguments
    /// * device: the dynamic block device
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(BusyDeviceUndropptable | DeviceIdDoesNotExist)
    pub fn unmount(&mut self, tracker: Arc<BlockDeviceTracker>) -> Result<()> {
        if self.map.get(&tracker.device_id).is_some() {
            if Arc::strong_count(&tracker) != 2 {
                return Err(FFSError::BusyDeviceUndropptable);
            }
            assert!(self.map.remove(&tracker.device_id).is_some());
            Ok(())
        } else {
            Err(FFSError::DeviceIdDoesNotExist(tracker.device_id))
        }
    }

    /// Private clear all devices from register
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(BusyDeviceUndropptable | DeviceIdDoesNotExist)
    fn _clear(&mut self) -> Result<()> {
        let trackers: Vec<Arc<BlockDeviceTracker>> = self
            .map
            .values()
            .map(|tracker| Arc::clone(tracker))
            .collect();
        for trackers in trackers {
            self.unmount(trackers)?;
        }
        Ok(())
    }

    /// Clear all devices from register
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(BusyDeviceUndropptable | DeviceIdDoesNotExist)
    pub fn clear(&mut self) -> Result<()> {
        let mut manager = BLOCK_CACHE_MANAGER.lock();
        manager.clear();
        self._clear()?;
        drop(manager);
        Ok(())
    }

    /// Clear all device from register and reset the device id.
    /// Only for unit tests
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(BusyDeviceUndropptable | DeviceIdDoesNotExist)
    #[cfg(test)]
    pub fn reset(&mut self) -> Result<()> {
        let mut manager = BLOCK_CACHE_MANAGER.lock();
        manager.clear();
        self._clear()?;
        self.next_id = 0;
        drop(manager);
        Ok(())
    }
}

/// The mock block device which is impl [`BlockDevice`] and used for testing.
/// Data will be stored into the memory.
pub struct MemoryBlockDevice {
    data: Arc<Mutex<[u8; BLOCK_BYTE_SIZE * MEMORY_BLOCK_COUNT]>>,
}
impl MemoryBlockDevice {
    /// Get the total block count of the mock device
    pub fn total_block_count() -> usize {
        MEMORY_BLOCK_COUNT
    }

    /// Create a new mock block device
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new([0; BLOCK_BYTE_SIZE * MEMORY_BLOCK_COUNT])),
        }
    }
}
impl Drop for MemoryBlockDevice {
    /// Clear the data in the memory as zero bytes
    fn drop(&mut self) {
        for byte in self.data.lock().iter_mut() {
            *byte = 0;
        }
    }
}
impl BlockDevice for MemoryBlockDevice {
    fn read_block(&self, id: usize, buffer: &mut [u8]) -> Option<isize> {
        assert!(buffer.len() == BLOCK_BYTE_SIZE);
        if id >= MEMORY_BLOCK_COUNT {
            Some(1)
        } else {
            let start_offset = id * BLOCK_BYTE_SIZE;
            let src = self.data.lock();
            buffer.copy_from_slice(&src[start_offset..start_offset + BLOCK_BYTE_SIZE]);
            None
        }
    }

    fn write_block(&self, id: usize, buffer: &[u8]) -> Option<isize> {
        assert!(buffer.len() == BLOCK_BYTE_SIZE);
        if id >= MEMORY_BLOCK_COUNT {
            Some(1)
        } else {
            let start_offset = id * BLOCK_BYTE_SIZE;
            let mut dst = self.data.lock();
            dst[start_offset..start_offset + BLOCK_BYTE_SIZE].copy_from_slice(buffer);
            None
        }
    }
}

lazy_static! {
    /// The register which contains all the block devices
    /// Every block device must have been registered first.
    pub static ref BLOCK_DEVICE_REGISTER: Mutex<BlockDeviceRegister> =
        Mutex::new(BlockDeviceRegister::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    #[test]
    fn test_mock_block_device_read_and_write() {
        let mock = MemoryBlockDevice::new();
        let mut test_block = [0; BLOCK_BYTE_SIZE];
        assert!(mock.read_block(0, &mut test_block).is_none());
        assert_eq!([0; BLOCK_BYTE_SIZE], test_block);

        test_block[0] = 1;
        assert!(mock.read_block(0, &mut test_block).is_none());
        assert_eq!([0; BLOCK_BYTE_SIZE], test_block);

        test_block[0] = 1;
        assert!(mock.write_block(0, &test_block).is_none());
        test_block[0] = 0;
        assert!(mock.read_block(0, &mut test_block).is_none());
        assert_eq!(1, test_block[0]);
    }

    #[test]
    fn test_block_device_mount_and_unmount() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker1 = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        assert_eq!(0, tracker1.device_id);
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker2 = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        assert_eq!(1, tracker2.device_id);
        assert!(BLOCK_DEVICE_REGISTER.lock().unmount(tracker1).is_ok());
        assert!(BLOCK_DEVICE_REGISTER.lock().unmount(tracker2).is_ok());
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker1 = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        assert_eq!(2, tracker1.device_id);
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker2 = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        assert_eq!(3, tracker2.device_id);
    }
}
