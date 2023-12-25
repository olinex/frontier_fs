// @author:    olinex
// @time:      2023/11/04

// self mods

// use other mods
use core::any::Any;

use alloc::sync::Arc;
use spin::Mutex;

// use self mods
use crate::configs::BLOCK_BYTE_SIZE;
use crate::{FFSError, Result};

const MOCK_BLOCK_COUNT: usize = 48;

pub trait BlockDevice: Send + Sync + Any {
    /// Read a block of bytes from device, 
    /// the length of the buffer must be same with [`crate::configs::BLOCK_BYTE_SIZE``]
    /// 
    /// # Arguments
    /// * id: the unique identifier of the block
    /// * buffer: the buffer which will store the block byte data
    fn read_block(&self, id: usize, buffer: &mut [u8]) -> Result<()>;

    /// Write a block of bytes to device,
    /// the length of the buffer must be same with [`crate::configs::BLOCK_BYTE_SIZE``]
    /// 
    /// # Arguments
    /// * id: the unique identifier of the block
    /// * buffer: the buffer which will be read and the data will be written to device
    fn write_block(&self, id: usize, buffer: &[u8]) -> Result<()>;
}

/// The mock block device which is impl [`BlockDevice`] and used for testing.
/// Data will be stored into the memory.
pub struct MockBlockDevice {
    data: Arc<Mutex<[u8; BLOCK_BYTE_SIZE * MOCK_BLOCK_COUNT]>>,
}
impl MockBlockDevice {

    /// Get the total block count of the mock device
    pub fn total_block_count() -> usize {
        MOCK_BLOCK_COUNT
    }

    /// Create a new mock block device
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new([0; BLOCK_BYTE_SIZE * MOCK_BLOCK_COUNT])),
        }
    }
}
impl Drop for MockBlockDevice {
    fn drop(&mut self) {
        for byte in self.data.lock().iter_mut() {
            *byte = 0;
        }
    }
}
impl BlockDevice for MockBlockDevice {
    fn read_block(&self, id: usize, buffer: &mut [u8]) -> Result<()> {
        assert!(buffer.len() == BLOCK_BYTE_SIZE);
        if id >= MOCK_BLOCK_COUNT {
            Err(FFSError::BlockOutOfBounds(id))
        } else {
            let start_offset = id * BLOCK_BYTE_SIZE;
            let src = self.data.lock();
            buffer.copy_from_slice(&src[start_offset..start_offset + BLOCK_BYTE_SIZE]);
            Ok(())
        }
    }

    fn write_block(&self, id: usize, buffer: &[u8]) -> Result<()> {
        assert!(buffer.len() == BLOCK_BYTE_SIZE);
        if id >= MOCK_BLOCK_COUNT {
            Err(FFSError::BlockOutOfBounds(id))
        } else {
            let start_offset = id * BLOCK_BYTE_SIZE;
            let mut dst = self.data.lock();
            dst[start_offset..start_offset + BLOCK_BYTE_SIZE].copy_from_slice(buffer);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mock_block_device_read_and_write() {
        let mock = MockBlockDevice::new();
        let mut test_block = [0; BLOCK_BYTE_SIZE];
        assert!(mock.read_block(0, &mut test_block).is_ok());
        assert_eq!([0; BLOCK_BYTE_SIZE], test_block);

        test_block[0] = 1;
        assert!(mock.read_block(0, &mut test_block).is_ok());
        assert_eq!([0; BLOCK_BYTE_SIZE], test_block);

        test_block[0] = 1;
        assert!(mock.write_block(0, &test_block).is_ok());
        test_block[0] = 0;
        assert!(mock.read_block(0, &mut test_block).is_ok());
        assert_eq!(1, test_block[0]);
    }
}
