// @author:    olinex
// @time:      2023/11/06

// self mods

// use other mods

use alloc::sync::Arc;

// use self mods
use crate::block::{BlockDeviceTracker, BLOCK_CACHE_MANAGER};
use crate::configs::{BLOCK_BIT_SIZE, BLOCK_BYTE_SIZE};
use crate::{FFSError, Result};

/// The byte size of the bitmap unit which is related with the architecture
const BITMAP_UNIT_BYTE_SIZE: usize = core::mem::size_of::<usize>();
const BITMAP_UNIT_BIT_SIZE: usize = BITMAP_UNIT_BYTE_SIZE * 8;
const BITMAP_UNIT_COUNT: usize = BLOCK_BYTE_SIZE / BITMAP_UNIT_BYTE_SIZE;

/// The bitmap data structure used to control the file system resources.
/// Bitmaps are stored in multiple data blocks,
/// and we can't manipulate a bit directly in the program,
/// so we need to operate uniformly in the area where the bit is located as a 32-bit positive integer.
pub struct Bitmap {
    /// The start block id which will be used for storing the bitmap data.
    start_block_id: usize,
    /// The count of the blocks used to store the bitmap data
    blocks: usize,
    /// The count of the usable bits in the bitmap
    usable_bits: usize,
}
impl Bitmap {
    /// Decompress the bitmap index to:
    /// * block index
    /// * unit index
    /// * bit offset
    ///
    /// # Arguments
    /// * bitmap_index: The index of the bit in the bitmap
    ///
    /// # Returns
    /// * (block id, unit index, bit offset)
    fn decompress(bitmap_index: usize) -> (usize, usize, usize) {
        let block_index = bitmap_index / BLOCK_BIT_SIZE;
        let bit = bitmap_index % BLOCK_BIT_SIZE;
        (
            block_index,
            bit / BITMAP_UNIT_BIT_SIZE,
            bit % BITMAP_UNIT_BIT_SIZE,
        )
    }

    /// Compress the block index/unit index/bit offset to bitmap index
    fn compress(block_index: usize, unit_index: usize, bit_offset: usize) -> usize {
        block_index * BLOCK_BIT_SIZE + unit_index * BITMAP_UNIT_BIT_SIZE + bit_offset
    }

    /// Create a new bitmap
    ///
    /// # Arguments
    /// * start_block_id: the block id which will be used for storing the bitmap data.
    /// * blocks: the count of the blocks used to store the bitmap data.
    /// * usable_bits: The count of the usable bits in the bitmap
    pub fn new(start_block_id: usize, blocks: usize, usable_bits: usize) -> Self {
        Self {
            start_block_id,
            blocks,
            usable_bits,
        }
    }

    /// Alloc a new bit and return the bitmap index.
    /// If all the bit were already allocated, return Err, otherwise return the bitmap index.
    ///
    /// # Arguments
    /// * tracker: the tracker for the block device which was mounted
    ///
    /// # Returns
    /// * Ok(bitmap index)
    /// * Err(BitmapExhausted(start_block_id) | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn alloc(&self, tracker: &Arc<BlockDeviceTracker>) -> Result<usize> {
        let mut manager = BLOCK_CACHE_MANAGER.lock();
        for block_index in 0..self.blocks {
            let once = |block: &mut BitmapBlock| {
                let position = block.iter().enumerate().find_map(|(unit_index, bits)| {
                    let bit_offset = bits.trailing_ones() as usize;
                    if bit_offset != BITMAP_UNIT_BIT_SIZE {
                        Some((unit_index, bit_offset))
                    } else {
                        None
                    }
                });
                if let Some((unit_index, bit_offset)) = position {
                    let bitmap_index = Self::compress(block_index, unit_index, bit_offset);
                    if bitmap_index < self.usable_bits {
                        block[unit_index] |= 1 << bit_offset;
                        Some(bitmap_index)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            let position = manager
                .get(tracker, self.start_block_id + block_index)?
                .lock()
                .modify(0, once)?;
            if let Some(bitmap_index) = position {
                return Ok(bitmap_index);
            }
        }
        Err(FFSError::BitmapExhausted(self.start_block_id))
    }

    /// Dealloc a old bit.
    /// If the bit is already deallocated, return Err
    ///
    /// # Arguments
    /// * tracker: the tracker for the block device which was mounted
    /// * bitmap_index: the index of the bit in the bitmap to deallocate
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | BitmapIndexDeallocated(bitmap_index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn dealloc(&self, tracker: &Arc<BlockDeviceTracker>, bitmap_index: usize) -> Result<()> {
        let (block_index, unit_index, bit_offset) = Self::decompress(bitmap_index);
        let once = |value: &mut usize| {
            let bit_value = 1 << bit_offset;
            if *value & bit_value == bit_value {
                *value -= bit_value;
                Ok(())
            } else {
                Err(FFSError::BitmapIndexDeallocated(bitmap_index))
            }
        };
        BLOCK_CACHE_MANAGER
            .lock()
            .get(tracker, self.start_block_id + block_index)?
            .lock()
            .modify(unit_index * BITMAP_UNIT_BYTE_SIZE, once)?
    }
}

pub type BitmapBlock = [usize; BITMAP_UNIT_COUNT];

#[cfg(test)]
mod tests {

    use super::*;
    use crate::block::{BlockDevice, MemoryBlockDevice, BLOCK_DEVICE_REGISTER};

    #[test]
    fn test_bitmap_compress() {
        assert_eq!(0, Bitmap::compress(0, 0, 0));
        assert_eq!(1, Bitmap::compress(0, 0, 1));
        assert_eq!(BITMAP_UNIT_BIT_SIZE - 1, Bitmap::compress(0, 0, BITMAP_UNIT_BIT_SIZE - 1));
        assert_eq!(BITMAP_UNIT_BIT_SIZE, Bitmap::compress(0, 1, 0));
        assert_eq!(BITMAP_UNIT_BIT_SIZE + 1, Bitmap::compress(0, 1, 1));

        assert_eq!(BITMAP_UNIT_BIT_SIZE + BITMAP_UNIT_BIT_SIZE - 1, Bitmap::compress(0, 1, BITMAP_UNIT_BIT_SIZE - 1));
        assert_eq!(BITMAP_UNIT_BIT_SIZE + BITMAP_UNIT_BIT_SIZE, Bitmap::compress(0, 2, 0));
        assert_eq!(BITMAP_UNIT_BIT_SIZE + BITMAP_UNIT_BIT_SIZE + 1, Bitmap::compress(0, 2, 1));

        assert_eq!(BITMAP_UNIT_BIT_SIZE * BITMAP_UNIT_COUNT - 1, Bitmap::compress(0, BITMAP_UNIT_COUNT - 1, BITMAP_UNIT_BIT_SIZE - 1));
        assert_eq!(BITMAP_UNIT_BIT_SIZE * BITMAP_UNIT_COUNT, Bitmap::compress(1, 0, 0));
        assert_eq!(BITMAP_UNIT_BIT_SIZE * BITMAP_UNIT_COUNT + 1, Bitmap::compress(1, 0, 1));
    }

    #[test]
    fn test_bitmap_decompress() {
        assert_eq!((0, 0, 0), Bitmap::decompress(0));
        assert_eq!((0, 0, 1), Bitmap::decompress(1));
        assert_eq!((0, 0, BITMAP_UNIT_BIT_SIZE - 1), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE - 1));
        assert_eq!((0, 1, 0), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE));
        assert_eq!((0, 1, 1), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE + 1));

        assert_eq!((0, 1, BITMAP_UNIT_BIT_SIZE - 1), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE + BITMAP_UNIT_BIT_SIZE - 1));
        assert_eq!((0, 2, 0), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE + BITMAP_UNIT_BIT_SIZE));
        assert_eq!((0, 2, 1), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE + BITMAP_UNIT_BIT_SIZE + 1));

        assert_eq!((0, BITMAP_UNIT_COUNT - 1, BITMAP_UNIT_BIT_SIZE - 1), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE * BITMAP_UNIT_COUNT - 1));
        assert_eq!((1, 0, 0), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE * BITMAP_UNIT_COUNT));
        assert_eq!((1, 0, 1), Bitmap::decompress(BITMAP_UNIT_BIT_SIZE * BITMAP_UNIT_COUNT + 1));
    }

    #[test]
    fn test_bitmap_alloc_and_dealloc() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let device: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(device).unwrap();
        let bitmap = Bitmap::new(0, MemoryBlockDevice::total_block_count(), usize::MAX);
        assert_eq!(0, bitmap.alloc(&tracker).unwrap());
        assert_eq!(1, bitmap.alloc(&tracker).unwrap());
        assert!(bitmap.dealloc(&tracker, 2).is_err());
        assert!(bitmap.dealloc(&tracker, 0).is_ok());
        assert!(bitmap.dealloc(&tracker, 1).is_ok());
        for i in 0..100 {
            let bitmap_index = bitmap.alloc(&tracker).unwrap();
            assert_eq!(bitmap_index, i);
        }
        for j in 0..100 {
            assert!(bitmap.dealloc(&tracker, j).is_ok(), "bitmap dealloc failed with {}", j);
        }
    }
}
