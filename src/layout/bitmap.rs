// @author:    olinex
// @time:      2023/11/06

// self mods

// use other mods
use alloc::sync::Arc;

// use self mods
use crate::block::{BlockDevice, BLOCK_CACHE_MANAGER};
use crate::configs::{BLOCK_BIT_SIZE, BLOCK_BYTE_SIZE};
use crate::{FFSError, Result};

/// The byte size of the bitmap unit which is related with the architecture
const BITMAP_UNIT_BYTE_SIZE: usize = core::mem::size_of::<usize>();

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
    used_bits: usize,
}
impl Bitmap {
    /// Decompress the bitmap index to:
    /// * block id
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
            bit / BITMAP_UNIT_BYTE_SIZE,
            bit % BITMAP_UNIT_BYTE_SIZE,
        )
    }

    /// Create a new bitmap
    ///
    /// # Arguments
    /// * start_block_id: the block id which will be used for storing the bitmap data.
    /// * blocks: the count of the blocks used to store the bitmap data.
    pub fn new(start_block_id: usize, blocks: usize, used_bits: usize) -> Self {
        Self {
            start_block_id,
            blocks,
            used_bits,
        }
    }

    /// Alloc a new bit and return the bitmap index.
    /// If all the bit were already allocated, return Err, otherwise return the bitmap index.
    ///
    /// # Arguments
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(bitmap index)
    /// * Err(FFSError::BitmapExhausted(start_block_id))
    pub fn alloc(&self, device: &Arc<dyn BlockDevice>) -> Result<usize> {
        for block_offset in 0..self.blocks {
            let position = BLOCK_CACHE_MANAGER
                .get_cache(self.start_block_id + block_offset, device)?
                .lock()
                .modify(0, |block: &mut BitmapBlock| {
                    let position = block.iter().enumerate().find_map(|(unit_index, bits)| {
                        if *bits != usize::MAX {
                            Some((unit_index, bits.trailing_ones() as usize))
                        } else {
                            None
                        }
                    });
                    if let Some((unit_index, bit_offset)) = position {
                        let block_index = block_offset * BLOCK_BIT_SIZE
                            + unit_index * BITMAP_UNIT_BYTE_SIZE
                            + bit_offset;
                        if block_index < self.used_bits {
                            block[unit_index] |= 1 << bit_offset;
                            Some(block_index)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })?;
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
    /// * bitmap_index: the index of the bit in the bitmap to deallocate
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(FFSError::BitmapIndexDeallocated(bitmap_index))
    pub fn dealloc(&self, bitmap_index: usize, device: &Arc<dyn BlockDevice>) -> Result<()> {
        let (block_offset, unit_index, bit_offset) = Self::decompress(bitmap_index);
        BLOCK_CACHE_MANAGER
            .get_cache(self.start_block_id + block_offset, device)?
            .lock()
            .modify(unit_index, |value: &mut usize| {
                let bit_value = 1 << bit_offset;
                if *value & bit_value != 0 {
                    *value -= bit_value;
                    Ok(())
                } else {
                    Err(FFSError::BitmapIndexDeallocated(bitmap_index))
                }
            })?
    }
}

pub type BitmapBlock = [usize; BLOCK_BYTE_SIZE / BITMAP_UNIT_BYTE_SIZE];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MockBlockDevice;

    #[test]
    fn test_bitmap_decompress() {
        let (block_offset, unit_index, bit_offset) = Bitmap::decompress(0);
        assert_eq!(0, block_offset);
        assert_eq!(0, unit_index);
        assert_eq!(0, bit_offset);

        let (block_offset, unit_index, bit_offset) = Bitmap::decompress(1);
        assert_eq!(0, block_offset);
        assert_eq!(0, unit_index);
        assert_eq!(1, bit_offset);

        let (block_offset, unit_index, bit_offset) = Bitmap::decompress(BITMAP_UNIT_BYTE_SIZE);
        assert_eq!(0, block_offset);
        assert_eq!(1, unit_index);
        assert_eq!(0, bit_offset);

        let (block_offset, unit_index, bit_offset) = Bitmap::decompress(BITMAP_UNIT_BYTE_SIZE * 2);
        assert_eq!(0, block_offset);
        assert_eq!(2, unit_index);
        assert_eq!(0, bit_offset);

        let (block_offset, unit_index, bit_offset) = Bitmap::decompress(BLOCK_BIT_SIZE);
        assert_eq!(1, block_offset);
        assert_eq!(0, unit_index);
        assert_eq!(0, bit_offset);

        let (block_offset, unit_index, bit_offset) = Bitmap::decompress(BLOCK_BIT_SIZE * 2);
        assert_eq!(2, block_offset);
        assert_eq!(0, unit_index);
        assert_eq!(0, bit_offset);
    }

    #[test]
    fn test_bitmap_alloc_and_dealloc() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let bitmap = Bitmap::new(0, MockBlockDevice::total_block_count(), 10);
        assert!(bitmap
            .alloc(&device)
            .is_ok_and(|bitmap_index| bitmap_index == 0));
        assert!(bitmap
            .alloc(&device)
            .is_ok_and(|bitmap_index| bitmap_index == 1));
        assert!(bitmap.dealloc(2, &device).is_err());
        assert!(bitmap.dealloc(0, &device).is_ok());
        assert!(bitmap.dealloc(1, &device).is_ok());
    }
}
