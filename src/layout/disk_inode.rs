// @author:    olinex
// @time:      2023/11/08

// self mods

// use other mods
use alloc::sync::Arc;
use alloc::vec::Vec;

// use self mods
use crate::block::{BlockDevice, BLOCK_CACHE_MANAGER};
use crate::configs::BLOCK_BYTE_SIZE;
use crate::{FFSError, Result};

const BLOCK_STORE_UNIT_BYTE_SIZE: usize = core::mem::size_of::<u32>();
const BLOCK_STORE_UNIT_COUNT: usize = BLOCK_BYTE_SIZE / BLOCK_STORE_UNIT_BYTE_SIZE;

const DIRECT_ROOT_BLOCK_COUNT: usize = 21;
const I1_ROOT_BLOCK_COUNT: usize = 4;
const I2_ROOT_BLOCK_COUNT: usize = 3;
const I3_ROOT_BLOCK_COUNT: usize = 2;

const PER_I1_LEAF_BLOCK_COUNT: usize = BLOCK_STORE_UNIT_COUNT;
const PER_I2_LEAF_BLOCK_COUNT: usize = PER_I1_LEAF_BLOCK_COUNT * BLOCK_STORE_UNIT_COUNT;
const PER_I3_LEAF_BLOCK_COUNT: usize = PER_I2_LEAF_BLOCK_COUNT * BLOCK_STORE_UNIT_COUNT;

const TOTAL_I1_LEAF_BLOCK_COUNT: usize = I1_ROOT_BLOCK_COUNT * PER_I1_LEAF_BLOCK_COUNT;
const TOTAL_I2_LEAF_BLOCK_COUNT: usize = I2_ROOT_BLOCK_COUNT * PER_I2_LEAF_BLOCK_COUNT;
const TOTAL_I3_LEAF_BLOCK_COUNT: usize = I3_ROOT_BLOCK_COUNT * PER_I3_LEAF_BLOCK_COUNT;

const PER_I1_TOTAL_BLOCK_COUNT: usize = I1_ROOT_BLOCK_COUNT;
const PER_I2_TOTAL_BLOCK_COUNT: usize = I2_ROOT_BLOCK_COUNT * (1 + PER_I1_LEAF_BLOCK_COUNT);

const MAX_INODE_BYTE_SIZE: u64 = BLOCK_BYTE_SIZE as u64
    * (TOTAL_I1_LEAF_BLOCK_COUNT + TOTAL_I2_LEAF_BLOCK_COUNT + TOTAL_I3_LEAF_BLOCK_COUNT) as u64;

type IndirectBlock = [u32; BLOCK_STORE_UNIT_COUNT];
pub type DataBlock = [u8; BLOCK_BYTE_SIZE];

///
enum HopLevel {
    Direct(usize),
    Indirect1(usize, usize),
    Indirect2(usize, usize, usize),
    Indirect3(usize, usize, usize, usize),
}
impl HopLevel {
    fn cal_from(leaf_index: u32) -> Result<Self> {
        let mut leaf_index = leaf_index as usize;
        if leaf_index < DIRECT_ROOT_BLOCK_COUNT {
            return Ok(HopLevel::Direct(leaf_index));
        }
        leaf_index -= DIRECT_ROOT_BLOCK_COUNT;
        if leaf_index < TOTAL_I1_LEAF_BLOCK_COUNT {
            return Ok(HopLevel::Indirect1(
                leaf_index / PER_I1_LEAF_BLOCK_COUNT,
                leaf_index % PER_I1_LEAF_BLOCK_COUNT,
            ));
        }
        leaf_index -= TOTAL_I1_LEAF_BLOCK_COUNT;
        if leaf_index < TOTAL_I2_LEAF_BLOCK_COUNT {
            return Ok(HopLevel::Indirect2(
                leaf_index / PER_I2_LEAF_BLOCK_COUNT,
                (leaf_index % PER_I2_LEAF_BLOCK_COUNT) / PER_I1_LEAF_BLOCK_COUNT,
                leaf_index % PER_I1_LEAF_BLOCK_COUNT,
            ));
        };
        leaf_index -= TOTAL_I2_LEAF_BLOCK_COUNT;
        if leaf_index < TOTAL_I3_LEAF_BLOCK_COUNT {
            return Ok(HopLevel::Indirect3(
                leaf_index / PER_I3_LEAF_BLOCK_COUNT,
                (leaf_index % PER_I3_LEAF_BLOCK_COUNT) / PER_I2_LEAF_BLOCK_COUNT,
                ((leaf_index % PER_I3_LEAF_BLOCK_COUNT) % PER_I2_LEAF_BLOCK_COUNT)
                    / PER_I1_LEAF_BLOCK_COUNT,
                leaf_index % PER_I1_LEAF_BLOCK_COUNT,
            ));
        }
        Err(FFSError::DataOutOfBounds)
    }
}

/// The type of the disk inode, which defines the structure of the block mapping.
/// The entire structure occupies 128 bytes and contains four types of block ids with different addressing depths.
///
/// Bitmap indexes area stores as u32, so theoretically,
/// an disk inode object can only store a maximum of 8204GB(0x80301000000) raw data.
///
/// But in fact, in order for an inode to represent more data,
/// we need to use the space on the block device to store which data blocks are currently used by the inode,
/// so an inode is often a little larger than the raw data, usually requires the use of the raw data size (1/4000)
///
/// # Direct block ids
/// single direct block id
///     --> data block(raw data)
///
/// # Level 1 indirect block id
/// single indirect block id
///     --> data block(list of block ids)
///         --> data block(raw data)
///
/// # Level 2 indirect block id
/// single indirect block id
///     --> data block(list of block ids)
///         --> data block(list of block ids)
///             --> data block(raw data)
///
/// # Level 3 indirect block id
/// single indirect block id
///     --> data block(list of block ids)
///         --> data block(list of block ids)
///             --> data block(list of block ids)
///                 --> data block(raw data)
///
#[repr(C)]
#[derive(Clone)]
pub struct DiskInode {
    /// The byte size of the file raw data.
    /// This size is always little smaller than the size which file was allocated,
    /// because the application for the occupation of file is always done in blocks.
    byte_size: u64,
    /// List of data block ids which are directly pointing to data blocks
    direct: [u32; DIRECT_ROOT_BLOCK_COUNT],
    /// List of data block ids which area indirectly pointing to data blocks by one hop
    indirect1: [u32; I1_ROOT_BLOCK_COUNT],
    /// List of data block ids which area indirectly pointing to data blocks by two hops
    indirect2: [u32; I2_ROOT_BLOCK_COUNT],
    /// List of data block ids which area indirectly pointing to data blocks by three hops
    indirect3: [u32; I3_ROOT_BLOCK_COUNT],
}
impl DiskInode {
    fn cal_allocated_byte_size(new_byte_size: u64) -> u64 {
        let remainder = BLOCK_BYTE_SIZE as u64;
        ((new_byte_size + remainder - 1) / remainder) * remainder
    }

    /// Calculate the leaf blocks needed to save the raw data
    ///
    /// # Arguments
    /// * byte_size: The byte size of the raw data
    ///
    /// # Returns
    /// * Ok(leaf block count)
    /// * Err(FFSError::DataOutOfBounds)
    fn cal_leaf_block_count(byte_size: u64) -> Result<u32> {
        if byte_size <= MAX_INODE_BYTE_SIZE {
            Ok(((byte_size + BLOCK_BYTE_SIZE as u64 - 1) / BLOCK_BYTE_SIZE as u64) as u32)
        } else {
            Err(FFSError::DataOutOfBounds)
        }
    }

    /// Calcuate the level 1 branch blocks needed to save the block ids of the raw data
    ///
    /// # Arguments
    /// * leaf_block_count: the count of the leaf blocks which only need to save in the level 1 indrect.
    fn cal_i1_branch_block_count(leaf_block_count: usize) -> usize {
        let index = leaf_block_count / PER_I1_LEAF_BLOCK_COUNT;
        let remainder = leaf_block_count % PER_I1_LEAF_BLOCK_COUNT;
        if remainder > 0 {
            index + 1
        } else {
            index
        }
    }

    /// Calcuate the level 2 branch blocks needed to save the block ids of the raw data
    ///
    /// # Arguments
    /// * leaf_block_count: the count of the leaf blocks which only need to save in the level 2 indrect.
    fn cal_i2_branch_block_count(leaf_block_count: usize) -> usize {
        let index = leaf_block_count / PER_I2_LEAF_BLOCK_COUNT;
        let remainder = leaf_block_count % PER_I2_LEAF_BLOCK_COUNT;
        let total = index * (1 + PER_I1_LEAF_BLOCK_COUNT);
        if remainder > 0 {
            total + 1 + Self::cal_i1_branch_block_count(remainder)
        } else {
            total
        }
    }

    /// Calcuate the level 3 branch blocks needed to save the block ids of the raw data
    ///
    /// # Arguments
    /// * leaf_block_count: the count of the leaf blocks which only need to save in the level 3 indrect.
    fn cal_i3_branch_block_count(leaf_block_count: usize) -> usize {
        let index = leaf_block_count / PER_I3_LEAF_BLOCK_COUNT;
        let remainder = leaf_block_count % PER_I3_LEAF_BLOCK_COUNT;
        let total = index * (1 + PER_I1_LEAF_BLOCK_COUNT + PER_I2_LEAF_BLOCK_COUNT);
        if remainder > 0 {
            total + 1 + Self::cal_i2_branch_block_count(remainder)
        } else {
            total
        }
    }

    /// calculate the total count of blocks which include all branch blocks and leaf blocks
    ///
    /// # Arguments
    /// * byte_size: the byte size of the raw data which you want to store into the inode
    ///
    /// # Returns
    /// * Ok(total block count)
    /// * Err(FFSError::DataOutOfBounds)
    fn cal_total_block_count(byte_size: u64) -> Result<u32> {
        let mut leaf_block_count = Self::cal_leaf_block_count(byte_size)? as usize;
        let mut total = leaf_block_count;
        if leaf_block_count <= DIRECT_ROOT_BLOCK_COUNT {
            return Ok(total as u32);
        }
        leaf_block_count -= DIRECT_ROOT_BLOCK_COUNT;
        if leaf_block_count <= TOTAL_I1_LEAF_BLOCK_COUNT {
            return Ok((total + Self::cal_i1_branch_block_count(leaf_block_count)) as u32);
        }
        leaf_block_count -= TOTAL_I1_LEAF_BLOCK_COUNT;
        total += PER_I1_TOTAL_BLOCK_COUNT;
        if leaf_block_count <= TOTAL_I2_LEAF_BLOCK_COUNT {
            return Ok((total + Self::cal_i2_branch_block_count(leaf_block_count)) as u32);
        }
        leaf_block_count -= TOTAL_I2_LEAF_BLOCK_COUNT;
        total += PER_I2_TOTAL_BLOCK_COUNT;
        if leaf_block_count <= TOTAL_I3_LEAF_BLOCK_COUNT {
            Ok((total + Self::cal_i3_branch_block_count(leaf_block_count)) as u32)
        } else {
            Err(FFSError::DataOutOfBounds)
        }
    }

    #[inline(always)]
    pub fn byte_size(&self) -> u64 {
        self.byte_size
    }

    /// Obtain the number of blocks to be added
    ///
    /// # Arguments
    /// * new_byte_size: the new byte size of the raw data, it should be greater than the current.
    ///
    /// # Returns
    /// * Ok(more blocks count)
    /// * Err(FFSError::DataOutOfBounds)
    pub fn blocks_needed(&self, new_byte_size: u64) -> Result<u32> {
        if self.byte_size < new_byte_size {
            Ok(Self::cal_total_block_count(new_byte_size)? - self.total_block_count())
        } else {
            Ok(0)
        }
    }

    #[inline(always)]
    pub fn leaf_block_count(&self) -> u32 {
        Self::cal_leaf_block_count(self.byte_size).unwrap()
    }

    #[inline(always)]
    pub fn total_block_count(&self) -> u32 {
        Self::cal_total_block_count(self.byte_size).unwrap()
    }

    /// Create a new disk inode and write it into the block device
    ///
    /// # Arguments
    /// * block_id: the unique id of the block in the block device
    /// * offset: the number of the offset in a single block
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(FFSError::DataOutOfBounds | FFSError::NoDroptableBlockCache)
    #[inline(always)]
    pub fn new(block_id: u32, offset: usize, device: &Arc<dyn BlockDevice>) -> Result<()> {
        BLOCK_CACHE_MANAGER
            .get_cache(block_id as usize, device)?
            .lock()
            .modify(offset, |inode: &mut Self| {
                inode.initialize();
            })
    }

    #[inline(always)]
    pub fn get(block_id: u32, offset: usize, device: &Arc<dyn BlockDevice>) -> Result<Self> {
        BLOCK_CACHE_MANAGER
            .get_cache(block_id as usize, device)?
            .lock()
            .read(offset, |inode: &Self| inode.clone())
    }

    /// Initially make the disk inode empty, be careful all the blocks are not dealloced yet.
    #[inline(always)]
    pub fn initialize(&mut self) {
        self.byte_size = 0;
        self.direct.iter_mut().for_each(|v| *v = 0);
        self.indirect1.iter_mut().for_each(|v| *v = 0);
        self.indirect2.iter_mut().for_each(|v| *v = 0);
        self.indirect3.iter_mut().for_each(|v| *v = 0);
    }

    /// Get the block id from indirect branch block by single hop
    ///
    /// # Arguments
    /// * block_id: the id of the indirect block
    /// * offset: the number of the offset which points to the next block
    /// * device: the dynamic device to be used
    #[inline(always)]
    fn get_indirect_block_id(
        block_id: usize,
        offset: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<u32> {
        BLOCK_CACHE_MANAGER
            .get_cache(block_id, device)?
            .lock()
            .read(0, |block: &IndirectBlock| block[offset])
    }

    /// Get the block id from level 1 indirect branch block by single hop
    ///
    /// # Arguments
    /// * index1: the index of the block id in level 1
    /// * offset: the number of the offset which points to the next block
    /// * device: the dynamic device to be used
    #[inline(always)]
    fn get_indirect1_block_id(
        &self,
        index1: usize,
        offset: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<u32> {
        Self::get_indirect_block_id(self.indirect1[index1] as usize, offset, device)
    }

    /// Get the block id from level 2 indirect branch block by two hops
    ///
    /// # Arguments
    /// * index2: the index of the block id in level 2
    /// * index1: the index of the block id in level 1
    /// * offset: the number of the offset which points to the next block
    /// * device: the dynamic device to be used
    #[inline(always)]
    fn get_indirect2_block_id(
        &self,
        index2: usize,
        index1: usize,
        offset: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<u32> {
        let indirect_block_id =
            Self::get_indirect_block_id(self.indirect2[index2] as usize, index1, device)?;
        Self::get_indirect_block_id(indirect_block_id as usize, offset, device)
    }

    /// Get the block id from level 2 indirect branch block by three hops
    ///
    /// # Arguments
    /// * index3: the index of the block id in level 3
    /// * index2: the index of the block id in level 2
    /// * index1: the index of the block id in level 1
    /// * offset: the number of the offset which points to the next block
    /// * device: the dynamic device to be used
    #[inline(always)]
    fn get_indirect3_block_id(
        &self,
        index3: usize,
        index2: usize,
        index1: usize,
        offset: usize,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<u32> {
        let indirect_block_id =
            Self::get_indirect_block_id(self.indirect3[index3] as usize, index2, device)?;
        let indirect_block_id =
            Self::get_indirect_block_id(indirect_block_id as usize, index1, device)?;
        Self::get_indirect_block_id(indirect_block_id as usize, offset, device)
    }

    /// Get the block id which stores the raw data
    ///
    /// # Arguments
    /// * leaf_index: the index of the leaf block which stores the raw data
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(block id)
    /// * Err(FFSError::DataOutOfBounds)
    pub fn get_block_id(&self, leaf_index: u32, device: &Arc<dyn BlockDevice>) -> Result<u32> {
        if leaf_index >= self.leaf_block_count() {
            return Err(FFSError::DataOutOfBounds);
        }
        match HopLevel::cal_from(leaf_index)? {
            HopLevel::Direct(index0) => Ok(self.direct[index0]),
            HopLevel::Indirect1(index1, index0) => {
                self.get_indirect1_block_id(index1, index0, device)
            }
            HopLevel::Indirect2(index2, index1, index0) => {
                self.get_indirect2_block_id(index2, index1, index0, device)
            }
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                self.get_indirect3_block_id(index3, index2, index1, index0, device)
            }
        }
    }

    fn _collect_block_ids(
        &self,
        start_leaf_index: u32,
        end_leaf_index: u32,
        block_count: u32,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<Vec<u32>> {
        let mut block_ids = vec![0; block_count as usize];
        let mut result_index = 0;
        for leaf_index in start_leaf_index..end_leaf_index {
            match HopLevel::cal_from(leaf_index)? {
                HopLevel::Direct(index0) => {
                    block_ids[result_index] = self.direct[index0];
                    result_index += 1;
                }
                HopLevel::Indirect1(index1, index0) => {
                    let pindex = self.indirect1[index1];
                    if index0 == 0 {
                        block_ids[result_index] = pindex;
                        result_index += 1;
                    }
                    block_ids[result_index] =
                        Self::get_indirect_block_id(pindex as usize, index0, device)?;
                    result_index += 1;
                }
                HopLevel::Indirect2(index2, index1, index0) => {
                    let pindex = self.indirect2[index2];
                    if index1 == 0 {
                        block_ids[result_index] = pindex;
                        result_index += 1;
                    }
                    let pindex = Self::get_indirect_block_id(pindex as usize, index1, device)?;
                    if index0 == 0 {
                        block_ids[result_index] = pindex;
                        result_index += 1;
                    }
                    block_ids[result_index] =
                        Self::get_indirect_block_id(pindex as usize, index0, device)?;
                    result_index += 1;
                }
                HopLevel::Indirect3(index3, index2, index1, index0) => {
                    let pindex = self.indirect3[index3];
                    if index2 == 0 {
                        block_ids[result_index] = pindex;
                        result_index += 1;
                    }
                    let pindex = Self::get_indirect_block_id(pindex as usize, index2, device)?;
                    if index1 == 0 {
                        block_ids[result_index] = pindex;
                        result_index += 1;
                    }
                    let pindex = Self::get_indirect_block_id(pindex as usize, index1, device)?;
                    if index0 == 0 {
                        block_ids[result_index] = pindex;
                        result_index += 1;
                    }
                    block_ids[result_index] =
                        Self::get_indirect_block_id(pindex as usize, index0, device)?;
                    result_index += 1;
                }
            }
        }
        Ok(block_ids)
    }

    /// clear the data in the leaf blocks and deallocate all of the leaf blocks and branch blocks
    ///
    /// # Arguments
    /// * device: the dynamic device to be used
    ///
    /// # Returns
    /// * Ok(Vec<block ids>)
    pub fn clear_byte_size(&mut self, device: &Arc<dyn BlockDevice>) -> Result<Vec<u32>> {
        let block_ids =
            self._collect_block_ids(0, self.leaf_block_count(), self.total_block_count(), device)?;
        self.initialize();
        Ok(block_ids)
    }

    pub fn decrease_to_byte_size(
        &mut self,
        new_byte_size: u64,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<Vec<u32>> {
        assert!(self.byte_size > new_byte_size);
        let origin_leaf_block_count = self.leaf_block_count();
        let origin_total_block_count = self.total_block_count();
        // try to collect dropable blocks
        let allocated_byte_size = Self::cal_allocated_byte_size(new_byte_size);
        let new_leaf_block_count = Self::cal_leaf_block_count(allocated_byte_size)?;
        let new_total_block_count = Self::cal_total_block_count(allocated_byte_size)?;
        let remove_block_count = origin_total_block_count - new_total_block_count;
        let block_ids = self._collect_block_ids(
            new_leaf_block_count,
            origin_leaf_block_count,
            remove_block_count,
            device,
        )?;
        // clear the last block's unusing bytes
        let origin_byte_size = self.byte_size;
        let buffer = vec![0u8; (origin_byte_size - new_byte_size) as usize];
        self.write_at(new_byte_size, &buffer, device)?;
        self.byte_size = new_byte_size;
        Ok(block_ids)
    }

    /// Increase raw data byte size to new one, write new block ids to inode.
    /// new block ids must be enough for new byte size, which may contains not only leaf block but also branch blocks.
    /// So before calling this function, you must call the Self::blocks_needed to know how many blocks should be allocated.
    /// Be careful, once you increase the bytes size, you only change the caches which blongs to the current disk inode,
    /// but the cache which contains the current disk inode was not updated yet!
    ///
    /// # Arguments
    /// * new_byte_size: the new byte size of the raw data
    /// * new_block_ids: contains not only leaf block but also branch block
    /// * device: the dynamic device to be used
    pub fn increase_to_byte_size(
        &mut self,
        new_byte_size: u64,
        new_block_ids: Vec<u32>,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<()> {
        assert!(self.byte_size < new_byte_size);
        let mut leaf_index = self.leaf_block_count();
        let mut offset = 0;
        let end = new_block_ids.len();
        self.byte_size = new_byte_size;
        while offset < end {
            match HopLevel::cal_from(leaf_index)? {
                HopLevel::Direct(inner_offset) => {
                    self.direct[inner_offset] = new_block_ids[offset];
                    leaf_index += 1;
                    offset += 1;
                }
                HopLevel::Indirect1(index1, inner_offset) => {
                    let indirect_block_id = if inner_offset == 0 {
                        let block_id = new_block_ids[offset];
                        self.indirect1[index1] = block_id;
                        offset += 1;
                        block_id
                    } else {
                        self.indirect1[index1]
                    };
                    BLOCK_CACHE_MANAGER
                        .get_cache(indirect_block_id as usize, device)?
                        .lock()
                        .modify(0, |block: &mut IndirectBlock| {
                            block[inner_offset] = new_block_ids[offset]
                        })?;
                    leaf_index += 1;
                    offset += 1;
                }
                HopLevel::Indirect2(index2, index1, inner_offset) => {
                    let indirect_block_id = if index1 == 0 {
                        let block_id = new_block_ids[offset];
                        self.indirect2[index2] = block_id;
                        offset += 1;
                        block_id
                    } else {
                        self.indirect2[index2]
                    };
                    let indirect_block_id = if inner_offset == 0 {
                        let block_id = new_block_ids[offset];
                        BLOCK_CACHE_MANAGER
                            .get_cache(indirect_block_id as usize, device)?
                            .lock()
                            .modify(0, |block: &mut IndirectBlock| block[index1] = block_id)?;
                        offset += 1;
                        block_id
                    } else {
                        Self::get_indirect_block_id(indirect_block_id as usize, index1, device)?
                    };
                    BLOCK_CACHE_MANAGER
                        .get_cache(indirect_block_id as usize, device)?
                        .lock()
                        .modify(0, |block: &mut IndirectBlock| {
                            block[inner_offset] = new_block_ids[offset]
                        })?;
                    leaf_index += 1;
                    offset += 1;
                }
                HopLevel::Indirect3(index3, index2, index1, inner_offset) => {
                    let indirect_block_id = if index2 == 0 {
                        let block_id = new_block_ids[offset];
                        self.indirect3[index3] = block_id;
                        offset += 1;
                        block_id
                    } else {
                        self.indirect3[index3]
                    };
                    let indirect_block_id = if index1 == 0 {
                        let block_id = new_block_ids[offset];
                        BLOCK_CACHE_MANAGER
                            .get_cache(indirect_block_id as usize, device)?
                            .lock()
                            .modify(0, |block: &mut IndirectBlock| block[index2] = block_id)?;
                        offset += 1;
                        block_id
                    } else {
                        Self::get_indirect_block_id(indirect_block_id as usize, index2, device)?
                    };
                    let indirect_block_id = if inner_offset == 0 {
                        let block_id = new_block_ids[offset];
                        BLOCK_CACHE_MANAGER
                            .get_cache(indirect_block_id as usize, device)?
                            .lock()
                            .modify(0, |block: &mut IndirectBlock| block[index1] = block_id)?;
                        offset += 1;
                        block_id
                    } else {
                        Self::get_indirect_block_id(indirect_block_id as usize, index1, device)?
                    };
                    BLOCK_CACHE_MANAGER
                        .get_cache(indirect_block_id as usize, device)?
                        .lock()
                        .modify(0, |block: &mut IndirectBlock| {
                            block[inner_offset] = new_block_ids[offset]
                        })?;
                    leaf_index += 1;
                    offset += 1;
                }
            }
        }
        Ok(())
    }

    /// Read data as bytes from a specified offset
    ///
    /// # Arguments
    /// * start_offset: the number of the offset which will be read as the start position
    /// * buffer: mutable reference to the buffer which will be written to bytes
    /// * device: the dynamic device to be used
    ///
    /// * Returns:
    /// * Ok(the byte size of the data which have been readed from block device and written to the buffer)
    pub fn read_at(
        &self,
        start_offset: u64,
        buffer: &mut [u8],
        device: &Arc<dyn BlockDevice>,
    ) -> Result<u64> {
        let end_offset = (start_offset + buffer.len() as u64).min(self.byte_size);
        if start_offset >= end_offset {
            return Ok(0);
        }
        let end_leaf_index = Self::cal_leaf_block_count(end_offset as u64)?;
        let start_leaf_index = (start_offset / BLOCK_BYTE_SIZE as u64) as u32;
        let mut read_byte_size = 0usize;
        for index in start_leaf_index..end_leaf_index {
            let src_begin = if index == start_leaf_index {
                (start_offset % BLOCK_BYTE_SIZE as u64) as usize
            } else {
                0
            };
            let src_end = if index == (end_leaf_index - 1) {
                (end_offset % BLOCK_BYTE_SIZE as u64) as usize
            } else {
                BLOCK_BYTE_SIZE
            };
            let src_byte_size = src_end - src_begin;
            let dst_begin = read_byte_size;
            let dst_end = dst_begin + src_byte_size;
            let dst = &mut buffer[dst_begin..dst_end];
            let block_id = self.get_block_id(index, device)?;
            BLOCK_CACHE_MANAGER
                .get_cache(block_id as usize, device)?
                .lock()
                .read(0, |block: &DataBlock| {
                    dst.copy_from_slice(&block[src_begin..src_end])
                })?;
            read_byte_size = dst_end;
        }
        Ok(read_byte_size as u64)
    }

    /// Write data as bytes to block device cache
    ///
    /// # Arguments
    /// * start_offset: the number of the offset which will be read as the start position
    /// * buffer: reference to the buffer which will be readed
    /// * device: the dynamic device to be used
    ///
    /// * Returns:
    /// * Ok(the byte size of the data which have been writed to block device cache)
    pub fn write_at(
        &mut self,
        start_offset: u64,
        buffer: &[u8],
        device: &Arc<dyn BlockDevice>,
    ) -> Result<u64> {
        let end_offset = (start_offset + buffer.len() as u64).min(self.byte_size);
        if start_offset >= end_offset {
            return Ok(0);
        }
        let end_leaf_index = Self::cal_leaf_block_count(end_offset as u64)?;
        let start_leaf_index = (start_offset / BLOCK_BYTE_SIZE as u64) as u32;
        let mut write_byte_size = 0usize;
        for index in start_leaf_index..end_leaf_index {
            let dst_begin = if index == start_leaf_index {
                (start_offset % BLOCK_BYTE_SIZE as u64) as usize
            } else {
                0
            };
            let dst_end = if index == (end_leaf_index - 1) {
                let dst_end = (end_offset % BLOCK_BYTE_SIZE as u64) as usize;
                if dst_end == 0 {
                    BLOCK_BYTE_SIZE
                } else {
                    dst_end
                }
            } else {
                BLOCK_BYTE_SIZE
            };

            let dst_byte_size = dst_end - dst_begin;
            let src_begin = write_byte_size;
            let src_end = src_begin + dst_byte_size;
            let src = &buffer[src_begin..src_end];
            let block_id = self.get_block_id(index, device)?;
            BLOCK_CACHE_MANAGER
                .get_cache(block_id as usize, device)?
                .lock()
                .modify(0, |block: &mut DataBlock| {
                    block[dst_begin..dst_end].copy_from_slice(src)
                })?;
            write_byte_size = src_end;
        }
        Ok(write_byte_size as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MockBlockDevice;

    #[test]
    fn test_hop_level_cal_from() {
        match HopLevel::cal_from(0).unwrap() {
            HopLevel::Direct(index0) => assert_eq!(0, index0),
            _ => unreachable!(),
        }
        match HopLevel::cal_from(1).unwrap() {
            HopLevel::Direct(index0) => assert_eq!(1, index0),
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT - 1) as u32).unwrap() {
            HopLevel::Direct(index0) => assert_eq!(DIRECT_ROOT_BLOCK_COUNT - 1, index0),
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT) as u32).unwrap() {
            HopLevel::Indirect1(index1, index0) => {
                assert_eq!(0, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT + 1) as u32).unwrap() {
            HopLevel::Indirect1(index1, index0) => {
                assert_eq!(0, index1);
                assert_eq!(1, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT + PER_I1_LEAF_BLOCK_COUNT) as u32)
            .unwrap()
        {
            HopLevel::Indirect1(index1, index0) => {
                assert_eq!(1, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT - 1) as u32)
            .unwrap()
        {
            HopLevel::Indirect1(index1, index0) => {
                assert_eq!(I1_ROOT_BLOCK_COUNT - 1, index1);
                assert_eq!(BLOCK_STORE_UNIT_COUNT - 1, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT) as u32)
            .unwrap()
        {
            HopLevel::Indirect2(index2, index1, index0) => {
                assert_eq!(0, index2);
                assert_eq!(0, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from((DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + 1) as u32)
            .unwrap()
        {
            HopLevel::Indirect2(index2, index1, index0) => {
                assert_eq!(0, index2);
                assert_eq!(0, index1);
                assert_eq!(1, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + PER_I1_LEAF_BLOCK_COUNT) as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect2(index2, index1, index0) => {
                assert_eq!(0, index2);
                assert_eq!(1, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + PER_I2_LEAF_BLOCK_COUNT) as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect2(index2, index1, index0) => {
                assert_eq!(1, index2);
                assert_eq!(0, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + TOTAL_I2_LEAF_BLOCK_COUNT - 1)
                as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect2(index2, index1, index0) => {
                assert_eq!(I2_ROOT_BLOCK_COUNT - 1, index2);
                assert_eq!(BLOCK_STORE_UNIT_COUNT - 1, index1);
                assert_eq!(BLOCK_STORE_UNIT_COUNT - 1, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + TOTAL_I2_LEAF_BLOCK_COUNT)
                as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                assert_eq!(0, index3);
                assert_eq!(0, index2);
                assert_eq!(0, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + TOTAL_I2_LEAF_BLOCK_COUNT + 1)
                as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                assert_eq!(0, index3);
                assert_eq!(0, index2);
                assert_eq!(0, index1);
                assert_eq!(1, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT
                + TOTAL_I1_LEAF_BLOCK_COUNT
                + TOTAL_I2_LEAF_BLOCK_COUNT
                + PER_I1_LEAF_BLOCK_COUNT) as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                assert_eq!(0, index3);
                assert_eq!(0, index2);
                assert_eq!(1, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT
                + TOTAL_I1_LEAF_BLOCK_COUNT
                + TOTAL_I2_LEAF_BLOCK_COUNT
                + PER_I2_LEAF_BLOCK_COUNT) as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                assert_eq!(0, index3);
                assert_eq!(1, index2);
                assert_eq!(0, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT
                + TOTAL_I1_LEAF_BLOCK_COUNT
                + TOTAL_I2_LEAF_BLOCK_COUNT
                + PER_I3_LEAF_BLOCK_COUNT) as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                assert_eq!(1, index3);
                assert_eq!(0, index2);
                assert_eq!(0, index1);
                assert_eq!(0, index0);
            }
            _ => unreachable!(),
        }
        match HopLevel::cal_from(
            (DIRECT_ROOT_BLOCK_COUNT
                + TOTAL_I1_LEAF_BLOCK_COUNT
                + TOTAL_I2_LEAF_BLOCK_COUNT
                + TOTAL_I3_LEAF_BLOCK_COUNT
                - 1) as u32,
        )
        .unwrap()
        {
            HopLevel::Indirect3(index3, index2, index1, index0) => {
                assert_eq!(I3_ROOT_BLOCK_COUNT - 1, index3);
                assert_eq!(BLOCK_STORE_UNIT_COUNT - 1, index2);
                assert_eq!(BLOCK_STORE_UNIT_COUNT - 1, index1);
                assert_eq!(BLOCK_STORE_UNIT_COUNT - 1, index0);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_disk_inode_cal_leaf_block_count() {
        assert_eq!(0, DiskInode::cal_leaf_block_count(0).unwrap());
        assert_eq!(1, DiskInode::cal_leaf_block_count(1).unwrap());
        assert_eq!(
            1,
            DiskInode::cal_leaf_block_count(BLOCK_BYTE_SIZE as u64 - 1).unwrap()
        );
        assert_eq!(
            1,
            DiskInode::cal_leaf_block_count(BLOCK_BYTE_SIZE as u64).unwrap()
        );
        assert_eq!(
            2,
            DiskInode::cal_leaf_block_count(BLOCK_BYTE_SIZE as u64 + 1).unwrap()
        );
    }

    #[test]
    fn test_disk_inode_cal_i1_branch_block_count() {
        assert_eq!(0, DiskInode::cal_i1_branch_block_count(0));
        assert_eq!(1, DiskInode::cal_i1_branch_block_count(1));
        assert_eq!(
            1,
            DiskInode::cal_i1_branch_block_count(BLOCK_STORE_UNIT_COUNT - 1)
        );
        assert_eq!(
            1,
            DiskInode::cal_i1_branch_block_count(BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            2,
            DiskInode::cal_i1_branch_block_count(BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            2,
            DiskInode::cal_i1_branch_block_count(
                BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT - 1
            )
        );
        assert_eq!(
            2,
            DiskInode::cal_i1_branch_block_count(BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            3,
            DiskInode::cal_i1_branch_block_count(
                BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT + 1
            )
        );
    }

    #[test]
    fn test_disk_inode_cal_i2_branch_block_count() {
        assert_eq!(0, DiskInode::cal_i2_branch_block_count(0));
        assert_eq!(2, DiskInode::cal_i2_branch_block_count(1));
        assert_eq!(
            2,
            DiskInode::cal_i2_branch_block_count(BLOCK_STORE_UNIT_COUNT - 1)
        );
        assert_eq!(
            2,
            DiskInode::cal_i2_branch_block_count(BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            3,
            DiskInode::cal_i2_branch_block_count(BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            3,
            DiskInode::cal_i2_branch_block_count(2 * BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            4,
            DiskInode::cal_i2_branch_block_count(2 * BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            4,
            DiskInode::cal_i2_branch_block_count(3 * BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            5,
            DiskInode::cal_i2_branch_block_count(3 * BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            BLOCK_STORE_UNIT_COUNT + 1,
            DiskInode::cal_i2_branch_block_count(BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            BLOCK_STORE_UNIT_COUNT + 3,
            DiskInode::cal_i2_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT + 1
            )
        );
    }

    #[test]
    fn test_disk_inode_cal_i3_branch_block_count() {
        assert_eq!(0, DiskInode::cal_i3_branch_block_count(0));
        assert_eq!(3, DiskInode::cal_i3_branch_block_count(1));

        assert_eq!(
            3,
            DiskInode::cal_i3_branch_block_count(BLOCK_STORE_UNIT_COUNT - 1)
        );
        assert_eq!(
            3,
            DiskInode::cal_i3_branch_block_count(BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            4,
            DiskInode::cal_i3_branch_block_count(BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            4,
            DiskInode::cal_i3_branch_block_count(2 * BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            5,
            DiskInode::cal_i3_branch_block_count(2 * BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            5,
            DiskInode::cal_i3_branch_block_count(3 * BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            6,
            DiskInode::cal_i3_branch_block_count(3 * BLOCK_STORE_UNIT_COUNT + 1)
        );
        assert_eq!(
            BLOCK_STORE_UNIT_COUNT + 2,
            DiskInode::cal_i3_branch_block_count(BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT)
        );
        assert_eq!(
            BLOCK_STORE_UNIT_COUNT + 4,
            DiskInode::cal_i3_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT + 1
            )
        );
        assert_eq!(
            1 + BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT,
            DiskInode::cal_i3_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT
            )
        );
        assert_eq!(
            1 + BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT + 3,
            DiskInode::cal_i3_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT + 1
            )
        );
        assert_eq!(
            1 + BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT + 3,
            DiskInode::cal_i3_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT
                    + BLOCK_STORE_UNIT_COUNT
            )
        );
        assert_eq!(
            1 + BLOCK_STORE_UNIT_COUNT + BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT + 4,
            DiskInode::cal_i3_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT
                    + BLOCK_STORE_UNIT_COUNT
                    + 1
            )
        );
        assert_eq!(
            1 + BLOCK_STORE_UNIT_COUNT
                + BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT
                + 2
                + BLOCK_STORE_UNIT_COUNT,
            DiskInode::cal_i3_branch_block_count(
                BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT
                    + BLOCK_STORE_UNIT_COUNT * BLOCK_STORE_UNIT_COUNT
            )
        );
    }

    #[test]
    fn test_disk_inode_cal_total_block_count() {
        assert_eq!(0, DiskInode::cal_total_block_count(0).unwrap());
        assert_eq!(1, DiskInode::cal_total_block_count(1).unwrap());
        assert_eq!(
            1,
            DiskInode::cal_total_block_count(BLOCK_BYTE_SIZE as u64).unwrap()
        );
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32,
            DiskInode::cal_total_block_count((DIRECT_ROOT_BLOCK_COUNT * BLOCK_BYTE_SIZE) as u64)
                .unwrap()
        );
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32 + 2,
            DiskInode::cal_total_block_count(
                (DIRECT_ROOT_BLOCK_COUNT * BLOCK_BYTE_SIZE + 1) as u64
            )
            .unwrap()
        );
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32 + 2,
            DiskInode::cal_total_block_count(
                (DIRECT_ROOT_BLOCK_COUNT * BLOCK_BYTE_SIZE + BLOCK_BYTE_SIZE) as u64
            )
            .unwrap()
        );
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32 + 3,
            DiskInode::cal_total_block_count(
                (DIRECT_ROOT_BLOCK_COUNT * BLOCK_BYTE_SIZE + BLOCK_BYTE_SIZE + 1) as u64
            )
            .unwrap()
        );
        assert_eq!(
            (DIRECT_ROOT_BLOCK_COUNT + BLOCK_STORE_UNIT_COUNT + 1) as u32,
            DiskInode::cal_total_block_count(
                (BLOCK_BYTE_SIZE * (DIRECT_ROOT_BLOCK_COUNT + BLOCK_STORE_UNIT_COUNT)) as u64
            )
            .unwrap()
        );
        assert_eq!(
            (DIRECT_ROOT_BLOCK_COUNT + PER_I1_TOTAL_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT) as u32,
            DiskInode::cal_total_block_count(
                (BLOCK_BYTE_SIZE * (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT)) as u64
            )
            .unwrap()
        );
        assert_eq!(
            (DIRECT_ROOT_BLOCK_COUNT + PER_I1_TOTAL_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + 3)
                as u32,
            DiskInode::cal_total_block_count(
                (BLOCK_BYTE_SIZE * (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT) + 1)
                    as u64
            )
            .unwrap()
        );
        assert_eq!(
            (DIRECT_ROOT_BLOCK_COUNT + PER_I1_TOTAL_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + 4)
                as u32,
            DiskInode::cal_total_block_count(
                (BLOCK_BYTE_SIZE * (DIRECT_ROOT_BLOCK_COUNT + TOTAL_I1_LEAF_BLOCK_COUNT + 1) + 1)
                    as u64
            )
            .unwrap()
        );
        assert_eq!(
            (DIRECT_ROOT_BLOCK_COUNT
                + PER_I1_TOTAL_BLOCK_COUNT
                + TOTAL_I1_LEAF_BLOCK_COUNT
                + PER_I2_TOTAL_BLOCK_COUNT
                + TOTAL_I2_LEAF_BLOCK_COUNT) as u32,
            DiskInode::cal_total_block_count(
                (BLOCK_BYTE_SIZE
                    * (DIRECT_ROOT_BLOCK_COUNT
                        + TOTAL_I1_LEAF_BLOCK_COUNT
                        + TOTAL_I2_LEAF_BLOCK_COUNT)) as u64
            )
            .unwrap()
        );
        assert_eq!(
            (DIRECT_ROOT_BLOCK_COUNT
                + PER_I1_TOTAL_BLOCK_COUNT
                + TOTAL_I1_LEAF_BLOCK_COUNT
                + PER_I2_TOTAL_BLOCK_COUNT
                + TOTAL_I2_LEAF_BLOCK_COUNT
                + 4) as u32,
            DiskInode::cal_total_block_count(
                (BLOCK_BYTE_SIZE
                    * (DIRECT_ROOT_BLOCK_COUNT
                        + TOTAL_I1_LEAF_BLOCK_COUNT
                        + TOTAL_I2_LEAF_BLOCK_COUNT)
                    + 1) as u64
            )
            .unwrap()
        );
    }

    #[test]
    fn test_disk_inode_blocks_needed() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode = DiskInode::get(0, 0, &device).unwrap();
        assert_eq!(0, inode.blocks_needed(0).unwrap());
        assert_eq!(1, inode.blocks_needed(1).unwrap());
        assert_eq!(1, inode.blocks_needed(BLOCK_BYTE_SIZE as u64).unwrap());
        assert_eq!(2, inode.blocks_needed(BLOCK_BYTE_SIZE as u64 + 1).unwrap());
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32,
            inode
                .blocks_needed((BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64)
                .unwrap()
        );
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32 + 2,
            inode
                .blocks_needed((BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64 + 1)
                .unwrap()
        );
        inode.byte_size = 1;
        assert_eq!(0, inode.blocks_needed(0).unwrap());
        assert_eq!(0, inode.blocks_needed(1).unwrap());
        assert_eq!(0, inode.blocks_needed(BLOCK_BYTE_SIZE as u64).unwrap());
        assert_eq!(1, inode.blocks_needed(BLOCK_BYTE_SIZE as u64 + 1).unwrap());
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32 - 1,
            inode
                .blocks_needed((BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64)
                .unwrap()
        );
        assert_eq!(
            DIRECT_ROOT_BLOCK_COUNT as u32 + 1,
            inode
                .blocks_needed((BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64 + 1)
                .unwrap()
        );
    }

    #[test]
    fn test_disk_inode_leaf_block_count() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode = DiskInode::get(0, 0, &device).unwrap();
        assert_eq!(0, inode.leaf_block_count());
        inode.byte_size = 1;
        assert_eq!(1, inode.leaf_block_count());
        inode.byte_size = BLOCK_BYTE_SIZE as u64;
        assert_eq!(1, inode.leaf_block_count());
        inode.byte_size = BLOCK_BYTE_SIZE as u64 + 1;
        assert_eq!(2, inode.leaf_block_count());
        inode.byte_size = (BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64;
        assert_eq!(DIRECT_ROOT_BLOCK_COUNT as u32, inode.leaf_block_count());
        inode.byte_size = (BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64 + 1;
        assert_eq!(DIRECT_ROOT_BLOCK_COUNT as u32 + 1, inode.leaf_block_count());
    }

    #[test]
    fn test_disk_inode_new() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        assert!(DiskInode::new(0, 0, &device).is_ok());
        let mut inode1 = DiskInode::get(0, 0, &device).unwrap();
        assert_eq!(0, inode1.byte_size());
        assert!(inode1.increase_to_byte_size(1, vec![1], &device).is_ok());
        assert_eq!(1, inode1.byte_size());
        assert!(DiskInode::new(0, 0, &device).is_ok());
        let inode1 = DiskInode::get(0, 0, &device).unwrap();
        assert_eq!(0, inode1.byte_size());
    }

    #[test]
    fn test_disk_inode_get_byte_size() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode1 = DiskInode::get(0, 0, &device).unwrap();
        assert_eq!(0, inode1.byte_size());
        inode1.byte_size = 2;
        assert_eq!(2, inode1.byte_size());
        let mut inode2 = DiskInode::get(0, 0, &device).unwrap();
        assert_eq!(2, inode1.byte_size());
        assert_eq!(0, inode2.byte_size());
        inode1.byte_size = 0;
        inode2.byte_size = 2;
        assert_eq!(0, inode1.byte_size());
        assert_eq!(2, inode2.byte_size());
    }

    #[test]
    fn test_disk_inode_get_block_id_and_clear_byte_size() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode = DiskInode::get(0, 0, &device).unwrap();
        let mut block_ids = vec![];
        for id in 0..=DIRECT_ROOT_BLOCK_COUNT + 1 {
            block_ids.push(id as u32);
        }
        assert!(inode
            .get_block_id(0, &device)
            .is_err_and(|e| e.is_dataoutofbounds()));
        assert!(inode
            .increase_to_byte_size(1, block_ids[0..1].to_vec(), &device)
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_err());
        assert!(inode
            .clear_byte_size(&device)
            .is_ok_and(|block_ids| { block_ids.len() == 1 && block_ids[0] == 0 }));
        assert!(inode
            .increase_to_byte_size(BLOCK_BYTE_SIZE as u64, block_ids[0..1].to_vec(), &device)
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_err());
        assert!(inode
            .clear_byte_size(&device)
            .is_ok_and(|block_ids| { block_ids.len() == 1 && block_ids[0] == 0 }));
        assert!(inode
            .increase_to_byte_size(
                BLOCK_BYTE_SIZE as u64 + 1,
                block_ids[0..2].to_vec(),
                &device
            )
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_ok_and(|id| *id == 1));
        assert!(inode.get_block_id(2, &device).is_err());
        assert!(inode.clear_byte_size(&device).is_ok_and(|block_ids| {
            block_ids.len() == 2 && block_ids[0] == 0 && block_ids[1] == 1
        }));
    }

    #[test]
    fn test_disk_inode_decrease_to_byte_size() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode = DiskInode::get(0, 0, &device).unwrap();
        let mut read_buffer = [0u8; BLOCK_BYTE_SIZE + 1];
        let write_buffer = [1u8; BLOCK_BYTE_SIZE + 1];
        let mut block_ids = vec![];
        for id in 0..=DIRECT_ROOT_BLOCK_COUNT + 1 {
            block_ids.push(id as u32);
        }
        assert!(inode
            .get_block_id(0, &device)
            .is_err_and(|e| e.is_dataoutofbounds()));

        assert!(inode
            .increase_to_byte_size(
                (BLOCK_BYTE_SIZE + 2) as u64,
                block_ids[0..2].to_vec(),
                &device
            )
            .is_ok());
        assert!(inode
            .decrease_to_byte_size(BLOCK_BYTE_SIZE as u64 + 1, &device)
            .is_ok_and(|block_ids| block_ids.len() == 0));
        assert!(inode
            .decrease_to_byte_size(BLOCK_BYTE_SIZE as u64, &device)
            .is_ok_and(|block_ids| block_ids.len() == 1 && block_ids[0] == 1));
        assert!(inode
            .decrease_to_byte_size(3, &device)
            .is_ok_and(|block_ids| block_ids.len() == 0));
        assert!(inode
            .write_at(0, &write_buffer, &device)
            .is_ok_and(|size| *size == 3));
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == 3));
        assert_eq!(1, read_buffer[0]);
        assert_eq!(1, read_buffer[1]);
        assert_eq!(1, read_buffer[2]);

        read_buffer[0] = 0;
        read_buffer[1] = 0;
        read_buffer[2] = 0;
        assert!(inode
            .decrease_to_byte_size(1, &device)
            .is_ok_and(|block_ids| block_ids.len() == 0));
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == 1));
        assert_eq!(1, read_buffer[0]);
        assert_eq!(0, read_buffer[1]);
        assert_eq!(0, read_buffer[2]);

        read_buffer[0] = 0;
        read_buffer[1] = 0;
        read_buffer[2] = 0;
        assert!(inode
            .decrease_to_byte_size(0, &device)
            .is_ok_and(|block_ids| block_ids.len() == 1 && block_ids[0] == 0));
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == 0));
        assert_eq!(0, read_buffer[0]);
        assert_eq!(0, read_buffer[1]);
        assert_eq!(0, read_buffer[2]);
    }

    #[test]
    fn test_disk_inode_get_block_id_and_increase_to_byte_size() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode = DiskInode::get(0, 0, &device).unwrap();
        let mut block_ids = vec![];
        for id in 0..=DIRECT_ROOT_BLOCK_COUNT + 1 {
            block_ids.push(id as u32);
        }
        assert!(inode
            .get_block_id(0, &device)
            .is_err_and(|e| e.is_dataoutofbounds()));
        assert!(inode
            .increase_to_byte_size(1, block_ids[0..1].to_vec(), &device)
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_err());
        assert!(inode
            .increase_to_byte_size(BLOCK_BYTE_SIZE as u64, vec![], &device)
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_err());
        assert!(inode
            .increase_to_byte_size(
                BLOCK_BYTE_SIZE as u64 + 1,
                block_ids[1..2].to_vec(),
                &device
            )
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_ok_and(|id| *id == 1));
        assert!(inode.get_block_id(2, &device).is_err());
        assert!(inode
            .increase_to_byte_size(
                (BLOCK_BYTE_SIZE * DIRECT_ROOT_BLOCK_COUNT) as u64 + 1,
                block_ids[2..=DIRECT_ROOT_BLOCK_COUNT + 1].to_vec(),
                &device
            )
            .is_ok());
        assert!(inode.get_block_id(0, &device).is_ok_and(|id| *id == 0));
        assert!(inode.get_block_id(1, &device).is_ok_and(|id| *id == 1));
        assert!(inode
            .get_block_id(DIRECT_ROOT_BLOCK_COUNT as u32 - 1, &device)
            .is_ok_and(|id| *id == DIRECT_ROOT_BLOCK_COUNT as u32 - 1));
        assert!(inode
            .get_block_id(DIRECT_ROOT_BLOCK_COUNT as u32, &device)
            .is_ok_and(|id| *id == DIRECT_ROOT_BLOCK_COUNT as u32 + 1));
        assert!(inode
            .get_block_id(DIRECT_ROOT_BLOCK_COUNT as u32 + 1, &device)
            .is_err());
    }

    #[test]
    fn test_disk_inode_read_at_and_write_at() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut inode = DiskInode::get(0, 0, &device).unwrap();
        let mut read_buffer = [0u8; BLOCK_BYTE_SIZE + 1];
        let write_buffer = [1u8; BLOCK_BYTE_SIZE + 1];
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == 0));

        assert!(inode.increase_to_byte_size(1, vec![0], &device).is_ok());
        assert!(inode
            .write_at(0, &write_buffer, &device)
            .is_ok_and(|size| *size == 1));
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == 1));
        assert_eq!(1, read_buffer[0]);

        assert!(inode.increase_to_byte_size(2, vec![], &device).is_ok());
        assert!(inode
            .write_at(0, &write_buffer, &device)
            .is_ok_and(|size| *size == 2));
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == 2));
        assert_eq!(1, read_buffer[0]);
        assert_eq!(1, read_buffer[1]);

        assert!(inode
            .increase_to_byte_size((BLOCK_BYTE_SIZE + 1) as u64, vec![1], &device)
            .is_ok());
        assert!(inode
            .write_at(0, &write_buffer, &device)
            .is_ok_and(|size| *size == (BLOCK_BYTE_SIZE + 1) as u64));
        assert!(inode
            .read_at(0, &mut read_buffer, &device)
            .is_ok_and(|size| *size == (BLOCK_BYTE_SIZE + 1) as u64));
        assert_eq!(1, read_buffer[0]);
        assert_eq!(1, read_buffer[1]);
        assert_eq!(1, read_buffer[BLOCK_BYTE_SIZE]);
    }
}
