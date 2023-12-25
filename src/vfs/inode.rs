// @author:    olinex
// @time:      2023/11/25

// self mods

// use other mods

use alloc::sync::Arc;
use spin::MutexGuard;

// use self mods
use super::ffs::{FrontierFileSystem, FS};
use crate::block::{BlockDevice, BLOCK_CACHE_MANAGER};
use crate::layout::DiskInode;
use crate::Result;

/// Abstract class for file in block device,
/// which contains the basic information and methods for controlling the real physical disk inode
pub struct Inode {
    /// the index of the disk inode in the bitmap
    inode_bitmap_index: u32,
    /// the block id in the block device, which contains the disk inode in the block
    disk_inode_block_id: u32,
    /// the offset of the disk inode in the block
    disk_inode_block_offset: usize,
    /// the inner mutable instance of the file system
    fs: FS,
    /// the dynamic device to be used
    device: Arc<dyn BlockDevice>,
}
// as raw file
impl Inode {
    /// Create a new Inode
    ///
    /// # Arguments
    /// * inode_bitmap_index: the index of the disk in the bitmap
    /// * disk_inode_block_id: the block id in the block device
    /// * disk_indde_block_offset: the offset of the disk inode in the block
    pub fn new(
        inode_bitmap_index: u32,
        disk_inode_block_id: u32,
        disk_inode_block_offset: usize,
        fs: &FS,
        device: &Arc<dyn BlockDevice>,
    ) -> Self {
        Self {
            inode_bitmap_index,
            disk_inode_block_id,
            disk_inode_block_offset,
            fs: Arc::clone(fs),
            device: Arc::clone(device),
        }
    }

    #[inline(always)]
    pub fn fs(&self) -> &FS {
        &self.fs
    }

    #[inline(always)]
    pub fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.device
    }

    #[inline(always)]
    pub fn disk_inode_block_id(&self) -> u32 {
        self.disk_inode_block_id
    }

    #[inline(always)]
    pub fn inode_bitmap_index(&self) -> u32 {
        self.inode_bitmap_index
    }

    /// Provides a method to reading disk inode and return the result of the closure
    ///
    /// # Arguments
    /// * f: the closure function which receives the reference of the disk inode and return the result
    ///
    /// # Returns
    /// * Ok(V): the result value wrapped in Result
    /// * Err(FFSError::NoDroptableBlockCache)
    /// * Err(FFSError::DataOutOfBounds)
    pub fn read_disk_inode<V>(&self, f: impl FnOnce(&DiskInode) -> V) -> Result<V> {
        BLOCK_CACHE_MANAGER
            .get_cache(self.disk_inode_block_id as usize, &self.device)?
            .lock()
            .read(self.disk_inode_block_offset, f)
    }

    /// Provides a method to writing disk inode and return the result of the closure
    ///
    /// # Arguments
    /// * f: the closure function which receives the mutable reference of the disk inode and return the result
    ///
    /// # Returns
    /// * Ok(V): the result value wrapped in Result
    /// * Err(FFSError::NoDroptableBlockCache)
    /// * Err(FFSError::DataOutOfBounds)
    pub fn modify_disk_inode<V>(&self, f: impl FnOnce(&mut DiskInode) -> V) -> Result<V> {
        BLOCK_CACHE_MANAGER
            .get_cache(self.disk_inode_block_id as usize, &self.device)?
            .lock()
            .modify(self.disk_inode_block_offset, f)
    }

    /// Change the disk inode byte size to the specified value.
    /// When the new byte size is greater than the original byte size, this method will allocate some needed new blocks.
    /// When the new byte size is smaller than the original byte size, this method will deallocate some blocks that are no longer in use.
    ///
    /// # Arguments
    /// * new_byte_size: the new byte size disk inode will changed to
    /// * disk_inode:
    pub fn to_byte_size(
        &self,
        new_byte_size: u64,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        let origin_byte_size = disk_inode.byte_size();
        let blocks_needed = disk_inode.blocks_needed(new_byte_size)?;
        if new_byte_size > origin_byte_size {
            let block_ids = fs.bulk_alloc_data_block_ids(blocks_needed)?;
            disk_inode.increase_to_byte_size(new_byte_size, block_ids, &self.device)
        } else if new_byte_size < origin_byte_size {
            let block_ids = disk_inode.decrease_to_byte_size(new_byte_size, &self.device)?;
            fs.bulk_dealloc_data_block_ids(block_ids)
        } else {
            Ok(())
        }
    }

    /// Get the count of the leaf blocks in the disk inode
    #[inline(always)]
    pub fn leaf_block_count(&self) -> Result<u32> {
        self.read_disk_inode(|disk_inode| disk_inode.leaf_block_count())
    }

    /// clear all blocks in the disk inode as a file.
    /// Be careful, this function does not deallocate the inode
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    pub fn clear_as_file(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<()> {
        let data_block_ids =
            self.modify_disk_inode(|disk_inode| disk_inode.clear_byte_size(&self.device))??;
        fs.bulk_dealloc_data_block_ids(data_block_ids)
    }
}

#[cfg(test)]
mod tests {
    use crate::{block::MockBlockDevice, configs::BLOCK_BYTE_SIZE, vfs::FileSystem};

    use super::*;

    #[test]
    fn test_inode_to_byte_size_and_leaf_block_count() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let fs = FS::initialize(15, 1, &device).unwrap();
        let inode = fs.root_inode();
        let mut mfs = fs.lock();
        assert_eq!(1, inode.leaf_block_count().unwrap());
        assert!(inode
            .modify_disk_inode(|disk_inode| {
                assert!(inode
                    .to_byte_size(2 * BLOCK_BYTE_SIZE as u64, disk_inode, &mut mfs)
                    .is_ok());
            })
            .is_ok());
        assert_eq!(2, inode.leaf_block_count().unwrap());
        assert!(inode
            .modify_disk_inode(|disk_inode| {
                assert!(inode
                    .to_byte_size(1 * BLOCK_BYTE_SIZE as u64, disk_inode, &mut mfs)
                    .is_ok());
            })
            .is_ok());
        assert_eq!(1, inode.leaf_block_count().unwrap());
    }
}
