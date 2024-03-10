// @author:    olinex
// @time:      2023/11/08

// self mods

// use other mods

// use self mods
use crate::configs::FS_MAGIC;

/// The super block hold information about the hierarchy within the viewport of the entire block device.
/// A block device has only one super block and is stored in the first block of data.
/// Frontier file system contains ive different block areas:
/// ```text
///                | <block area> |    <block count>
///                ----------------
///                | super block  | <-      1
///                ----------------
///                |              | <-
///             -- | inode bitmap |   |     inode bitmap area blocks
///             |  |              | <-
///      manage |  ----------------
///             |  |              | <-
/// manage      -> |    inode     |   |     inode area blocks
///    ----------- |              | <-
///    |           ----------------
///    |           |              | <-
///    |        -- | data bitmap  |   |     data bitmap area blocks
///    |        |  |              | <-
///    | manage |  ----------------
///    |        |  |              | <-
///    |        -> |    data      |   |     data area blocks
///    ----------> |              | <-
///                ----------------
/// ```
///
/// In order to avoid naming confusion, we will unify the various index names in the naming block device here:
/// * block id:                             The ID of a block that uniquely identifies the entire block device
/// * bitmap index:          
///     ** inode bitmap index:              
///     ** data bitmap index:
/// * area index:
///     ** inode area index:
///     ** data area index:
///
#[repr(C)]
pub(crate) struct SuperBlock {
    magic: u32,
    total_blocks: u32,
    inode_bitmap_blocks: u32,
    inode_area_blocks: u32,
    data_bitmap_blocks: u32,
    data_area_blocks: u32,
    disk_inodes: u32,
    iabc: u8,
}
impl SuperBlock {

    /// Initializing a superblock, which does not have `new` function, 
    /// is only stored or read directly by a pointer
    /// 
    /// # Arguments
    /// * total_blocks: the number of blocks in the block device
    /// * inode_bitmap_blocks: the number of the blocks which storing inode block bitmaps
    /// * inode_area_blocks: the number of the blocks which storing inode
    /// * data_bitmap_blocks: the number of the blocks which storing raw data block bitmaps
    /// * data_area_blocks: the number of the blocks which storing raw data
    /// * disk_inodes: the number of the disk inode allowed to be stored
    /// * iabc: he average block count of disk inode
    pub(crate) fn initialize(
        &mut self,
        total_blocks: u32,
        inode_bitmap_blocks: u32,
        inode_area_blocks: u32,
        data_bitmap_blocks: u32,
        data_area_blocks: u32,
        disk_inodes: u32,
        iabc: u8,
    ) {
        let used_blocks =
            inode_bitmap_blocks + inode_area_blocks + data_bitmap_blocks + data_area_blocks;
        assert!(total_blocks >= used_blocks);
        *self = Self {
            magic: FS_MAGIC,
            total_blocks,
            inode_bitmap_blocks,
            inode_area_blocks,
            data_bitmap_blocks,
            data_area_blocks,
            disk_inodes,
            iabc,
        }
    }

    /// Check the validation of the super block data
    pub(crate) fn is_valid(&self) -> bool {
        self.magic == FS_MAGIC
    }

    #[inline(always)]
    pub(crate) fn inode_bitmap_blocks(&self) -> u32 {
        self.inode_bitmap_blocks
    }

    #[inline(always)]
    pub(crate) fn inode_area_blocks(&self) -> u32 {
        self.inode_area_blocks
    }

    #[inline(always)]
    pub(crate) fn data_bitmap_blocks(&self) -> u32 {
        self.data_bitmap_blocks
    }

    #[inline(always)]
    pub(crate) fn data_area_blocks(&self) -> u32 {
        self.data_area_blocks
    }

    #[inline(always)]
    pub(crate) fn disk_inodes(&self) -> u32 {
        self.disk_inodes
    }
}
