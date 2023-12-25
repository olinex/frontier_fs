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
pub struct SuperBlock {
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
    pub fn initialize(
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
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.magic == FS_MAGIC
    }

    #[inline(always)]
    pub fn total_blocks(&self) -> u32 {
        self.total_blocks
    }

    #[inline(always)]
    pub fn inode_bitmap_blocks(&self) -> u32 {
        self.inode_bitmap_blocks
    }

    #[inline(always)]
    pub fn inode_area_blocks(&self) -> u32 {
        self.inode_area_blocks
    }

    #[inline(always)]
    pub fn data_bitmap_blocks(&self) -> u32 {
        self.data_bitmap_blocks
    }

    #[inline(always)]
    pub fn data_area_blocks(&self) -> u32 {
        self.data_area_blocks
    }

    #[inline(always)]
    pub fn disk_inodes(&self) -> u32 {
        self.disk_inodes
    }

    #[inline(always)]
    pub fn iabc(&self) -> u8 {
        self.iabc
    }
}
