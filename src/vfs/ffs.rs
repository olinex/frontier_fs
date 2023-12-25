// @author:    olinex
// @time:      2023/11/23

// self mods

use alloc::boxed::Box;
// use other mods
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

// use self mods
use super::{Directory, FileFlags, FileSystem, Inode};
use crate::block::{BlockDevice, BLOCK_CACHE_MANAGER};
use crate::configs::{BLOCK_BIT_SIZE, BLOCK_BYTE_SIZE};
use crate::layout::{Bitmap, DataBlock, DiskInode, SuperBlock};
use crate::{FFSError, Result};

const INODE_BITMAP_START_BLOCK_ID: u32 = 1;
const DISK_INODE_BYTE_SIZE: usize = core::mem::size_of::<DiskInode>();
const PER_BLOCK_DISK_INODE_COUNT: usize = BLOCK_BYTE_SIZE / DISK_INODE_BYTE_SIZE;

pub struct FrontierFileSystem {
    inode_bitmap: Bitmap,
    data_bitmap: Bitmap,
    inode_area_start_block_id: u32,
    data_area_start_block_id: u32,
    device: Arc<dyn BlockDevice>,
}
impl FrontierFileSystem {
    /// Calculates the count of the data bitmap blocks which these blocks map all data blocks in their entirety
    ///
    /// # Arguments
    /// * area_blocks: the count of the area blocks
    ///
    /// # Returns
    /// * u32: the count of the bitmap blocks
    fn cal_data_bitmap_blocks(data_area_blocks: u32) -> u32 {
        let bit_size = BLOCK_BIT_SIZE as u32;
        (data_area_blocks + bit_size - 1) / bit_size
    }

    /// Calculates the total disk inodes count
    ///
    /// # Arguments
    /// * data_area_blocks: the count of the data area blocks
    /// * iabc: the average blocks count of disk inode
    ///
    /// # Returns
    /// * u32: the count of the disk inode
    fn cal_disk_inodes(data_area_blocks: u32, iabc: u8) -> u32 {
        let iabc = iabc as u32;
        (data_area_blocks + iabc - 1) / iabc
    }

    /// Calculates the total blocks count of the inode area
    ///
    /// # Arguments
    /// * disk_inodes: the count of the disk inodes
    ///
    /// # Returns
    /// * u32: the count of the inode area
    fn cal_inode_area_blocks(disk_inodes: u32) -> u32 {
        let count = PER_BLOCK_DISK_INODE_COUNT as u32;
        (disk_inodes + count - 1) / count
    }

    /// Calculates the total blocks count of the inode bitmap area
    ///
    /// # Arguments
    /// * disk_inodes: the count of the disk inodes
    ///
    /// # Returns
    /// * u32: the count of the inode bitmap area
    fn cal_inode_bitmap_blocks(disk_inodes: u32) -> u32 {
        let bit_size = BLOCK_BIT_SIZE as u32;
        (disk_inodes + bit_size - 1) / bit_size
    }

    /// We can use a math function y=f(x) to calculate the recommended data blocks
    /// * Set x = data_area_blocks
    /// * Set y = total_blocks
    /// * Set bbs = BLOCK_BIT_SIZE
    /// * Set iabc = PER_INODE_AVG_BLOCK_COUNt
    /// * Set dic = PER_BLOCK_DISK_INODE_COUNT
    ///
    /// ```text
    /// We knows that:
    ///     data_bitmap_blocks = ((x + bbs - 1) / bbs)
    ///     inode_area_blocks = ((((x + iabc - 1) / ibac) + dic - 1) / dic)
    ///     inode_bitmap_blocks = ((((x + iabc - 1) / ibac) + bbs - 1) / bbs)
    ///
    /// So:
    ///     y = 1                                                           # super block
    ///         + x                                                         # data area blocks
    ///         + ((x + bbs - 1) / bbs)                                     # data bitmap blocks
    ///         + ((((x + iabc - 1) / iabc) + dic - 1) / dic)               # inode area blocks
    ///         + ((((x + iabc - 1) / iabc) + bbs - 1) / bbs)               # inode bitmap blocks
    ///
    ///       = 1
    ///         + x
    ///         + (x/bbs + 1 - 1/bbs)
    ///         + ((x/iabc - 1/iabc + dic) / dic)  
    ///         + ((x/iabc - 1/iabc + bbs) / bbs)
    ///
    ///       = 1
    ///         + x
    ///         + (x/bbs + 1 - 1/bbs)
    ///         + (x/(iabc*dic) - 1/(iabc*dic) + 1)  
    ///         + (x/(iabc*bbs) - 1/(iabc*bbs) + 1)  
    ///
    ///       = x + x/bbs + x/(iabc*dic) + x/(iabc*bbs) + 4 - 1/bbs - 1/(iabc*dic) - 1/(iabc*bbs)
    ///       
    /// So:
    ///     y - 4 + 1/bbs + 1/(iabc*dic) + 1/(iabc*bbs) = x + x/bbs + x/(iabc*dic) + x/(iabc*bbs)
    ///     y - 5 + (1 + 1/bbs + 1/(iabc*dic) + 1/(iabc*bbs)) = x * (1 + 1/bbs + 1/(iabc*dic) + 1/(iabc*bbs))
    ///
    /// Finally:
    ///     x = ((y - 5) * (iabc*dic*bbs)) / ((iabc*dic*bbs) + iabc*dic + bbs + dic) + 1
    /// ```
    ///
    /// # Arguments
    /// * total_blocks: total count of blocks
    /// * iabc: the average block count of disk inode
    ///
    /// # Returns
    /// * None: no recommended data blocks
    /// * Some(recommended data blocks)
    fn recommended_data_area_blocks(total_blocks: u32, iabc: u8) -> Option<u32> {
        if total_blocks < 5 {
            None
        } else {
            let bbs = BLOCK_BIT_SIZE as u64;
            let dic = PER_BLOCK_DISK_INODE_COUNT as u64;
            let iabc = iabc as u64;
            let y = total_blocks as u64;
            let mut x = (y - 5) * iabc * dic * bbs;
            let remainder = (iabc * dic * bbs) + (iabc * dic) + bbs + dic;
            x = ((x + remainder - 1) / remainder) + 1;
            Some(x as u32)
        }
    }

    /// Calculates the recommended blocks area structure
    ///
    /// # Arguments
    /// * total_blocks: The total number of blocks in blocks device
    /// * iabc: the average block count of disk inode
    ///
    /// # Returns
    /// * Some((
    ///     u32: inode bitmap blocks,
    ///     u32: inode area blocks,
    ///     u32: data bitmap blocks,
    ///     u32: data area blocks,
    ///     u32: used total blocks,
    ///     u32: disk inodes
    /// ))
    /// * None
    fn recommended_blocks_structure(
        total_blocks: u32,
        iabc: u8,
    ) -> Option<(u32, u32, u32, u32, u32, u32)> {
        if let Some(data_area_blocks) = Self::recommended_data_area_blocks(total_blocks, iabc) {
            for overflow in 0..=1 as u32 {
                let data_area_blocks = data_area_blocks - overflow;
                let disk_inodes = Self::cal_disk_inodes(data_area_blocks, iabc);
                let data_bitmap_blocks = Self::cal_data_bitmap_blocks(data_area_blocks);
                let inode_area_blocks = Self::cal_inode_area_blocks(disk_inodes);
                let inode_bitmap_blocks = Self::cal_inode_bitmap_blocks(disk_inodes);
                let used_total_blocks = INODE_BITMAP_START_BLOCK_ID
                    + inode_bitmap_blocks
                    + inode_area_blocks
                    + data_bitmap_blocks
                    + data_area_blocks;
                if used_total_blocks <= total_blocks {
                    return Some((
                        inode_bitmap_blocks,
                        inode_area_blocks,
                        data_bitmap_blocks,
                        data_area_blocks,
                        used_total_blocks,
                        disk_inodes,
                    ));
                }
            }
            panic!("Recommended blocks structure must be exists")
        } else {
            None
        }
    }

    /// Calculates the disk inode's position by the bitmap index of the inode.
    ///
    /// # Arguments
    /// * inode_bitmap_index: the bitmap index of the disk inode
    ///
    /// # Returns
    /// (
    ///     u32: the block id of the disk inode,
    ///     usize: the offset of the disk inode in the block
    /// )
    pub fn cal_disk_inode_position(&self, inode_bitmap_index: u32) -> (u32, usize) {
        (
            self.inode_area_start_block_id
                + (inode_bitmap_index / PER_BLOCK_DISK_INODE_COUNT as u32),
            (inode_bitmap_index as usize % PER_BLOCK_DISK_INODE_COUNT) * DISK_INODE_BYTE_SIZE,
        )
    }

    /// Allocate an unused disk inode from bitmap and return the bitmap index
    pub fn alloc_inode_bitmap_index(&mut self) -> Result<u32> {
        Ok(self.inode_bitmap.alloc(&self.device)? as u32)
    }

    /// Deallocate an used disk inode back to bitmap
    ///
    /// # Arguments
    /// * inode_bitmap_index: inode bitmap index to deallocate
    pub fn dealloc_inode_bitmap_index(&mut self, inode_bitmap_index: u32) -> Result<()> {
        self.inode_bitmap
            .dealloc(inode_bitmap_index as usize, &self.device)
    }

    /// Allocate an unused data block from bitmap an return the bitmap index
    pub fn alloc_data_block_id(&mut self) -> Result<u32> {
        let data_block_id =
            self.data_bitmap.alloc(&self.device)? as u32 + self.data_area_start_block_id;
        match BLOCK_CACHE_MANAGER
            .get_cache(data_block_id as usize, &self.device)?
            .lock()
            .modify(0, |data_block: &mut DataBlock| {
                data_block.iter_mut().for_each(|p| {
                    *p = 0;
                })
            }) {
            Ok(_) => Ok(data_block_id),
            Err(err) => {
                self.dealloc_data_block_id(data_block_id)?;
                Err(err)
            }
        }
    }

    /// Allocate multiple data blocks from bitmap an return the data block ids.
    /// This function will dealloc the data blocks immediately when error is encountered,
    /// in order to prevent an error from being reported during the block application process,
    /// some of the blocks that have been applied for will not be collected.
    ///
    /// # Arguments
    /// * blocks_needed: The count of blocks will be allocated
    ///
    /// # Returns
    /// * Ok(Vec<block id>)
    /// * Err(FFSError::NotValidBlockDevice): very serious error occurred caused by deallocation failure after allocation failed
    /// * Err(other FFSError)
    pub fn bulk_alloc_data_block_ids(&mut self, blocks_needed: u32) -> Result<Vec<u32>> {
        let mut data_block_ids = Vec::new();
        let mut error = None;
        for _ in 0..blocks_needed {
            match self.alloc_data_block_id() {
                Ok(block_id) => data_block_ids.push(block_id),
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
        if data_block_ids.len() == blocks_needed as usize {
            Ok(data_block_ids)
        } else if self.bulk_dealloc_data_block_ids(data_block_ids).is_ok() {
            Err(error.unwrap())
        } else {
            Err(FFSError::NotValidBlockDevice)
        }
    }

    /// Deallocate an used data block to bitmap
    ///
    /// # Arguments
    /// * data_block_id: data block id to deallocate
    pub fn dealloc_data_block_id(&mut self, data_block_id: u32) -> Result<()> {
        self.data_bitmap.dealloc(
            (data_block_id - self.data_area_start_block_id) as usize,
            &self.device,
        )
    }

    /// Deallocate multiple blocks to bitmap and clear all data in the blocks
    ///
    /// # Arguments
    /// * data_block_ids: vector of block IDs to deallocate
    pub fn bulk_dealloc_data_block_ids(&mut self, data_block_ids: Vec<u32>) -> Result<()> {
        for block_id in data_block_ids {
            self.dealloc_data_block_id(block_id)?
        }
        Ok(())
    }

    /// Just create a new File System structure, this function will do nothing with block device
    ///
    /// # Arguments:
    /// * inode_bitmap_blocks: the count of the blocks contains the data of the inode bitmap
    /// * inode_area_blocks: the count of the blocks contains the data of the disk inodes
    /// * data_bitmap_blocks: the count of the blocks contains the data of the data bitmap
    /// * data_area_blocks: the count of the blocks contains the original data
    /// * disk_inodes: the count of the disk inodes can be used in this file system
    /// * device: the dynamic device to be used
    pub fn new(
        inode_bitmap_blocks: u32,
        inode_area_blocks: u32,
        data_bitmap_blocks: u32,
        data_area_blocks: u32,
        disk_inodes: u32,
        device: &Arc<dyn BlockDevice>,
    ) -> Self {
        let inode_area_start_block_id = INODE_BITMAP_START_BLOCK_ID + inode_bitmap_blocks;
        let data_bitmap_start_block_id = inode_area_start_block_id + inode_area_blocks;
        let data_area_start_block_id = data_bitmap_start_block_id + data_bitmap_blocks;
        let inode_bitmap = Bitmap::new(
            INODE_BITMAP_START_BLOCK_ID as usize,
            inode_bitmap_blocks as usize,
            disk_inodes as usize,
        );
        let data_bitmap = Bitmap::new(
            data_bitmap_start_block_id as usize,
            data_bitmap_blocks as usize,
            data_area_blocks as usize,
        );
        Self {
            inode_bitmap,
            data_bitmap,
            inode_area_start_block_id,
            data_area_start_block_id,
            device: Arc::clone(device),
        }
    }

    #[inline(always)]
    pub fn inode_area_start_block_id(&self) -> u32 {
        self.inode_area_start_block_id
    }

    #[inline(always)]
    pub fn data_area_start_block_id(&self) -> u32 {
        self.data_area_start_block_id
    }
}

pub type FS = Arc<Mutex<FrontierFileSystem>>;
impl FileSystem for FS {
    /// Get the root inode in the file system.
    fn root_inode(&self) -> Inode {
        let fs = self.lock();
        let (disk_inode_block_id, disk_inode_block_offset) = fs.cal_disk_inode_position(0);
        Inode::new(
            0,
            disk_inode_block_id,
            disk_inode_block_offset,
            self,
            &fs.device,
        )
    }

    /// Initialize a new instance of the file system.
    /// * First: calculates the most recommended block distribution
    /// * Second: clear all usable blocks in the block device
    /// * third: write the block distribution in super block to the block device's first block
    /// * fourth: allocate the first disk inode as the root directory `/`
    ///
    /// # Arguments
    /// * total_blocks: the total count of the blocks can be used
    /// * iabc: the avarage block count of the inode
    /// * device: the dynamic device to be used
    fn initialize(total_blocks: u32, iabc: u8, device: &Arc<dyn BlockDevice>) -> Result<Box<Self>> {
        if let Some((
            inode_bitmap_blocks,
            inode_area_blocks,
            data_bitmap_blocks,
            data_area_blocks,
            used_total_blocks,
            disk_inodes,
        )) = FrontierFileSystem::recommended_blocks_structure(total_blocks, iabc)
        {
            let mut ffs = FrontierFileSystem::new(
                inode_bitmap_blocks,
                inode_area_blocks,
                data_bitmap_blocks,
                data_area_blocks,
                disk_inodes,
                device,
            );
            for i in 0..used_total_blocks {
                BLOCK_CACHE_MANAGER
                    .get_cache(i as usize, device)?
                    .lock()
                    .modify(0, |data_block: &mut DataBlock| {
                        for byte in data_block.iter_mut() {
                            *byte = 0;
                        }
                    })?;
            }
            BLOCK_CACHE_MANAGER.get_cache(0, device)?.lock().modify(
                0,
                |super_block: &mut SuperBlock| {
                    super_block.initialize(
                        used_total_blocks,
                        inode_bitmap_blocks,
                        inode_area_blocks,
                        data_bitmap_blocks,
                        data_area_blocks,
                        disk_inodes,
                        iabc,
                    );
                },
            )?;
            assert_eq!(ffs.alloc_inode_bitmap_index()?, 0);
            let (root_inode_block_id, root_inode_offset) = ffs.cal_disk_inode_position(0);
            BLOCK_CACHE_MANAGER
                .get_cache(root_inode_block_id as usize, device)?
                .lock()
                .modify(root_inode_offset, |disk_inode: &mut DiskInode| {
                    disk_inode.initialize();
                })?;
            let fs = Arc::new(Mutex::new(ffs));
            let root_inode = fs.root_inode();
            let root_dir = Directory::new(root_inode);
            let flags = FileFlags::IS_DIR;
            let mut mfs = fs.lock();
            root_dir.initialize(0, flags, flags, &mut mfs)?;
            drop(mfs);
            Ok(Box::new(fs))
        } else {
            Err(FFSError::NotValidBlockDevice)
        }
    }

    /// Open an initialized block device as the file system by the block distribution in super block,
    /// which super block is stored in the first block in the block device.
    ///
    /// # Arguments
    /// * device: the dynamic device to be used
    fn open(device: &Arc<dyn BlockDevice>) -> Result<Box<Self>> {
        BLOCK_CACHE_MANAGER
            .get_cache(0, device)?
            .lock()
            .read(0, |sb: &SuperBlock| {
                if sb.is_valid() {
                    let ffs = FrontierFileSystem::new(
                        sb.inode_bitmap_blocks(),
                        sb.inode_area_blocks(),
                        sb.data_bitmap_blocks(),
                        sb.data_area_blocks(),
                        sb.disk_inodes(),
                        device,
                    );
                    Ok(Box::new(Arc::new(Mutex::new(ffs))))
                } else {
                    Err(FFSError::NotValidBlockDevice)
                }
            })?
    }
}

#[cfg(test)]
mod tests {
    use crate::block::MockBlockDevice;

    use super::*;

    #[test]
    fn test_disk_inode_size() {
        assert_eq!(0, BLOCK_BYTE_SIZE % DISK_INODE_BYTE_SIZE);
    }

    #[test]
    fn test_ffs_cal_data_bitmap_blocks() {
        assert_eq!(0, FrontierFileSystem::cal_data_bitmap_blocks(0));
        assert_eq!(1, FrontierFileSystem::cal_data_bitmap_blocks(1));
        assert_eq!(
            1,
            FrontierFileSystem::cal_data_bitmap_blocks(BLOCK_BIT_SIZE as u32)
        );
        assert_eq!(
            2,
            FrontierFileSystem::cal_data_bitmap_blocks(BLOCK_BIT_SIZE as u32 + 1)
        );
    }

    #[test]
    fn test_ffs_cal_disk_inodes() {
        assert_eq!(0, FrontierFileSystem::cal_disk_inodes(0, 1));
        assert_eq!(1, FrontierFileSystem::cal_disk_inodes(1, 1));
        assert_eq!(2, FrontierFileSystem::cal_disk_inodes(2, 1));
        assert_eq!(1, FrontierFileSystem::cal_disk_inodes(2, 2));
        assert_eq!(2, FrontierFileSystem::cal_disk_inodes(3, 2));
        assert_eq!(2, FrontierFileSystem::cal_disk_inodes(4, 2));
        assert_eq!(2, FrontierFileSystem::cal_disk_inodes(4, 3));
    }

    #[test]
    fn test_ffs_recommended_blocks_structure() {
        for iabc in 1..=4 {
            for i in 0..4 {
                assert!(FrontierFileSystem::recommended_blocks_structure(i, iabc).is_none());
            }
            for i in 5..=10000000 {
                let (
                    inode_bitmap_blocks,
                    inode_area_blocks,
                    data_bitmap_blocks,
                    data_area_blocks,
                    used_total_blocks,
                    disk_inodes,
                ) = FrontierFileSystem::recommended_blocks_structure(i, iabc).unwrap();
                assert!(inode_bitmap_blocks > 0);
                assert!(inode_area_blocks > 0);
                assert!(data_bitmap_blocks > 0);
                assert!(data_area_blocks > 0);
                assert!(used_total_blocks > 0);
                assert!(disk_inodes > 0);

                assert!(inode_bitmap_blocks < i);
                assert!(inode_area_blocks < i);
                assert!(data_bitmap_blocks < i);
                assert!(data_area_blocks < i);
                assert!(used_total_blocks <= i);
                assert!(inode_bitmap_blocks <= inode_area_blocks);
                assert!(data_bitmap_blocks <= data_area_blocks);
                assert!(inode_area_blocks <= data_area_blocks);
                assert!(inode_bitmap_blocks <= data_bitmap_blocks);

                assert!(disk_inodes * iabc as u32 >= data_area_blocks);
                assert!(((disk_inodes - 1) * iabc as u32) < data_area_blocks);
                assert!(inode_bitmap_blocks * BLOCK_BIT_SIZE as u32 >= disk_inodes);
                assert!(inode_area_blocks * PER_BLOCK_DISK_INODE_COUNT as u32 >= disk_inodes);
            }
            for i in (u32::MAX - 10000000)..=u32::MAX {
                let (
                    inode_bitmap_blocks,
                    inode_area_blocks,
                    data_bitmap_blocks,
                    data_area_blocks,
                    used_total_blocks,
                    disk_inodes,
                ) = FrontierFileSystem::recommended_blocks_structure(i, iabc).unwrap();
                assert!(inode_bitmap_blocks > 0);
                assert!(inode_area_blocks > 0);
                assert!(data_bitmap_blocks > 0);
                assert!(data_area_blocks > 0);
                assert!(used_total_blocks > 0);
                assert!(disk_inodes > 0);

                assert!(inode_bitmap_blocks < i);
                assert!(inode_area_blocks < i);
                assert!(data_bitmap_blocks < i);
                assert!(data_area_blocks < i);
                assert!(used_total_blocks <= i);
                assert!(inode_bitmap_blocks <= inode_area_blocks);
                assert!(data_bitmap_blocks <= data_area_blocks);
                assert!(inode_area_blocks <= data_area_blocks);
                assert!(inode_bitmap_blocks <= data_bitmap_blocks);

                assert!(disk_inodes * iabc as u32 >= data_area_blocks);
                assert!(((disk_inodes - 1) * iabc as u32) < data_area_blocks);
                assert!(inode_bitmap_blocks * BLOCK_BIT_SIZE as u32 >= disk_inodes);
                assert!(inode_area_blocks * PER_BLOCK_DISK_INODE_COUNT as u32 >= disk_inodes);
            }
        }
    }

    #[test]
    fn test_ffs_bulk_alloc_and_dealloc_data_block_ids() {
        BLOCK_CACHE_MANAGER.clear();
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let mut ffs = FrontierFileSystem::new(1, 1, 1, 3, 3, &device);
        let block_ids = ffs.bulk_alloc_data_block_ids(3).unwrap();
        assert_eq!(4, block_ids[0]);
        assert_eq!(5, block_ids[1]);
        assert_eq!(6, block_ids[2]);
        assert_eq!(3, block_ids.len());
        ffs.bulk_dealloc_data_block_ids(block_ids[0..2].to_vec())
            .unwrap();
        let block_ids = ffs.bulk_alloc_data_block_ids(2).unwrap();
        assert_eq!(4, block_ids[0]);
        assert_eq!(5, block_ids[1]);
        assert_eq!(2, block_ids.len());
    }

    #[test]
    fn test_ffs_initialize_and_open() {
        BLOCK_CACHE_MANAGER.clear();
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        assert!(FS::initialize(5, 1, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(4, ffs.data_area_start_block_id());
            true
        }));
        assert!(FS::initialize(5, 2, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(4, ffs.data_area_start_block_id());
            true
        }));
        assert!(FS::initialize(6, 2, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(4, ffs.data_area_start_block_id());
            true
        }));
        assert!(FS::initialize(PER_BLOCK_DISK_INODE_COUNT as u32, 1, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(4, ffs.data_area_start_block_id());
            true
        }));
        assert!(FS::initialize(PER_BLOCK_DISK_INODE_COUNT as u32 + 3, 1, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(4, ffs.data_area_start_block_id());
            true
        }));
        assert!(FS::initialize(PER_BLOCK_DISK_INODE_COUNT as u32 + 4, 1, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(4, ffs.data_area_start_block_id());
            true
        }));
        assert!(FS::initialize(PER_BLOCK_DISK_INODE_COUNT as u32 + 6, 1, &device).is_ok());
        assert!(FS::open(&device).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id());
            assert_eq!(5, ffs.data_area_start_block_id());
            true
        }));
    }
}
