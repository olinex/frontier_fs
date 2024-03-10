// @author:    olinex
// @time:      2023/11/23

// self mods

// use other mods
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

// use self mods
use super::{AbstractInode, FileFlags, FileSystem, InitMode, Inode};
use crate::block::{BlockDeviceTracker, BLOCK_CACHE_MANAGER};
use crate::configs::{BLOCK_BIT_SIZE, BLOCK_BYTE_SIZE};
use crate::layout::{Bitmap, DataBlock, DiskInode, SuperBlock};
use crate::{FFSError, Result};

const INODE_BITMAP_START_BLOCK_ID: u32 = 1;
const DISK_INODE_BYTE_SIZE: usize = core::mem::size_of::<DiskInode>();
const PER_BLOCK_DISK_INODE_COUNT: usize = BLOCK_BYTE_SIZE / DISK_INODE_BYTE_SIZE;

/// The main struct of the file system
pub struct FrontierFileSystem {
    tracker: Arc<BlockDeviceTracker>,
    inode_bitmap: Bitmap,
    data_bitmap: Bitmap,
    inode_area_start_block_id: u32,
    data_area_start_block_id: u32,
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

    /// Calculates the blocks area structure according to the total bytes size
    ///
    /// # Arguments
    /// * total_byte_size: The bytes size of the data will be written to the device
    /// * iabc: the average block count of disk inode
    ///
    /// # Returns
    /// (
    ///     u32: inode bitmap blocks,
    ///     u32: inode area blocks,
    ///     u32: data bitmap blocks,
    ///     u32: data area blocks,
    ///     u32: used total blocks,
    ///     u32: disk inodes
    /// )
    fn fix_blocks_structure(total_byte_size: u64, iabc: u8) -> (u32, u32, u32, u32, u32, u32) {
        let block_byte_size = BLOCK_BIT_SIZE as u64;
        let data_area_blocks = ((total_byte_size + block_byte_size - 1) / block_byte_size) as u32;
        let data_bitmap_blocks = Self::cal_data_bitmap_blocks(data_area_blocks);
        let disk_inodes = Self::cal_disk_inodes(data_area_blocks, iabc);
        let inode_area_blocks = Self::cal_inode_area_blocks(disk_inodes);
        let inode_bitmap_blocks = Self::cal_inode_bitmap_blocks(disk_inodes);
        (
            inode_bitmap_blocks,
            inode_area_blocks,
            data_bitmap_blocks,
            data_area_blocks,
            1 + inode_bitmap_blocks + inode_area_blocks + data_bitmap_blocks + data_area_blocks,
            disk_inodes,
        )
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
    pub(crate) fn cal_disk_inode_position(&self, inode_bitmap_index: u32) -> (u32, usize) {
        (
            self.inode_area_start_block_id
                + (inode_bitmap_index / PER_BLOCK_DISK_INODE_COUNT as u32),
            (inode_bitmap_index as usize % PER_BLOCK_DISK_INODE_COUNT) * DISK_INODE_BYTE_SIZE,
        )
    }

    /// Allocate an unused disk inode from bitmap and return the bitmap index
    ///
    /// # Returns
    /// * Ok(inode bitmap index)
    /// * Err(BitmapExhausted(start_block_id) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn alloc_inode_bitmap_index(&mut self) -> Result<u32> {
        Ok(self.inode_bitmap.alloc(&self.tracker)? as u32)
    }

    /// Deallocate an used disk inode back to bitmap
    ///
    /// # Arguments
    /// * inode_bitmap_index: inode bitmap index to deallocate
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | BitmapIndexDeallocated(bitmap_index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn dealloc_inode_bitmap_index(&mut self, inode_bitmap_index: u32) -> Result<()> {
        self.inode_bitmap
            .dealloc(&self.tracker, inode_bitmap_index as usize)
    }

    /// Allocate an unused data block from bitmap an return the bitmap index
    ///
    /// # Returns
    /// * Err(DataOutOfBounds | BitmapExhausted(start_block_id) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn alloc_data_block_id(&mut self) -> Result<u32> {
        let data_block_id =
            self.data_bitmap.alloc(&self.tracker)? as u32 + self.data_area_start_block_id;
        let mut manager = BLOCK_CACHE_MANAGER.lock();
        let cache = manager.get(&self.tracker, data_block_id as usize)?;
        let mut cache_lock = cache.lock();
        match cache_lock.modify(0, |data_block: &mut DataBlock| {
            data_block.iter_mut().for_each(|p| {
                *p = 0;
            })
        }) {
            Ok(_) => Ok(data_block_id),
            Err(err) => {
                drop(cache_lock);
                drop(cache);
                drop(manager);
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
    /// * Err(DataOutOfBounds | BitmapExhausted(start_block_id) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn bulk_alloc_data_block_ids(&mut self, blocks_needed: u32) -> Result<Vec<u32>> {
        let mut data_block_ids = Vec::new();
        for _ in 0..blocks_needed {
            match self.alloc_data_block_id() {
                Ok(block_id) => data_block_ids.push(block_id),
                Err(err) => {
                    self.bulk_dealloc_data_block_ids(data_block_ids)
                    .expect("very serious error occurred caused by deallocation failure after allocation failed");
                    return Err(err);
                }
            }
        }
        Ok(data_block_ids)
    }

    /// Deallocate an used data block to bitmap
    ///
    /// # Arguments
    /// * data_block_id: data block id to deallocate
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | BitmapIndexDeallocated(bitmap_index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn dealloc_data_block_id(&mut self, data_block_id: u32) -> Result<()> {
        self.data_bitmap.dealloc(
            &self.tracker,
            (data_block_id - self.data_area_start_block_id) as usize,
        )
    }

    /// Deallocate multiple blocks to bitmap and clear all data in the blocks
    ///
    /// # Arguments
    /// * data_block_ids: vector of block IDs to deallocate
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | BitmapIndexDeallocated(bitmap_index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn bulk_dealloc_data_block_ids(&mut self, data_block_ids: Vec<u32>) -> Result<()> {
        for block_id in data_block_ids {
            self.dealloc_data_block_id(block_id)?
        }
        Ok(())
    }

    /// Just create a new File System structure, this function will do nothing with block device
    ///
    /// # Arguments:
    /// * tracker: the tracker for the block device which was mounted
    /// * inode_bitmap_blocks: the count of the blocks contains the data of the inode bitmap
    /// * inode_area_blocks: the count of the blocks contains the data of the disk inodes
    /// * data_bitmap_blocks: the count of the blocks contains the data of the data bitmap
    /// * data_area_blocks: the count of the blocks contains the original data
    /// * disk_inodes: the count of the disk inodes can be used in this file system
    pub fn new(
        tracker: &Arc<BlockDeviceTracker>,
        inode_bitmap_blocks: u32,
        inode_area_blocks: u32,
        data_bitmap_blocks: u32,
        data_area_blocks: u32,
        disk_inodes: u32,
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
            tracker: Arc::clone(tracker),
            inode_bitmap,
            data_bitmap,
            inode_area_start_block_id,
            data_area_start_block_id,
        }
    }

    /// Get the unique id of the device
    pub(crate) fn tracker(&self) -> &Arc<BlockDeviceTracker> {
        &self.tracker
    }

    /// Get the root inode in the file system.
    pub(crate) fn root_abstract_inode(&self) -> AbstractInode {
        let (disk_inode_block_id, disk_inode_block_offset) = self.cal_disk_inode_position(0);
        AbstractInode::new(
            0,
            disk_inode_block_id,
            disk_inode_block_offset,
            FileFlags::all(),
        )
    }
}

pub type FS = Arc<Mutex<FrontierFileSystem>>;
impl FileSystem for FS {
    /// Get the root inode in the file system.
    fn root_inode(&self) -> Inode {
        let fs = self.lock();
        let abs_root_inode = fs.root_abstract_inode();
        Inode::new(abs_root_inode, Arc::clone(self))
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
    /// * tracker: the tracker for the block device which was mounted
    ///
    /// # Returns
    /// * Ok(Box<Arc<Mutex<FrontierFileSystem>>>)
    /// * Err(NoEnoughBlocks | DataOutOfBounds | BitmapExhausted(start_block_id) | NoDroptableBlockCache | RawDeviceError(error code))
    fn initialize(
        mode: InitMode,
        iabc: u8,
        tracker: &Arc<BlockDeviceTracker>,
    ) -> Result<Box<Self>> {
        let (
            inode_bitmap_blocks,
            inode_area_blocks,
            data_bitmap_blocks,
            data_area_blocks,
            used_total_blocks,
            disk_inodes,
        ) = match mode {
            InitMode::TotalBlocks(total_blocks) => {
                FrontierFileSystem::recommended_blocks_structure(total_blocks, iabc)
                    .ok_or(FFSError::NoEnoughBlocks)?
            }
            InitMode::TotalByteSize(total_byte_size) => {
                FrontierFileSystem::fix_blocks_structure(total_byte_size, iabc)
            }
        };
        let mut ffs = FrontierFileSystem::new(
            tracker,
            inode_bitmap_blocks,
            inode_area_blocks,
            data_bitmap_blocks,
            data_area_blocks,
            disk_inodes,
        );
        for i in 0..used_total_blocks {
            BLOCK_CACHE_MANAGER
                .lock()
                .get(tracker, i as usize)?
                .lock()
                .modify(0, |data_block: &mut DataBlock| {
                    for byte in data_block.iter_mut() {
                        *byte = 0;
                    }
                })?;
        }
        BLOCK_CACHE_MANAGER
            .lock()
            .get(tracker, 0)?
            .lock()
            .modify(0, |super_block: &mut SuperBlock| {
                super_block.initialize(
                    used_total_blocks,
                    inode_bitmap_blocks,
                    inode_area_blocks,
                    data_bitmap_blocks,
                    data_area_blocks,
                    disk_inodes,
                    iabc,
                );
            })?;
        assert_eq!(ffs.alloc_inode_bitmap_index()?, 0);
        let (root_inode_block_id, root_inode_offset) = ffs.cal_disk_inode_position(0);
        DiskInode::new(tracker, root_inode_block_id, root_inode_offset)?;
        let fs = Arc::new(Mutex::new(ffs));
        let mut mfs = fs.lock();
        let root_abstract_inode = mfs.root_abstract_inode();
        let flags = FileFlags::all();
        root_abstract_inode.init_as_dir(0, flags, &mut mfs)?;
        drop(mfs);
        Ok(Box::new(fs))
    }

    /// Open an initialized block device as the file system by the block distribution in super block,
    /// which super block is stored in the first block in the block device.
    ///
    /// # Arguments
    /// * tracker: the tracker for the block device which was mounted
    ///
    /// # Returns
    /// * Ok(Box<Arc<Mutex<FrontierFileSystem>>>)
    /// * Err(NotValidBlockDeviceData | DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn open(tracker: &Arc<BlockDeviceTracker>) -> Result<Box<Self>> {
        BLOCK_CACHE_MANAGER
            .lock()
            .get(tracker, 0)?
            .lock()
            .read(0, |sb: &SuperBlock| {
                if sb.is_valid() {
                    let ffs = FrontierFileSystem::new(
                        tracker,
                        sb.inode_bitmap_blocks(),
                        sb.inode_area_blocks(),
                        sb.data_bitmap_blocks(),
                        sb.data_area_blocks(),
                        sb.disk_inodes(),
                    );
                    Ok(Box::new(Arc::new(Mutex::new(ffs))))
                } else {
                    Err(FFSError::NotValidBlockDeviceData)
                }
            })?
    }
}

#[cfg(test)]
mod tests {
    use crate::block::{BlockDevice, MemoryBlockDevice, BLOCK_DEVICE_REGISTER};

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
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let mut ffs = FrontierFileSystem::new(&tracker, 1, 1, 1, 3, 3);
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
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        assert!(FS::initialize(InitMode::TotalBlocks(5), 1, &tracker).is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(4, ffs.data_area_start_block_id);
            true
        }));
        assert!(FS::initialize(InitMode::TotalBlocks(5), 2, &tracker).is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(4, ffs.data_area_start_block_id);
            true
        }));
        assert!(FS::initialize(InitMode::TotalBlocks(6), 2, &tracker).is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(4, ffs.data_area_start_block_id);
            true
        }));
        assert!(FS::initialize(
            InitMode::TotalBlocks(PER_BLOCK_DISK_INODE_COUNT as u32),
            1,
            &tracker
        )
        .is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(4, ffs.data_area_start_block_id);
            true
        }));
        assert!(FS::initialize(
            InitMode::TotalBlocks(PER_BLOCK_DISK_INODE_COUNT as u32 + 3),
            1,
            &tracker
        )
        .is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(4, ffs.data_area_start_block_id);
            true
        }));
        assert!(FS::initialize(
            InitMode::TotalBlocks(PER_BLOCK_DISK_INODE_COUNT as u32 + 4),
            1,
            &tracker
        )
        .is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(4, ffs.data_area_start_block_id);
            true
        }));
        assert!(FS::initialize(
            InitMode::TotalBlocks(PER_BLOCK_DISK_INODE_COUNT as u32 + 6),
            1,
            &tracker
        )
        .is_ok());
        assert!(FS::open(&tracker).is_ok_and(|ffs| {
            let ffs = ffs.lock();
            assert_eq!(2, ffs.inode_area_start_block_id);
            assert_eq!(5, ffs.data_area_start_block_id);
            true
        }));
    }
}
