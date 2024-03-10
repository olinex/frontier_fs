// @author:    olinex
// @time:      2023/11/25

// self mods

// use other mods
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use bit_field::BitField;
use hmac_sha256::Hash;
use spin::{Mutex, MutexGuard};

// use self mods
use super::ffs::FrontierFileSystem;
use crate::block::{BlockDeviceTracker, BLOCK_CACHE_MANAGER};
use crate::configs::BLOCK_BYTE_SIZE;
use crate::layout::DiskInode;
use crate::{AsBytes, AsBytesMut, FFSError, Result};

const DENTRY_MAX_DEPTH: usize = 8;
const NAME_BYTE_SIZE: usize = 242;
const NAME_HASH_BYTE_SIZE: usize = 32;
const HASH_GROUP_COUNT: usize = 4;
const HASH_GROUP_ITEM_COUNT: usize = 4;
const HASH_GROUP_END_INDEX: usize = HASH_GROUP_COUNT - 1;
const HASH_GROUP_ITEM_END_INDEX: usize = HASH_GROUP_ITEM_COUNT - 1;
const FHEADER_BYTE_SIZE: usize = core::mem::size_of::<Fheader>();
const FENTRY_BYTE_SIZE: usize = core::mem::size_of::<Fentry>();
const FNAME_BYTE_SIZE: usize = core::mem::size_of::<Fname>();

pub const SELF_FNAME_STR: &str = ".";
pub const PARENT_FNAME_STR: &str = "..";

bitflags! {
    /// Flags that indicate file's meta infos, including file types/permissions
    #[derive(Clone, Copy)]
    pub struct FileFlags: u32 {
        const VALID = 1 << 31;
        const DIR = 1 << 30;
        const HARD_LINK = 1 << 29;
    }
}
impl FileFlags {
    /// Check if the file is valid
    pub(crate) fn is_valid(&self) -> bool {
        self.contains(FileFlags::VALID)
    }

    /// Check if the file is directory
    pub(crate) fn is_dir(&self) -> bool {
        self.contains(FileFlags::DIR)
    }

    /// Check if the file is a hard link
    pub(crate) fn is_hard_link(&self) -> bool {
        self.contains(FileFlags::HARD_LINK)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Fheader {
    next_leaf_indexes: [u32; HASH_GROUP_COUNT],
}
impl Fheader {
    /// Calculate the byte offset of the file header in directory's leaf blocks
    fn cal_start_offset(leaf_index: u32) -> u64 {
        leaf_index as u64 * BLOCK_BYTE_SIZE as u64
    }

    /// Create a new empty file header
    fn empty() -> Self {
        Self {
            next_leaf_indexes: [0; HASH_GROUP_COUNT],
        }
    }
}
impl AsBytes for Fheader {
    /// Read Self as bytes slice from memory
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                HASH_GROUP_COUNT * 4,
            )
        }
    }
}
impl AsBytesMut for Fheader {
    /// Read Self as mutable bytes slice from memory
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut _ as usize as *mut u8,
                HASH_GROUP_COUNT * 4,
            )
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Fname {
    bytes: [u8; NAME_BYTE_SIZE],
    length: u8,
}
impl Fname {
    /// Calculate the byte offset of the file name in directory's leaf blocks
    fn cal_start_offset(leaf_index: u32, hash_index: usize, item_index: usize) -> u64 {
        Fentry::cal_start_offset(leaf_index, hash_index, item_index) + FENTRY_BYTE_SIZE as u64
    }

    /// Calculate the hash bytes array of the input bytes slice
    fn cal_hash(bytes: &[u8]) -> [u8; NAME_HASH_BYTE_SIZE] {
        Hash::hash(bytes)
    }

    /// Calculate the hash index of the input byte
    fn cal_hash_index(byte: u8) -> usize {
        byte.get_bits(0..2) as usize
    }

    /// Calculate the hash byte array by the file name
    fn cal_name_hash(name: &str) -> [u8; NAME_HASH_BYTE_SIZE] {
        let bytes = name.as_bytes();
        let name_len = bytes.len();
        assert!(name_len <= NAME_BYTE_SIZE && bytes[name_len - 1] as char != '\0');
        Self::cal_hash(bytes)
    }

    /// Create a new empty file name
    fn empty() -> Self {
        Self {
            bytes: [0; NAME_BYTE_SIZE],
            length: 0,
        }
    }

    /// Clear current file name as empty
    fn clear(&mut self) {
        for each in self.bytes.iter_mut() {
            *each = 0;
        }
        self.length = 0;
    }

    /// Create a new file name from a string
    fn new(name: &str) -> Self {
        let length = name.len();
        assert!(length <= NAME_BYTE_SIZE);
        let mut bytes = [0; NAME_BYTE_SIZE];
        bytes[0..length].copy_from_slice(name.as_bytes());
        Self {
            bytes,
            length: length as u8,
        }
    }

    /// Convert file name to a string
    fn to_str(&self) -> &str {
        core::str::from_utf8(self.to_bytes()).unwrap()
    }

    /// Convert file name to a byte slice
    fn to_bytes(&self) -> &[u8] {
        &self.bytes[0..self.length as usize]
    }

    /// Check if the current file name is equal to other string
    fn is_equal(&self, other: &str) -> bool {
        self.to_bytes().iter().eq(other.as_bytes().iter())
    }
}
impl AsBytes for Fname {
    /// Read Self as bytes slice from memory
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self as *const _ as usize as *const u8, FNAME_BYTE_SIZE)
        }
    }
}
impl AsBytesMut for Fname {
    /// Read Self as mutable bytes slice from memory
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self as *mut _ as usize as *mut u8, FNAME_BYTE_SIZE)
        }
    }
}

/// The entry of a file
#[repr(C)]
#[derive(Clone, Copy)]
struct Fentry {
    /// the bitmap index of the inode
    inode_bitmap_index: u32,
    /// the glags that indicate file's meta infos
    flags: FileFlags,
    /// next hash byte in name hash
    next_hash_byte: u8,
}
impl Fentry {
    fn cal_start_offset(leaf_index: u32, hash_index: usize, item_index: usize) -> u64 {
        Fheader::cal_start_offset(leaf_index)
            + FHEADER_BYTE_SIZE as u64
            + ((hash_index as u64 * HASH_GROUP_ITEM_COUNT as u64 + item_index as u64)
                * (FENTRY_BYTE_SIZE + FNAME_BYTE_SIZE) as u64)
    }

    /// Create a new empty file entry
    fn empty() -> Self {
        Self {
            inode_bitmap_index: 0,
            flags: FileFlags::empty(),
            next_hash_byte: 0,
        }
    }

    /// Make self empty
    fn clear(&mut self) {
        self.inode_bitmap_index = 0;
        self.flags = FileFlags::empty();
        self.next_hash_byte = 0;
    }

    /// Create a new file entry
    ///
    /// # Arguments
    /// * name: the name of the file to create
    /// * inode_bitmap_index: the bitmap index of the inode
    /// * flags: the glags that indicate file's meta infos
    fn new(inode_bitmap_index: u32, flags: FileFlags, next_hash_byte: u8) -> Self {
        let bits = flags.bits() | FileFlags::VALID.bits();
        let flags = FileFlags::from_bits(bits).unwrap();
        Self {
            inode_bitmap_index,
            flags,
            next_hash_byte,
        }
    }

    /// Check if the file is directory
    fn is_dir(&self) -> bool {
        self.flags.is_dir()
    }

    /// Check if the file entry is valid
    fn is_valid(&self) -> bool {
        self.flags.is_valid()
    }

    // Check if the file entry is hard link
    fn is_hard_link(&self) -> bool {
        self.flags.is_hard_link()
    }
}
impl AsBytes for Fentry {
    /// Read Self as bytes slice from memory
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self as *const _ as usize as *const u8, FENTRY_BYTE_SIZE)
        }
    }
}
impl AsBytesMut for Fentry {
    /// Read Self as mutable bytes slice from memory
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self as *mut _ as usize as *mut u8, FENTRY_BYTE_SIZE)
        }
    }
}

/// Abstract class for file in block device,
/// which contains the basic information and methods for controlling the real physical disk inode
pub(crate) struct AbstractInode {
    /// the index of the disk inode in the bitmap
    inode_bitmap_index: u32,
    /// the block id in the block device, which contains the disk inode in the block
    disk_inode_block_id: u32,
    /// the offset of the disk inode in the block
    disk_inode_block_offset: usize,
    /// the file flags of the disk inode
    flags: FileFlags,
}
// as common
impl AbstractInode {
    /// Change the disk inode byte size to the specified value.
    /// When the new byte size is greater than the original byte size, this method will allocate some needed new blocks.
    /// When the new byte size is smaller than the original byte size, this method will deallocate some blocks that are no longer in use.
    ///
    /// # Arguments
    /// * new_byte_size: the new byte size disk inode will changed to
    /// * disk_inode: the disk inode which will be modified
    /// ference of the file system which owns the current disk inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(
    ///     DataOutOfBounds |
    ///     BitmapExhausted(start_block_id) |
    ///     BitmapIndexDeallocated(bitmap_index) |
    ///     NoDroptableBlockCache |
    ///     RawDeviceError(error code)
    /// )
    #[inline(always)]
    fn to_byte_size(
        new_byte_size: u64,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        let origin_byte_size = disk_inode.data_byte_size();
        if new_byte_size > origin_byte_size {
            let blocks_needed = disk_inode.blocks_needed(new_byte_size)?;
            let block_ids = fs.bulk_alloc_data_block_ids(blocks_needed)?;
            disk_inode.increase_to_byte_size(fs.tracker(), new_byte_size, block_ids)
        } else if new_byte_size < origin_byte_size {
            let block_ids = disk_inode.decrease_to_byte_size(fs.tracker(), new_byte_size)?;
            fs.bulk_dealloc_data_block_ids(block_ids)
        } else {
            Ok(())
        }
    }

    /// Provides a method to reading disk inode and return the result of the closure
    ///
    /// # Arguments
    /// * tracker: the tracker for the block device which was mounted
    /// * f: the closure function which receives the reference of the disk inode and return the result
    ///
    /// # Returns
    /// * Ok(V): the result value wrapped in Result
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn read_disk_inode<V>(
        &self,
        tracker: &Arc<BlockDeviceTracker>,
        f: impl FnOnce(&DiskInode) -> V,
    ) -> Result<V> {
        let mut manager = BLOCK_CACHE_MANAGER.lock();
        let cache = manager.get(tracker, self.disk_inode_block_id as usize)?;
        let cache_lock = cache.lock();
        drop(manager);
        cache_lock.read(self.disk_inode_block_offset, f)
    }

    /// Provides a method to writing disk inode and return the result of the closure
    ///
    /// # Arguments
    /// * tracker: the tracker for the block device which was mounted
    /// * f: the closure function which receives the mutable reference of the disk inode and return the result
    ///
    /// # Returns
    /// * Ok(V): the result value wrapped in Result
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn modify_disk_inode<V>(
        &self,
        tracker: &Arc<BlockDeviceTracker>,
        f: impl FnOnce(&mut DiskInode) -> V,
    ) -> Result<V> {
        let mut manager = BLOCK_CACHE_MANAGER.lock();
        let cache = manager.get(tracker, self.disk_inode_block_id as usize)?;
        let mut cache_lock = cache.lock();
        drop(manager);
        cache_lock.modify(self.disk_inode_block_offset, f)
    }

    /// Get the count of the leaf blocks in the disk inode
    ///
    /// # Arguments
    /// * tracker: the tracker for the block device which was mounted
    ///
    /// # Returns
    /// * Ok(leaf block count)
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn leaf_block_count(&self, tracker: &Arc<BlockDeviceTracker>) -> Result<u32> {
        self.read_disk_inode(tracker, |disk_inode| disk_inode.leaf_block_count())
    }
}
// as file
impl AbstractInode {
    /// Create a new Inode as file
    ///
    /// # Arguments
    /// * inode_bitmap_index: the index of the disk in the bitmap
    /// * disk_inode_block_id: the block id in the block device
    /// * disk_indde_block_offset: the offset of the disk inode in the block
    /// * flags: the file flags of the disk inode
    pub(crate) fn new(
        inode_bitmap_index: u32,
        disk_inode_block_id: u32,
        disk_inode_block_offset: usize,
        flags: FileFlags,
    ) -> Self {
        Self {
            inode_bitmap_index,
            disk_inode_block_id,
            disk_inode_block_offset,
            flags,
        }
    }

    /// clear all blocks in the disk inode as a file.
    /// Be careful, this function does not deallocate the inode
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(
    ///     FFSError::NoDroptableBlockCache |
    ///     FFSError::DataOutOfBounds |
    ///     FFSError::BitmapIndexDeallocated(bitmap_index)
    /// )
    fn clear_as_file(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<()> {
        let tracker = fs.tracker();
        let data_block_ids =
            self.modify_disk_inode(tracker, |disk_inode| disk_inode.clear_byte_size(tracker))??;
        fs.bulk_dealloc_data_block_ids(data_block_ids)
    }
}
// as directory
impl AbstractInode {
    /// Check if current inode is directory
    #[inline(always)]
    fn must_be_dir(&self) -> Result<()> {
        if !self.flags.is_dir() {
            Err(FFSError::InodeMustBeDirectory(self.inode_bitmap_index))
        } else {
            Ok(())
        }

    }

    /// Convert file entry to abstract inode
    ///
    /// # Arguments
    /// * fentry: the file entry to convert
    /// * fs: the mutable reference of the file system which owns the current inode
    #[inline(always)]
    fn convert_to_inode(fentry: &Fentry, fs: &mut MutexGuard<FrontierFileSystem>) -> Self {
        let (disk_inode_block_id, disk_inode_block_offset) =
            fs.cal_disk_inode_position(fentry.inode_bitmap_index);
        Self {
            inode_bitmap_index: fentry.inode_bitmap_index,
            disk_inode_block_id,
            disk_inode_block_offset,
            flags: fentry.flags,
        }
    }

    /// Increase the current inode just one block size
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(new block id)
    /// * Err(
    ///     DataOutOfBounds |
    ///     BitmapExhausted(start_block_id) |
    ///     BitmapIndexDeallocated(bitmap_index) |
    ///     NoDroptableBlockCache |
    ///     RawDeviceError(error code)
    /// )
    #[inline(always)]
    fn increase_block(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<u32> {
        let tracker = Arc::clone(fs.tracker());
        let origin_leaf_blocks = self.leaf_block_count(&tracker)?;
        self.modify_disk_inode(&tracker, |disk_inode| {
            Self::to_byte_size(
                (origin_leaf_blocks + 1) as u64 * BLOCK_BYTE_SIZE as u64,
                disk_inode,
                fs,
            )
        })??;
        Ok(origin_leaf_blocks)
    }

    /// Read the child instance from block device cache
    ///
    /// # Arguments
    /// * child: impl AsBytesMut
    /// * start_offset: the byte offset to start reading from
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn read_child<T>(
        &self,
        child: &mut T,
        start_offset: u64,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()>
    where
        T: AsBytesMut,
    {
        let buffer = child.as_bytes_mut();
        let tracker = fs.tracker();
        self.read_disk_inode(tracker, |disk_inode| {
            match disk_inode.read_at(tracker, start_offset, buffer) {
                Ok(size) if size == buffer.len() => Ok(()),
                Ok(_) => Err(FFSError::DataOutOfBounds),
                Err(e) => Err(e),
            }
        })?
    }

    /// Read the raw byte data from block device cache
    ///
    /// # Arguments
    /// * buffer: the byte slice which stores the raw data will be readed from
    /// * start_offset: the byte offset to start reading from
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(the byte size of the data which have been readed from block device and written to the buffer)
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn read_buffer(
        &self,
        buffer: &mut [u8],
        start_offset: u64,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<usize> {
        let tracker = fs.tracker();
        self.read_disk_inode(tracker, |disk_inode| {
            disk_inode.read_at(tracker, start_offset, buffer)
        })?
    }

    /// Write the child instance to block device cache
    ///
    /// # Arguments
    /// * child: impl AsBytes
    /// * start_offset: the byte offset to start writting to
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn write_child<T>(
        &self,
        child: &T,
        start_offset: u64,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()>
    where
        T: AsBytes,
    {
        let buffer = child.as_bytes();
        let tracker = fs.tracker();
        self.modify_disk_inode(tracker, |disk_inode| {
            match disk_inode.write_at(tracker, start_offset, buffer) {
                Ok(size) if size == buffer.len() => Ok(()),
                Ok(_) => Err(FFSError::DataOutOfBounds),
                Err(e) => Err(e),
            }
        })?
    }

    /// Write the raw byte data to block device cache
    ///
    /// # Arguments
    /// * buffer: the byte slice which stores the raw data will be writted to block device cache
    /// * start_offset: the byte offset to start writting to
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    #[inline(always)]
    fn write_buffer(
        &self,
        buffer: &[u8],
        start_offset: u64,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<usize> {
        let tracker = fs.tracker();
        self.modify_disk_inode(tracker, |disk_inode| {
            disk_inode.write_at(tracker, start_offset, buffer)
        })?
    }

    /// Create a new iterator which will read all file entries from current directory
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(map iterator)
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn to_entry_iter<'a>(
        &'a self,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<AbstractInodeEntryIterator> {
        let tracker = fs.tracker();
        let leaf_block_count = self.leaf_block_count(tracker)?;
        Ok(AbstractInodeEntryIterator::new(self, leaf_block_count))
    }

    /// Create a new hard link to current directory
    ///
    /// # Arguments
    /// * name: the name of the hard link
    /// * inode_bitmap_index: the inode bitmap index which was refected by the hard link
    /// * flags: the flags of the hard link
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn create_hard_link(
        &self,
        name: &str,
        inode_bitmap_index: u32,
        flags: FileFlags,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<'_, FrontierFileSystem>,
    ) -> Result<()> {
        let tracker = fs.tracker();
        let hash_bytes = Fname::cal_name_hash(name);
        let hash_index = Fname::cal_hash_index(hash_bytes[0]);
        let fentry = Fentry::new(
            inode_bitmap_index,
            flags | FileFlags::HARD_LINK,
            hash_bytes[1],
        );
        let start_offset = Fentry::cal_start_offset(0, hash_index, 0);
        disk_inode.write_at(tracker, start_offset, fentry.as_bytes())?;
        let fname = Fname::new(name);
        let start_offset = Fname::cal_start_offset(0, hash_index, 0);
        disk_inode.write_at(tracker, start_offset, fname.as_bytes())?;
        Ok(())
    }

    /// Initialize the current inode as directory.
    /// Each directory have the parent hard link and self hard link.
    ///
    /// # Arguments
    /// * parent_inode_bitmap_index: the inode bitmap index of the parent directory
    /// * parent_flags: the flags of the parent directory hard link
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn init_as_dir(
        &self,
        parent_inode_bitmap_index: u32,
        parent_flags: FileFlags,
        fs: &mut MutexGuard<'_, FrontierFileSystem>,
    ) -> Result<()> {
        let tracker = Arc::clone(fs.tracker());
        self.modify_disk_inode(&tracker, |disk_inode| {
            Self::to_byte_size(BLOCK_BYTE_SIZE as u64, disk_inode, fs)?;
            // insert self as child directory
            self.create_hard_link(
                SELF_FNAME_STR,
                self.inode_bitmap_index,
                self.flags,
                disk_inode,
                fs,
            )?;
            // insert parent as child directory
            self.create_hard_link(
                PARENT_FNAME_STR,
                parent_inode_bitmap_index,
                parent_flags,
                disk_inode,
                fs,
            )
        })?
    }

    /// Get the self abstract inode
    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn self_inode(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Self {
        self.get_child_inode(SELF_FNAME_STR, fs).unwrap().unwrap()
    }

    /// Get the current self abstract inode's parent directory abstract inode
    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn parent_inode(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Self {
        self.get_child_inode(PARENT_FNAME_STR, fs).unwrap().unwrap()
    }

    /// Check if the current directory is empty.
    /// Only self file name and parent file name can be exists.
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// * Returns
    /// * Ok(if is empty)
    /// * Err(DataOutOfBounds | InodeMustBeDirectory(bitmap index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn dir_is_empty(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<bool> {
        if !self.flags.is_dir() {
            return Err(FFSError::InodeMustBeDirectory(self.inode_bitmap_index));
        }
        let mut iterator = self.to_entry_iter(fs)?;
        loop {
            let name = iterator.fname.to_str();
            if name != SELF_FNAME_STR && name != PARENT_FNAME_STR && iterator.fentry.is_valid() {
                return Ok(false);
            }
            if !iterator.next(fs)? {
                return Ok(true);
            }
        }
    }

    /// Get all the child's names, excluding the self directory name and parent directory name.
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// Ok(Vec<String>)
    /// Err(DataOutOfBounds | InodeMustBeDirectory(bitmap index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub(crate) fn list_child_names(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<Vec<String>> {
        self.must_be_dir()?;
        let mut iterator = self.to_entry_iter(fs)?;
        let mut names = Vec::new();
        loop {
            let name = iterator.fname.to_str();
            if name != SELF_FNAME_STR && name != PARENT_FNAME_STR && iterator.fentry.is_valid() {
                names.push(name.to_string());
            }
            if !iterator.next(fs)? {
                break;
            }
        }
        Ok(names)
    }

    /// Get the child abstract inode by name
    ///
    /// # Arguments
    /// * name: The name of child abstract inode will be find
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(None): child does not exist
    /// * Ok(Some(child)): child exists and returns the child
    /// * Err(DataOutOfBounds | InodeMustBeDirectory(bitmap index) | NoDroptableBlockCache | RawDeviceError(error code))
    fn get_child_inode(
        &self,
        name: &str,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<Option<Self>> {
        self.must_be_dir()?;
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        for depth in 1..=DENTRY_MAX_DEPTH {
            let next_hash_byte = hash[depth];
            let hash_index = Fname::cal_hash_index(hash_byte);
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, start_offset, fs)?;
                if !fentry.is_valid() {
                    return Ok(None);
                }
                if fentry.next_hash_byte != next_hash_byte {
                    continue;
                }
                let start_offset = Fname::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fname, start_offset, fs)?;
                if !fname.is_equal(name) {
                    continue;
                }
                return Ok(Some(Self::convert_to_inode(&fentry, fs)));
            }
            let start_offset = Fheader::cal_start_offset(leaf_index);
            self.read_child(&mut fheader, start_offset, fs)?;
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index == 0 {
                return Ok(None);
            }
            hash_byte = next_hash_byte;
        }
        Ok(None)
    }

    /// Create a new child abstract inode.
    ///
    /// # Arguments
    /// * name: The name of the child abstract inode
    /// * flags: The flags of the child abstract inode
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(child)
    /// * Err(
    ///     DuplicatedFname(name, inode bitmap index) |
    ///     InodeMustBeDirectory(bitmap index) |
    ///     BitmapExhausted(start_block_id) |
    ///     BitmapIndexDeallocated(bitmap_index) |
    ///     DataOutOfBounds |
    ///     NoDroptableBlockCache |
    ///     RawDeviceError(error code)
    /// )
    fn create_child_inode(
        &self,
        name: &str,
        flags: FileFlags,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<Self> {
        self.must_be_dir()?;
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut next_hash_byte = hash[1];
        let mut leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        let mut end_hash_index = 0;
        let mut end_item_index = 0;
        'outter: for depth in 1..=DENTRY_MAX_DEPTH {
            let hash_index = Fname::cal_hash_index(hash_byte);
            next_hash_byte = hash[depth];
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, start_offset, fs)?;
                if !fentry.is_valid() {
                    end_hash_index = hash_index;
                    end_item_index = item_index;
                    break 'outter;
                }
                if fentry.next_hash_byte != next_hash_byte {
                    continue;
                }
                let start_offset = Fname::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fname, start_offset, fs)?;
                if !fname.is_equal(name) {
                    continue;
                }
                return Err(FFSError::DuplicatedFname(
                    name.to_string(),
                    self.inode_bitmap_index,
                ));
            }
            let start_offset = Fheader::cal_start_offset(leaf_index);
            self.read_child(&mut fheader, start_offset, fs)?;
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index == 0 {
                if depth == DENTRY_MAX_DEPTH {
                    return Err(FFSError::DataOutOfBounds);
                }
                leaf_index = self.increase_block(fs)?;
                fheader.next_leaf_indexes[hash_index] = leaf_index;
                self.write_child(&fheader, start_offset, fs)?;
            }
            hash_byte = next_hash_byte;
        }
        let inode_bitmap_index = fs.alloc_inode_bitmap_index()?;
        fentry = Fentry::new(inode_bitmap_index, flags, next_hash_byte);
        let start_offset = Fentry::cal_start_offset(leaf_index, end_hash_index, end_item_index);
        self.write_child(&fentry, start_offset, fs)?;
        fname = Fname::new(name);
        let start_offset = Fname::cal_start_offset(leaf_index, end_hash_index, end_item_index);
        self.write_child(&fname, start_offset, fs)?;
        let child_inode = Self::convert_to_inode(&fentry, fs);
        if flags.is_dir() {
            child_inode.init_as_dir(
                self.inode_bitmap_index,
                self.flags,
                fs
            )?;
        }
        Ok(child_inode)
    }

    /// Remove child inode from current directory abstract inode
    ///
    /// # Arguments
    /// * name: The name of the child will be removed
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(
    ///     FnameDoesNotExist(name, inode bitmap index) |
    ///     InodeMustBeDirectory(bitmap index) |
    ///     DataOutOfBounds |
    ///     BitmapIndexDeallocated(bitmap_index) |
    ///     NoDroptableBlockCache |
    ///     RawDeviceError(error code) |
    ///     DeleteNonEmptyDirectory(name, inode bitmap index)
    /// )
    fn remove_child_inode(
        &self,
        name: &str,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        self.must_be_dir()?;
        if name == SELF_FNAME_STR || name == PARENT_FNAME_STR {
            return Err(FFSError::FnameDoesNotExist(
                name.to_string(),
                self.inode_bitmap_index,
            ));
        }
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        let mut hit_depth = 0;
        let mut leaf_index = 0u32;
        let mut dst_leaf_index = 0u32;
        let mut dst_hash_index = 0usize;
        let mut dst_item_index = 0usize;
        let mut founeded = false;
        'outter: for depth in 1..=DENTRY_MAX_DEPTH {
            let hash_index = Fname::cal_hash_index(hash_byte);
            let next_hash_byte = hash[depth];
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, start_offset, fs)?;
                if !fentry.is_valid() {
                    break 'outter;
                }
                if fentry.next_hash_byte != next_hash_byte {
                    continue;
                }
                let start_offset = Fname::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fname, start_offset, fs)?;
                if !fname.is_equal(name) {
                    continue;
                }
                let child_inode = Self::convert_to_inode(&fentry, fs);
                if fentry.is_dir() && !child_inode.dir_is_empty(fs)? {
                    return Err(FFSError::DeleteNonEmptyDirectory(
                        name.to_string(),
                        self.inode_bitmap_index,
                    ));
                }
                if !fentry.is_hard_link() {
                    child_inode.clear_as_file(fs)?;
                    fs.dealloc_inode_bitmap_index(fentry.inode_bitmap_index)?;
                }
                hit_depth = depth;
                dst_leaf_index = leaf_index;
                dst_hash_index = hash_index;
                dst_item_index = item_index;
                founeded = true;
                break 'outter;
            }
            let start_offset = Fheader::cal_start_offset(leaf_index);
            self.read_child(&mut fheader, start_offset, fs)?;
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index == 0 {
                break;
            }
            hash_byte = next_hash_byte;
        }
        if !founeded {
            return Err(FFSError::FnameDoesNotExist(
                name.to_string(),
                self.inode_bitmap_index,
            ));
        }
        let (src_leaf_index, src_hash_index, src_item_index) =
            self.find_ending_child_inode(dst_leaf_index, dst_hash_index, dst_item_index, fs)?;
        if src_leaf_index != dst_leaf_index
            || src_hash_index != dst_hash_index
            || src_item_index != dst_item_index
        {
            let start_offset =
                Fentry::cal_start_offset(src_leaf_index, src_hash_index, src_item_index);
            self.read_child(&mut fentry, start_offset, fs)?;
            let start_offset =
                Fname::cal_start_offset(src_leaf_index, src_hash_index, src_item_index);
            self.read_child(&mut fname, start_offset, fs)?;
            fentry.next_hash_byte = Fname::cal_name_hash(fname.to_str())[hit_depth];
            let start_offset =
                Fentry::cal_start_offset(dst_leaf_index, dst_hash_index, dst_item_index);
            self.write_child(&fentry, start_offset, fs)?;
            let start_offset =
                Fname::cal_start_offset(dst_leaf_index, dst_hash_index, dst_item_index);
            self.write_child(&fname, start_offset, fs)?;
            dst_leaf_index = src_leaf_index;
            dst_hash_index = src_hash_index;
            dst_item_index = src_item_index;
        }
        let start_offset = Fentry::cal_start_offset(dst_leaf_index, dst_hash_index, dst_item_index);
        fentry.clear();
        self.write_child(&fentry, start_offset, fs)?;
        let start_offset = Fname::cal_start_offset(dst_leaf_index, dst_hash_index, dst_item_index);
        fname.clear();
        self.write_child(&fname, start_offset, fs)?;
        if dst_item_index == 0 {
            self.clear_empty_ending_leaf_indexes(fs)
        } else {
            Ok(())
        }
    }

    /// Find the ending child inode after input destination child inode,
    /// which will be used to switch position with input destination child inode.
    ///
    /// the ending child inode have three cases:
    /// * 1 - ending child inode is the input child inode itself
    /// * 2 - ending child inode and input child inode are storing in the same leaf block
    /// * 3 - ending child inode and input child inode are storing in the different leaf blocks
    ///
    /// # Arguments
    /// * dst_leaf_index: the leaf index of the input child inode
    /// * dst_hash_index: the hash index of the input child inode
    /// * dst_item_index: the item index of the input child inode
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok((src leaf index, src hash index, src item index))
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn find_ending_child_inode(
        &self,
        dst_leaf_index: u32,
        dst_hash_index: usize,
        dst_item_index: usize,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<(u32, usize, usize)> {
        let mut fheader = Fheader::empty();
        let start_offset = Fheader::cal_start_offset(dst_leaf_index);
        self.read_child(&mut fheader, start_offset, fs)?;
        let next_leaf_index = fheader.next_leaf_indexes[dst_hash_index];
        if next_leaf_index != 0 {
            return self.find_other_leaf_ending_child_inode(next_leaf_index, fs);
        }
        let mut src_item_index = dst_item_index;
        let mut fentry = Fentry::empty();
        for item_index in (dst_item_index + 1)..HASH_GROUP_ITEM_COUNT {
            let start_offset = Fentry::cal_start_offset(dst_leaf_index, dst_hash_index, item_index);
            self.read_child(&mut fentry, start_offset, fs)?;
            if fentry.is_valid() {
                src_item_index = item_index;
            }
        }
        Ok((dst_leaf_index, dst_hash_index, src_item_index))
    }

    /// Find the ending child inode after input ending child inode, which is storing in other leaf blocks.
    ///
    /// # Arguments
    /// * leaf_index: The index of the leaf blocks
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok((src leaf index, src hash index, src item index))
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn find_other_leaf_ending_child_inode(
        &self,
        leaf_index: u32,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<(u32, usize, usize)> {
        let mut fheader = Fheader::empty();
        let start_offset = Fheader::cal_start_offset(leaf_index);
        self.read_child(&mut fheader, start_offset, fs)?;
        // check if the current blocks has more deeeper blocks
        for next_leaf_index in fheader.next_leaf_indexes {
            if next_leaf_index == 0 {
                continue;
            }
            return self.find_other_leaf_ending_child_inode(next_leaf_index, fs);
        }
        let mut src_hash_index = 0;
        let mut src_item_index = 0;
        let mut fentry = Fentry::empty();
        for hash_index in 0..HASH_GROUP_COUNT {
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, start_offset, fs)?;
                if fentry.is_valid() {
                    src_hash_index = hash_index;
                    src_item_index = item_index;
                    continue;
                }
                return Ok((leaf_index, src_hash_index, src_item_index));
            }
        }
        return Ok((leaf_index, src_hash_index, src_item_index));
    }

    /// Clear all possible existing empty leaf blocks.
    /// Each time we remove child inode, it is possible the last child inode in the blocks,
    /// so we should try to clear those blocks.
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn clear_empty_ending_leaf_indexes(
        &self,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        let tracker = Arc::clone(fs.tracker());
        let total_leaf_indexes = self.leaf_block_count(&tracker)?;
        let mut inused_leaf_indexes = total_leaf_indexes;
        let mut fentry = Fentry::empty();
        'outter: for leaf_index in (0..total_leaf_indexes).rev() {
            for hash_index in 0..HASH_GROUP_COUNT {
                let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, 0);
                self.read_child(&mut fentry, start_offset, fs)?;
                if fentry.is_valid() {
                    break 'outter;
                }
            }
            inused_leaf_indexes -= 1;
        }
        if inused_leaf_indexes == total_leaf_indexes {
            return Ok(());
        }
        self.modify_disk_inode(&tracker, |disk_inode| {
            Self::to_byte_size(
                inused_leaf_indexes as u64 * BLOCK_BYTE_SIZE as u64,
                disk_inode,
                fs,
            )
        })??;
        let mut fheader = Fheader::empty();
        let mut clear_leaf_indexes = BTreeSet::new();
        for clear_leaf_index in inused_leaf_indexes..total_leaf_indexes {
            clear_leaf_indexes.insert(clear_leaf_index);
        }
        for inused_leaf_index in (0..inused_leaf_indexes).rev() {
            let start_offset = Fheader::cal_start_offset(inused_leaf_index);
            let mut founded = false;
            self.read_child(&mut fheader, start_offset, fs)?;
            for index in 0..HASH_GROUP_ITEM_COUNT {
                let fheader_leaf_index = fheader.next_leaf_indexes[index];
                if fheader_leaf_index == 0 || !clear_leaf_indexes.contains(&fheader_leaf_index) {
                    continue;
                }
                fheader.next_leaf_indexes[index] = 0;
                clear_leaf_indexes.remove(&fheader_leaf_index);
                founded = true;
            }
            if !founded {
                continue;
            }
            self.write_child(&fheader, start_offset, fs)?;
            if clear_leaf_indexes.len() == 0 {
                break;
            }
        }
        Ok(())
    }
}

/// The iterator for abstract inode structures, which will generate all the valid file entry and file name.
struct AbstractInodeEntryIterator<'a> {
    inode: &'a AbstractInode,
    leaf_block_count: u32,
    leaf_index: u32,
    hash_index: usize,
    item_index: usize,
    fentry: Fentry,
    fname: Fname,
    has_next: bool,
}
impl<'a> AbstractInodeEntryIterator<'a> {
    /// Create a new iterator
    ///
    /// * inode: The reference to the abstract inode
    /// * leaf_block_count: The number of leaf blocks of the abstract inode
    fn new(inode: &'a AbstractInode, leaf_block_count: u32) -> Self {
        Self {
            inode,
            leaf_block_count,
            leaf_index: 0,
            hash_index: 0,
            item_index: 0,
            fentry: Fentry::empty(),
            fname: Fname::empty(),
            has_next: true,
        }
    }

    /// Read the fentry into iterator
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn read_fentry(&mut self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<()> {
        let start_offset =
            Fentry::cal_start_offset(self.leaf_index, self.hash_index, self.item_index);
        self.inode.read_child(&mut self.fentry, start_offset, fs)
    }

    /// Read the fname into iterator
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// # Returns
    /// * Ok(())
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn read_fname(&mut self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<()> {
        let start_offset =
            Fname::cal_start_offset(self.leaf_index, self.hash_index, self.item_index);
        self.inode.read_child(&mut self.fname, start_offset, fs)
    }

    /// Check if the iterator has next, and change the position indexes to the next
    /// If returns true, the iterator has next entry,
    /// and the file entry and file name was loaded successfully.
    /// If returns false, the iterator has no next entry
    ///
    /// # Arguments
    /// * fs: the mutable reference of the file system which owns the current inode
    ///
    /// * Returns
    /// * Ok(true): has next entry
    /// * Ok(false): has no next entry
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    fn next(&mut self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<bool> {
        if !self.has_next {
            return Ok(false);
        }
        loop {
            if self.leaf_index >= self.leaf_block_count {
                self.has_next = false;
                return Ok(false);
            }
            self.read_fentry(fs)?;
            self.read_fname(fs)?;
            match (self.hash_index, self.item_index) {
                (HASH_GROUP_END_INDEX, HASH_GROUP_ITEM_END_INDEX) => {
                    self.hash_index = 0;
                    self.item_index = 0;
                    self.leaf_index += 1;
                }
                (_, HASH_GROUP_ITEM_END_INDEX) => {
                    self.item_index = 0;
                    self.hash_index += 1;
                }
                _ => {
                    self.item_index += 1;
                }
            }
            if !self.fentry.is_valid() {
                continue;
            }
            return Ok(true);
        }
    }
}

pub struct Inode {
    inner: AbstractInode,
    fs: Arc<Mutex<FrontierFileSystem>>,
}
impl Inode {
    /// Create a new inode
    /// 
    /// # Arguments
    /// * inner: abstract inode instance
    /// * fs: the mutable frontier file system
    pub(crate) fn new(inner: AbstractInode, fs: Arc<Mutex<FrontierFileSystem>>) -> Self {
        Inode { inner, fs }
    }

    /// Get the index of the inode in bitmap
    pub fn inode_bitmap_index(&self) -> u32 {
        self.inner.inode_bitmap_index
    }

    /// Read data from block device and write bytes back into buffer.
    /// This function reads a sufficient amount of data from the block device based on the length of the incoming slice,
    /// However, when the data in the device is not enough to fill the entire slice, 
    /// you need to make your own judgment based on the length of the read bytes returned.
    /// 
    /// # Arguments
    /// * buffer: the mutable buffer which will be writed
    /// * start_offset: the offset where the data starts to be read
    /// 
    /// # Returns
    /// * Ok(read bytes length)
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn read_buffer(&self, buffer: &mut [u8], start_offset: u64) -> Result<usize> {
        let mut fs = self.fs.lock();
        self.inner.read_buffer(buffer, start_offset, &mut fs)
    }

    /// Write data to block device according to the buffer.
    /// This function reads a sufficient amount of data from the buffer.
    /// When the block device is not enough space to fill, 
    /// you need to make your own judgment based on the length of the write bytes returned.
    /// 
    /// # Arguments
    /// * buffer: the inmmutable buffer which will be read
    /// * start_offset: the offset where the data starts to be writed
    /// 
    /// # Returns
    /// * Ok(write bytes length)
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn write_buffer(&self, buffer: &[u8], start_offset: u64) -> Result<usize> {
        let mut fs = self.fs.lock();
        self.inner.write_buffer(buffer, start_offset, &mut fs)
    }

    /// Read all bytes from the block device an return the bytes vector.
    /// 
    /// # Returns
    /// * Ok(Vec<bytes>)
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn read_all(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut buffer = [0u8; 512];
        let mut start_offset = 0;
        loop {
            let read_size = self.read_buffer(&mut buffer, start_offset)?;
            if read_size == 0 {
                break;
            }
            result.extend_from_slice(&buffer[0..read_size]);
            start_offset += read_size as u64;
        }
        Ok(result)
    }

    /// List all the name of the child inodes
    /// 
    /// # Returns
    /// * Ok(Vec<Strings>)
    /// * Err(DataOutOfBounds | InodeMustBeDirectory(bitmap index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn list_child_names(&self) -> Result<Vec<String>> {
        let mut fs = self.fs.lock();
        self.inner.list_child_names(&mut fs)
    }

    /// Adjust the size of the current inode based on the value of argument incoming,
    /// note that this adjustment will not be adjusted exactly according to the number of bytes,
    /// because we can only adjust it based on integer multiples of the number of bytes in the block.
    /// As a result, the adjusted inode will generally be larger than the specified number of bytes.
    /// 
    /// # Arguments
    /// * new_byte_size: the new byte size of the inode
    /// 
    /// # Returns
    /// * Ok(()) 
    /// * Err(DataOutOfBounds | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn to_byte_size(&self, new_byte_size: u64) -> Result<()> {
        let mut fs = self.fs.lock();
        let tracker = Arc::clone(fs.tracker());
        self.inner.modify_disk_inode(&tracker, |disk_inode| {
            AbstractInode::to_byte_size(new_byte_size, disk_inode, &mut fs)
        })?
    }

    /// Get child inode from the current directory inode according to the name incoming.
    /// 
    /// # Arguments
    /// * name: the name string of the child inode
    /// 
    /// # Returns
    /// * Ok(Some(chld inode))
    /// * Ok(None)
    /// * Err(DataOutOfBounds | InodeMustBeDirectory(bitmap index) | NoDroptableBlockCache | RawDeviceError(error code))
    pub fn get_child_inode(&self, name: &str) -> Result<Option<Self>> {
        let mut fs = self.fs.lock();
        if let Some(abs_inode) = self.inner.get_child_inode(name, &mut fs)? {
            Ok(Some(Self::new(abs_inode, Arc::clone(&self.fs))))
        } else {
            Ok(None)
        }
    }

    /// Create a new child inode according to the name and flags arguments incomming.
    /// 
    /// # Arguments
    /// * name: the name of the new child inode
    /// * flags: the file flags of the new child inode
    /// 
    /// # Returns
    /// * Ok(child inode)
    /// * Err(
    ///     DuplicatedFname(name, inode bitmap index) |
    ///     InodeMustBeDirectory(bitmap index) |
    ///     BitmapExhausted(start_block_id) |
    ///     BitmapIndexDeallocated(bitmap_index) |
    ///     DataOutOfBounds |
    ///     NoDroptableBlockCache |
    ///     RawDeviceError(error code)
    /// )
    pub fn create_child_inode(&self, name: &str, flags: FileFlags) -> Result<Self> {
        let mut fs = self.fs.lock();
        let abs_inode = self.inner.create_child_inode(name, flags, &mut fs)?;
        Ok(Self::new(abs_inode, Arc::clone(&self.fs)))
    }

    /// Remove a child inode from the current inode.
    /// 
    /// # Arguments
    /// * name: the name of the child inode which will be removed
    /// 
    /// # Returns
    /// * Ok(())
    /// * Err(
    ///     FnameDoesNotExist(name, inode bitmap index) |
    ///     InodeMustBeDirectory(bitmap index) |
    ///     DataOutOfBounds |
    ///     BitmapIndexDeallocated(bitmap_index) |
    ///     NoDroptableBlockCache |
    ///     RawDeviceError(error code) |
    ///     DeleteNonEmptyDirectory(name, inode bitmap index)
    /// )
    pub fn remove_child_inode(&self, name: &str) -> Result<()> {
        let mut fs = self.fs.lock();
        self.inner.remove_child_inode(name, &mut fs)
    }
}

#[cfg(test)]
mod tests {

    use crate::block::{BlockDevice, MemoryBlockDevice, BLOCK_DEVICE_REGISTER};
    use crate::vfs::FS;

    use super::super::{FileSystem, InitMode};
    use super::*;

    const HASH_TOTAL_ITEM_COUNT: usize = HASH_GROUP_COUNT * HASH_GROUP_ITEM_COUNT;

    #[test]
    fn test_entry_size() {
        assert_eq!(
            BLOCK_BYTE_SIZE,
            FHEADER_BYTE_SIZE + (FNAME_BYTE_SIZE + FENTRY_BYTE_SIZE) * HASH_TOTAL_ITEM_COUNT
        )
    }

    #[test]
    fn test_fname_cal_hash() {
        assert_eq!(Fname::cal_hash(&[0, 0]), Fname::cal_hash(&[0, 0]));
        assert_ne!(Fname::cal_hash(&[0, 1]), Fname::cal_hash(&[0, 0]));
    }

    #[test]
    fn test_fname_cal_hash_index() {
        assert_eq!(0, Fname::cal_hash_index(0));
        assert_eq!(1, Fname::cal_hash_index(1));
        assert_eq!(2, Fname::cal_hash_index(2));
        assert_eq!(3, Fname::cal_hash_index(3));
        assert_eq!(0, Fname::cal_hash_index(4));
    }

    #[test]
    fn test_fname_cal_name_hash() {
        assert_eq!(Fname::cal_name_hash("a"), Fname::cal_name_hash("a"));
        assert_ne!(Fname::cal_name_hash("a"), Fname::cal_name_hash("b"));
    }

    #[test]
    fn test_fname_to_str() {
        assert_eq!("", Fname::empty().to_str());
        assert_eq!("a", Fname::new("a").to_str());
        assert_eq!("ab", Fname::new("ab").to_str());
    }

    #[test]
    fn test_fname_is_equal() {
        assert!(Fname::empty().is_equal(""));
        assert!(Fname::new("a").is_equal("a"));
        assert!(Fname::new("ab").is_equal("ab"));

        assert!(!Fname::new("a").is_equal("b"));
        assert!(!Fname::new("ab").is_equal("b"));
        assert!(!Fname::new("ba").is_equal("b"));
        assert!(!Fname::new("b").is_equal("ab"));
        assert!(!Fname::new("b").is_equal("ba"));
        assert!(!Fname::new("a").is_equal("ab"));
        assert!(!Fname::new("a").is_equal("ba"));
        assert!(!Fname::new("ab").is_equal("a"));
        assert!(!Fname::new("ba").is_equal("a"));
    }

    #[test]
    fn test_abstract_inode_to_byte_size_and_leaf_block_count() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        assert_eq!(1, abstract_inode.leaf_block_count(&tracker).unwrap());
        assert!(abstract_inode
            .modify_disk_inode(&tracker, |disk_inode| {
                assert!(AbstractInode::to_byte_size(
                    2 * BLOCK_BYTE_SIZE as u64,
                    disk_inode,
                    &mut mfs
                )
                .is_ok());
            })
            .is_ok());
        assert_eq!(2, abstract_inode.leaf_block_count(&tracker).unwrap());
        assert!(abstract_inode
            .modify_disk_inode(&tracker, |disk_inode| {
                assert!(AbstractInode::to_byte_size(
                    1 * BLOCK_BYTE_SIZE as u64,
                    disk_inode,
                    &mut mfs
                )
                .is_ok());
            })
            .is_ok());
        assert_eq!(1, abstract_inode.leaf_block_count(&tracker).unwrap());
    }

    #[test]
    fn test_abstract_inode_write_and_read_buffer() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        let child_inode = abstract_inode
            .create_child_inode("test", FileFlags::VALID, &mut mfs)
            .unwrap();
        assert!(child_inode
            .modify_disk_inode(&tracker, |disk_inode| {
                AbstractInode::to_byte_size(BLOCK_BYTE_SIZE as u64, disk_inode, &mut mfs)
            })
            .is_ok());
        let mut read_buffer = [0u8; BLOCK_BYTE_SIZE as usize];
        let mut write_buffer = [0u8; BLOCK_BYTE_SIZE as usize];
        assert_eq!(read_buffer, write_buffer);
        assert!(child_inode
            .write_buffer(&write_buffer, 0, &mut mfs)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert!(child_inode
            .read_buffer(&mut read_buffer, 0, &mut mfs)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert_eq!(read_buffer, write_buffer);
        write_buffer[0] = 1u8;
        assert!(child_inode
            .write_buffer(&write_buffer, 0, &mut mfs)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert!(child_inode
            .read_buffer(&mut read_buffer, 0, &mut mfs)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert_eq!(read_buffer, write_buffer);
    }

    #[test]
    fn test_abstract_inode_read_and_write_child() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        let mut fentry = Fentry::empty();
        let start_offset = Fentry::cal_start_offset(0, 0, 0);
        assert!(abstract_inode
            .read_child(&mut fentry, start_offset, &mut mfs)
            .is_ok());
        assert!(!fentry.is_valid());
        assert_eq!(0, fentry.inode_bitmap_index);
        assert_eq!(FileFlags::empty().bits(), fentry.flags.bits());
        assert_eq!(0, fentry.next_hash_byte);
        fentry = Fentry::new(1, FileFlags::VALID, 1);
        assert!(abstract_inode
            .write_child(&fentry, start_offset, &mut mfs)
            .is_ok());
        fentry = Fentry::empty();
        assert!(abstract_inode
            .read_child(&mut fentry, start_offset, &mut mfs)
            .is_ok());
        assert!(fentry.is_valid());
        assert_eq!(1, fentry.inode_bitmap_index);
        assert_eq!(FileFlags::VALID.bits(), fentry.flags.bits());
        assert_eq!(1, fentry.next_hash_byte);
    }

    #[test]
    fn test_inode_write_and_read() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let mock: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(mock).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &tracker).unwrap();
        let inode = fs.root_inode();
        let child_inode = inode.create_child_inode("test", FileFlags::VALID).unwrap();
        assert!(child_inode.to_byte_size(BLOCK_BYTE_SIZE as u64).is_ok());
        let mut read_buffer = [0u8; BLOCK_BYTE_SIZE as usize];
        let mut write_buffer = [0u8; BLOCK_BYTE_SIZE as usize];
        assert_eq!(read_buffer, write_buffer);
        assert!(child_inode
            .write_buffer(&write_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert!(child_inode
            .read_buffer(&mut read_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert_eq!(read_buffer, write_buffer);
        assert_eq!(read_buffer.to_vec(), child_inode.read_all().unwrap());
        write_buffer[0] = 1u8;
        assert!(child_inode
            .write_buffer(&write_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert!(child_inode
            .read_buffer(&mut read_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE));
        assert_eq!(read_buffer, write_buffer);
        assert_eq!(read_buffer.to_vec(), child_inode.read_all().unwrap());

        assert!(child_inode.to_byte_size(BLOCK_BYTE_SIZE as u64 * 2).is_ok());
        let mut read_buffer = [0u8; BLOCK_BYTE_SIZE as usize * 2];
        let mut write_buffer = [0u8; BLOCK_BYTE_SIZE as usize * 2];
        assert_eq!(read_buffer, write_buffer);
        assert!(child_inode
            .write_buffer(&write_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE * 2));
        assert!(child_inode
            .read_buffer(&mut read_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE * 2));
        assert_eq!(read_buffer, write_buffer);
        assert_eq!(read_buffer.to_vec(), child_inode.read_all().unwrap());
        write_buffer[0] = 1u8;
        assert!(child_inode
            .write_buffer(&write_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE * 2));
        assert!(child_inode
            .read_buffer(&mut read_buffer, 0)
            .is_ok_and(|size| size == BLOCK_BYTE_SIZE * 2));
        assert_eq!(read_buffer, write_buffer);
        assert_eq!(read_buffer.to_vec(), child_inode.read_all().unwrap());
    }

    #[test]
    fn test_abstract_inode_init_as_dir() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let device: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(48), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        assert_eq!(
            abstract_inode.inode_bitmap_index,
            abstract_inode.self_inode(&mut mfs).inode_bitmap_index
        );
        assert_eq!(
            abstract_inode.inode_bitmap_index,
            abstract_inode.parent_inode(&mut mfs).inode_bitmap_index
        );
    }

    #[test]
    fn teset_abstract_inode_list_child_names() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let device: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(48), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        assert!(abstract_inode
            .list_child_names(&mut mfs)
            .is_ok_and(|names| names.is_empty()));
        assert!(abstract_inode
            .create_child_inode("test", FileFlags::VALID, &mut mfs)
            .is_ok());
        assert!(abstract_inode
            .list_child_names(&mut mfs)
            .is_ok_and(|names| !names.is_empty() && names[0] == "test"));
        assert!(abstract_inode.remove_child_inode("test", &mut mfs).is_ok());
        assert!(abstract_inode
            .list_child_names(&mut mfs)
            .is_ok_and(|names| names.is_empty()));
    }

    #[test]
    fn test_abstract_inode_create_child_inode() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let device: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(48), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        let names = vec![
            "forkexec",
            "hello_world",
            "usertests",
            "sleep",
            "forktest_simple",
            "fantastic_text",
            "initproc",
            "usertests_simple",
            "yield_out",
            "forktest2",
            "forktest",
            "forktree",
            "stack_overflow",
            "sleep_simple",
            "exit_test",
            "matrix",
            "core_shell",
        ];
        for name in names.iter() {
            assert!(abstract_inode
                .create_child_inode(name, FileFlags::VALID, &mut mfs)
                .is_ok());
        }
        assert_eq!(
            names.len(),
            abstract_inode.list_child_names(&mut mfs).unwrap().len()
        );
    }

    #[test]
    fn test_abstract_inode_create_and_get_child_inode() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let device: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(48), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        assert!(abstract_inode
            .get_child_inode(SELF_FNAME_STR, &mut mfs)
            .is_ok_and(|w| w.is_some_and(
                |child| child.inode_bitmap_index == abstract_inode.inode_bitmap_index
            )));
        assert!(abstract_inode
            .get_child_inode(PARENT_FNAME_STR, &mut mfs)
            .is_ok_and(|w| w.is_some_and(
                |child| child.inode_bitmap_index == abstract_inode.inode_bitmap_index
            )));
        assert!(abstract_inode
            .get_child_inode("test", &mut mfs)
            .is_ok_and(|w| w.is_none()));
        assert!(abstract_inode
            .create_child_inode(SELF_FNAME_STR, FileFlags::VALID, &mut mfs)
            .is_err_and(|e| e.is_duplicatedfname()));
        assert!(abstract_inode
            .create_child_inode(PARENT_FNAME_STR, FileFlags::VALID, &mut mfs)
            .is_err_and(|e| e.is_duplicatedfname()));
        assert!(abstract_inode
            .create_child_inode("test", FileFlags::VALID, &mut mfs)
            .is_ok_and(|child| child.inode_bitmap_index != abstract_inode.inode_bitmap_index));
        assert!(abstract_inode
            .get_child_inode("test", &mut mfs)
            .is_ok_and(|w| w.is_some_and(
                |child| child.inode_bitmap_index != abstract_inode.inode_bitmap_index
            )));
        for i in 0..10 {
            let name = &format!("test{}", i);
            assert!(abstract_inode
                .get_child_inode(name, &mut mfs)
                .is_ok_and(|w| w.is_none()));
            assert!(abstract_inode
                .create_child_inode(name, FileFlags::VALID, &mut mfs)
                .is_ok());
            assert!(abstract_inode
                .get_child_inode(name, &mut mfs)
                .is_ok_and(|w| w.is_some()));
        }
    }

    #[test]
    fn test_abstract_inode_create_and_remove_child_inode() {
        BLOCK_DEVICE_REGISTER.lock().reset().unwrap();
        let device: Box<dyn BlockDevice> = Box::new(MemoryBlockDevice::new());
        let tracker = BLOCK_DEVICE_REGISTER.lock().mount(device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(48), 1, &tracker).unwrap();
        let mut mfs = fs.lock();
        let abstract_inode = mfs.root_abstract_inode();
        for i in 0..10 {
            let name = &format!("test{}", i);
            assert!(abstract_inode
                .get_child_inode(name, &mut mfs)
                .is_ok_and(|w| w.is_none()));
            assert!(abstract_inode
                .create_child_inode(name, FileFlags::VALID, &mut mfs)
                .is_ok());
            assert!(abstract_inode
                .get_child_inode(name, &mut mfs)
                .is_ok_and(|w| w.is_some()));
        }
        assert!(abstract_inode
            .leaf_block_count(&tracker)
            .is_ok_and(|i| i == 2));
        for i in 0..10 {
            let name = &format!("test{}", i);
            assert!(abstract_inode
                .get_child_inode(name, &mut mfs)
                .is_ok_and(|w| w.is_some()));
            assert!(abstract_inode.remove_child_inode(name, &mut mfs).is_ok());
            assert!(abstract_inode
                .get_child_inode(name, &mut mfs)
                .is_ok_and(|w| w.is_none()));
            for j in (i + 1)..10 {
                let name = &format!("test{}", j);
                assert!(
                    abstract_inode
                        .get_child_inode(name, &mut mfs)
                        .is_ok_and(|w| w.is_some()),
                    "{} was deleted, {} must be exist",
                    i,
                    name
                );
            }
        }
        assert!(abstract_inode
            .leaf_block_count(&tracker)
            .is_ok_and(|i| i == 1));
    }
}
