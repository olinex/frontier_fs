// @author:    olinex
// @time:      2023/11/25

// self mods

// use other mods
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use bit_field::BitField;
use sha2::{Digest, Sha256};
use spin::MutexGuard;

// use self mods
use super::ffs::FrontierFileSystem;
use crate::block::{BlockDevice, BLOCK_CACHE_MANAGER};
use crate::configs::BLOCK_BYTE_SIZE;
use crate::layout::DiskInode;
use crate::{AsBytes, AsBytesMut, FFSError, Result};

const DENTRY_MAX_DEPTH: usize = 8;
const NAME_BYTE_SIZE: usize = 242;
const NAME_HASH_BYTE_SIZE: usize = 32;
const HASH_GROUP_COUNT: usize = 4;
const HASH_GROUP_ITEM_COUNT: usize = 4;
const FHEADER_BYTE_SIZE: usize = core::mem::size_of::<Fheader>();
const FENTRY_BYTE_SIZE: usize = core::mem::size_of::<Fentry>();
const FNAME_BYTE_SIZE: usize = core::mem::size_of::<Fname>();

const SELF_FNAME_STR: &str = ".";
const PARENT_FNAME_STR: &str = "..";

bitflags! {
    /// Flags that indicate file's meta infos, including file types/permissions
    #[derive(Clone, Copy)]
    pub struct FileFlags: u32 {
        const VALID = 1 << 31;
        const DIR = 1 << 30;
    }
}
impl FileFlags {
    fn is_valid(&self) -> bool {
        self.contains(FileFlags::VALID)
    }

    fn is_dir(&self) -> bool {
        self.contains(FileFlags::DIR)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Fheader {
    next_leaf_indexes: [u32; HASH_GROUP_COUNT],
}
impl Fheader {
    fn cal_start_offset(leaf_index: u32) -> u64 {
        leaf_index as u64 * BLOCK_BYTE_SIZE as u64
    }

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
    fn cal_start_offset(leaf_index: u32, hash_index: usize, item_index: usize) -> u64 {
        Fentry::cal_start_offset(leaf_index, hash_index, item_index) + FENTRY_BYTE_SIZE as u64
    }

    fn cal_hash(bytes: &[u8]) -> [u8; NAME_HASH_BYTE_SIZE] {
        let mut name_hash = [0; NAME_HASH_BYTE_SIZE];
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        name_hash.copy_from_slice(&hasher.finalize());
        name_hash
    }

    fn cal_hash_index(byte: u8) -> usize {
        byte.get_bits(0..2) as usize
    }

    fn cal_name_hash(name: &str) -> [u8; NAME_HASH_BYTE_SIZE] {
        let bytes = name.as_bytes();
        let name_len = bytes.len();
        assert!(name_len <= NAME_BYTE_SIZE && bytes[name_len - 1] as char != '\0');
        Self::cal_hash(bytes)
    }

    fn empty() -> Self {
        Self {
            bytes: [0; NAME_BYTE_SIZE],
            length: 0,
        }
    }

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

    fn to_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[0..self.length as usize]).unwrap()
    }

    fn is_equal(&self, other: &str) -> bool {
        self.to_str().as_bytes().iter().eq(other.as_bytes().iter())
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
    #[inline(always)]
    fn is_dir(&self) -> bool {
        self.flags.is_dir()
    }

    /// Check if the file entry is valid
    #[inline(always)]
    fn is_valid(&self) -> bool {
        self.flags.is_valid()
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
pub struct Inode {
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
impl Inode {
    #[inline(always)]
    pub fn flags(&self) -> FileFlags {
        self.flags
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
    pub fn read_disk_inode<V>(
        &self,
        device: &Arc<dyn BlockDevice>,
        f: impl FnOnce(&DiskInode) -> V,
    ) -> Result<V> {
        BLOCK_CACHE_MANAGER
            .get_cache(self.disk_inode_block_id as usize, device)?
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
    pub fn modify_disk_inode<V>(
        &self,
        device: &Arc<dyn BlockDevice>,
        f: impl FnOnce(&mut DiskInode) -> V,
    ) -> Result<V> {
        BLOCK_CACHE_MANAGER
            .get_cache(self.disk_inode_block_id as usize, device)?
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
    fn to_byte_size(
        &self,
        new_byte_size: u64,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        let origin_byte_size = disk_inode.byte_size();
        let blocks_needed = disk_inode.blocks_needed(new_byte_size)?;
        if new_byte_size > origin_byte_size {
            let block_ids = fs.bulk_alloc_data_block_ids(blocks_needed)?;
            disk_inode.increase_to_byte_size(new_byte_size, block_ids, fs.device())
        } else if new_byte_size < origin_byte_size {
            let block_ids = disk_inode.decrease_to_byte_size(new_byte_size, fs.device())?;
            fs.bulk_dealloc_data_block_ids(block_ids)
        } else {
            Ok(())
        }
    }

    /// Get the count of the leaf blocks in the disk inode
    pub fn leaf_block_count(&self, device: &Arc<dyn BlockDevice>) -> Result<u32> {
        self.read_disk_inode(device, |disk_inode| disk_inode.leaf_block_count())
    }
}
// as file
impl Inode {
    /// Create a new Inode as file
    ///
    /// # Arguments
    /// * inode_bitmap_index: the index of the disk in the bitmap
    /// * disk_inode_block_id: the block id in the block device
    /// * disk_indde_block_offset: the offset of the disk inode in the block
    /// * flags: the file flags of the disk inode
    pub fn new(
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
    pub fn clear_as_file(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<()> {
        let device = fs.device();
        let data_block_ids =
            self.modify_disk_inode(device, |disk_inode| disk_inode.clear_byte_size(device))??;
        fs.bulk_dealloc_data_block_ids(data_block_ids)
    }
}
// as directory
impl Inode {
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

    fn increase_block(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<u32> {
        let device = Arc::clone(fs.device());
        let origin_leaf_blocks = self.leaf_block_count(&device)?;
        self.modify_disk_inode(&device, |disk_inode| {
            self.to_byte_size(
                (origin_leaf_blocks + 1) as u64 * BLOCK_BYTE_SIZE as u64,
                disk_inode,
                fs,
            )
        })??;
        Ok(origin_leaf_blocks)
    }

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
        let device = Arc::clone(fs.device());
        self.read_disk_inode(&device, |disk_inode| {
            match disk_inode.read_at(start_offset, buffer, &device) {
                Ok(size) if size == buffer.len() as u64 => Ok(()),
                Ok(_) => Err(FFSError::DataOutOfBounds),
                Err(e) => Err(e),
            }
        })?
    }

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
        self.modify_disk_inode(fs.device(), |disk_inode| {
            match disk_inode.write_at(start_offset, buffer, fs.device()) {
                Ok(size) if size == buffer.len() as u64 => Ok(()),
                Ok(_) => Err(FFSError::DataOutOfBounds),
                Err(e) => Err(e),
            }
        })?
    }

    pub fn init_as_dir(
        &self,
        parent_inode_bitmap_index: u32,
        parent_flags: FileFlags,
        fs: &mut MutexGuard<'_, FrontierFileSystem>,
    ) -> Result<()> {
        let device = Arc::clone(fs.device());
        
        self.modify_disk_inode(&device, |disk_inode| {
            self.to_byte_size(BLOCK_BYTE_SIZE as u64, disk_inode, fs)?;
            // insert self as child directory
            let hash_bytes = Fname::cal_name_hash(SELF_FNAME_STR);
            let hash_index = Fname::cal_hash_index(hash_bytes[0]);
            let fentry = Fentry::new(self.inode_bitmap_index, self.flags, hash_bytes[1]);
            let start_offset = Fentry::cal_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fentry.as_bytes(), fs.device())?;
            let fname = Fname::new(SELF_FNAME_STR);
            let start_offset = Fname::cal_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fname.as_bytes(), fs.device())?;
            // insert parent as child directory
            let hash_bytes = Fname::cal_name_hash(PARENT_FNAME_STR);
            let hash_index = Fname::cal_hash_index(hash_bytes[0]);
            let fentry = Fentry::new(parent_inode_bitmap_index, parent_flags, hash_bytes[1]);
            let start_offset = Fentry::cal_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fentry.as_bytes(), fs.device())?;
            let fname = Fname::new(SELF_FNAME_STR);
            let start_offset = Fname::cal_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fname.as_bytes(), fs.device())?;
            Ok(())
        })?
    }

    pub fn dir_is_empty(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<bool> {
        let device = Arc::clone(fs.device());
        let total_leaf_indexes = self.leaf_block_count(&device)?;
        let mut fname = Fname::empty();
        let mut fentry = Fentry::empty();
        for leaf_index in 0..total_leaf_indexes {
            for hash_index in 0..HASH_GROUP_COUNT {
                for item_index in 0..HASH_GROUP_ITEM_COUNT {
                    let start_offset = Fname::cal_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fname, start_offset, fs)?;
                    let name = fname.to_str();
                    if name == SELF_FNAME_STR || name == PARENT_FNAME_STR {
                        continue;
                    }
                    let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fentry, start_offset, fs)?;
                    if fentry.is_valid() {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    #[inline(always)]
    pub fn self_inode(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Self {
        self.get_child_inode(SELF_FNAME_STR, fs).unwrap().unwrap()
    }

    #[inline(always)]
    pub fn parent_inode(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Self {
        self.get_child_inode(PARENT_FNAME_STR, fs).unwrap().unwrap()
    }

    pub fn get_child_inode(
        &self,
        name: &str,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<Option<Self>> {
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut hash_index = Fname::cal_hash_index(hash_byte);
        let mut leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        for depth in 0..DENTRY_MAX_DEPTH {
            let next_hash_byte = hash[depth + 1];
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
            hash_byte = next_hash_byte;
            hash_index = Fname::cal_hash_index(hash_byte);
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index == 0 {
                return Ok(None);
            }
        }
        Ok(None)
    }

    pub fn list_child_name(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<Vec<String>> {
        let device = Arc::clone(fs.device());
        let leaf_block_indexes = self.leaf_block_count(&device)?;
        let mut names = Vec::new();
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        for leaf_index in 0..leaf_block_indexes {
            for hash_index in 0..HASH_GROUP_COUNT {
                for item_index in 0..HASH_GROUP_ITEM_COUNT {
                    let fentry_start_offset =
                        Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fentry, fentry_start_offset, fs)?;
                    if !fentry.is_valid() {
                        continue;
                    }
                    let fname_start_offset =
                        Fname::cal_start_offset(leaf_index, hash_index, item_index);
                    self.write_child(&mut fname, fname_start_offset, fs)?;
                    names.push(fname.to_str().to_string())
                }
            }
        }
        Ok(names)
    }

    pub fn create_child_inode(
        &self,
        name: &str,
        flags: FileFlags,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<Self> {
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut hash_index = Fname::cal_hash_index(hash_byte);
        let mut leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        for depth in 0..DENTRY_MAX_DEPTH {
            let next_hash_byte = hash[depth + 1];
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let fentry_start_offset =
                    Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                let fname_start_offset =
                    Fname::cal_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, fentry_start_offset, fs)?;
                if !fentry.is_valid() {
                    let inode_bitmap_index = fs.alloc_inode_bitmap_index()?;
                    fentry = Fentry::new(inode_bitmap_index, flags, next_hash_byte);
                    fname = Fname::new(name);
                    self.write_child(&mut fentry, fentry_start_offset, fs)?;
                    self.write_child(&mut fname, fname_start_offset, fs)?;
                    let inode = Self::convert_to_inode(&fentry, fs);
                    inode.modify_disk_inode(fs.device(), |disk_inode| disk_inode.initialize())?;
                    if flags.is_dir() {
                        inode.init_as_dir(self.inode_bitmap_index, self.flags, fs)?;
                    }
                    return Ok(inode);
                }
                if fentry.next_hash_byte != next_hash_byte {
                    continue;
                }
                self.read_child(&mut fname, fname_start_offset, fs)?;
                if fname.is_equal(name) {
                    return Err(FFSError::DuplicatedFname(fentry.inode_bitmap_index));
                }
            }
            let fheader_start_offset = Fheader::cal_start_offset(leaf_index);
            self.read_child(&mut fheader, fheader_start_offset, fs)?;
            hash_byte = next_hash_byte;
            hash_index = Fname::cal_hash_index(hash_byte);
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index != 0 {
                continue;
            }
            if depth != (DENTRY_MAX_DEPTH - 1) {
                leaf_index = self.increase_block(fs)?;
                fheader.next_leaf_indexes[hash_index] = leaf_index;
                self.write_child(&mut fheader, fheader_start_offset, fs)?;
                continue;
            }
            break;
        }
        Err(FFSError::DataOutOfBounds)
    }

    pub fn remove_child_inode(
        &self,
        name: &str,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        if name == SELF_FNAME_STR || name == PARENT_FNAME_STR {
            return Err(FFSError::FnameDoesNotExist(self.inode_bitmap_index));
        }
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut hash_index = Fname::cal_hash_index(hash_byte);
        let mut last_leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        let mut dst_fentry_start_offset = 0;
        let mut dst_fname_start_offset = 0;
        let mut src_fentry_start_offset = 0;
        let mut src_fname_start_offset = 0;
        let mut founded = false;
        'outter: for depth in 0..DENTRY_MAX_DEPTH {
            let next_hash_byte = hash[depth + 1];
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let fentry_start_offset =
                    Fentry::cal_start_offset(last_leaf_index, hash_index, item_index);
                let fname_start_offset =
                    Fname::cal_start_offset(last_leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, fentry_start_offset, fs)?;
                if founded {
                    if fentry.is_valid() {
                        src_fentry_start_offset = fentry_start_offset;
                        src_fname_start_offset = fname_start_offset;
                    } else {
                        break 'outter;
                    }
                } else {
                    if !fentry.is_valid() {
                        break 'outter;
                    }
                    if fentry.next_hash_byte != next_hash_byte {
                        continue;
                    }
                    self.read_child(&mut fname, fname_start_offset, fs)?;
                    if !fname.is_equal(name) {
                        continue;
                    }
                    if fentry.is_dir() && Self::convert_to_inode(&fentry, fs).dir_is_empty(fs)? {
                        return Err(FFSError::DeleteNonEmptyDirectory(fentry.inode_bitmap_index));
                    }
                    dst_fentry_start_offset = fentry_start_offset;
                    dst_fname_start_offset = fname_start_offset;
                    founded = true;
                }
            }
            let start_offset = Fheader::cal_start_offset(last_leaf_index);
            self.read_child(&mut fheader, start_offset, fs)?;
            hash_byte = next_hash_byte;
            hash_index = Fname::cal_hash_index(hash_byte);
            let current_leaf_index = fheader.next_leaf_indexes[hash_index];
            if current_leaf_index == 0 {
                break;
            }
            last_leaf_index = current_leaf_index;
        }
        if !founded {
            return Err(FFSError::FnameDoesNotExist(self.inode_bitmap_index));
        }
        // dealloc the entry's disk inode
        self.read_child(&mut fentry, dst_fentry_start_offset, fs)?;
        fs.dealloc_inode_bitmap_index(fentry.inode_bitmap_index)?;
        let inode = Self::convert_to_inode(&fentry, fs);
        inode.clear_as_file(fs)?;
        // find the prossible existing child in the last leaf index which can relpace the deleted child
        if src_fentry_start_offset != 0 && src_fname_start_offset != 0 {
            self.read_child(&mut fentry, src_fentry_start_offset, fs)?;
            self.read_child(&mut fname, src_fname_start_offset, fs)?;
            self.write_child(&mut fentry, dst_fentry_start_offset, fs)?;
            self.write_child(&mut fname, dst_fname_start_offset, fs)?;
            self.write_child(&mut Fentry::empty(), src_fentry_start_offset, fs)?;
            self.write_child(&mut Fname::empty(), src_fname_start_offset, fs)?;
        } else {
            self.write_child(&mut Fentry::empty(), dst_fentry_start_offset, fs)?;
            self.write_child(&mut Fname::empty(), dst_fname_start_offset, fs)?;
        }
        // try to release the last leaf index if it is empty
        self.clear_empty_ending_leaf_indexes(fs)
    }

    fn clear_empty_ending_leaf_indexes(
        &self,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        let device = Arc::clone(fs.device());
        let total_leaf_indexes = self.leaf_block_count(&device)?;
        let mut inused_leaf_indexes = total_leaf_indexes;
        let mut fentry = Fentry::empty();
        'outter: for leaf_index in (0..total_leaf_indexes).rev() {
            for hash_index in 0..HASH_GROUP_COUNT {
                for item_index in 0..HASH_GROUP_ITEM_COUNT {
                    let start_offset = Fentry::cal_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fentry, start_offset, fs)?;
                    if fentry.is_valid() {
                        break 'outter;
                    }
                }
            }
            inused_leaf_indexes -= 1;
        }
        if inused_leaf_indexes == total_leaf_indexes {
            return Ok(());
        }
        let device = Arc::clone(fs.device());
        self.modify_disk_inode(&device, |disk_inode| {
            self.to_byte_size(
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
            self.write_child(&mut fheader, start_offset, fs)?;
            if clear_leaf_indexes.len() == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use crate::block::{BlockDevice, MockBlockDevice};
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
    fn test_inode_to_byte_size_and_leaf_block_count() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &device).unwrap();
        let inode = fs.root_inode();
        let mut mfs = fs.lock();
        let device = Arc::clone(&mfs.device());
        assert_eq!(1, inode.leaf_block_count(&device).unwrap());
        assert!(inode
            .modify_disk_inode(&device, |disk_inode| {
                assert!(inode
                    .to_byte_size(2 * BLOCK_BYTE_SIZE as u64, disk_inode, &mut mfs)
                    .is_ok());
            })
            .is_ok());
        assert_eq!(2, inode.leaf_block_count(&device).unwrap());
        assert!(inode
            .modify_disk_inode(&device, |disk_inode| {
                assert!(inode
                    .to_byte_size(1 * BLOCK_BYTE_SIZE as u64, disk_inode, &mut mfs)
                    .is_ok());
            })
            .is_ok());
        assert_eq!(1, inode.leaf_block_count(&device).unwrap());
    }

    #[test]
    fn test_dir_create_and_get_and_remove_child_inode() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        // let disk_inode = DiskInode::get(0, 0, &device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &device).unwrap();
        let inode = fs.root_inode();
        let mut mfs = fs.lock();
        let device = Arc::clone(mfs.device());
        // test get and delete entry from empty directory
        assert!(inode
            .get_child_inode("test", &mut mfs)
            .is_ok_and(|i| i.is_none()));
        assert!(inode
            .remove_child_inode("test", &mut mfs)
            .is_err_and(|e| e.is_fnamedoesnotexist()));
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 1);
        // test insert and delete entry into empty directory
        assert!(inode
            .create_child_inode("test", FileFlags::empty(), &mut mfs)
            .is_ok_and(|i| i.flags.is_valid() && !i.flags.is_dir() && i.inode_bitmap_index == 1));
        assert!(inode
            .get_child_inode("other", &mut mfs)
            .is_ok_and(|i| i.is_none()));
        assert!(inode
            .get_child_inode("test", &mut mfs)
            .unwrap()
            .is_some_and(|i| i.flags.is_valid() && !i.flags.is_dir() && i.inode_bitmap_index == 1));
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 1);
        assert!(inode.remove_child_inode("test", &mut mfs).is_ok());
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 1);
        // test insert entry into a non-empty directory
        assert!(inode
            .create_child_inode("other", FileFlags::DIR, &mut mfs)
            .is_ok_and(|i| i.flags.is_valid() && i.flags.is_dir() && i.inode_bitmap_index == 1));
        assert!(inode
            .get_child_inode("test", &mut mfs)
            .is_ok_and(|i| i.is_none()));
        assert!(inode
            .get_child_inode("other", &mut mfs)
            .unwrap()
            .is_some_and(|i| i.flags.is_valid() && i.flags.is_dir() && i.inode_bitmap_index == 1));
        assert!(inode.leaf_block_count(&device).is_ok_and(|i| i == 1));
        // test insert same hash byte fentry into directory
        // number in list have the same prefix hash byte 9f with "test"
        // those number name files will be stored in the leaf indexes [0, 0, 0, 0, 1, 2, 3, 2, 3]
        for (index, x) in vec![35, 114, 249, 655, 803, 1084, 1500, 1764, 2167]
            .iter()
            .enumerate()
        {
            assert!(inode
                .create_child_inode(x.to_string().as_str(), FileFlags::empty(), &mut mfs)
                .is_ok_and(|i| i.flags.is_valid()
                    && !i.flags.is_dir()
                    && i.inode_bitmap_index == (2 + index as u32)));
        }
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 4);

        assert!(inode.get_child_inode("803", &mut mfs).unwrap().is_some());
        assert!(inode.remove_child_inode("803", &mut mfs).is_ok());
        assert!(inode.get_child_inode("803", &mut mfs).unwrap().is_none());
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 4);

        assert!(inode.get_child_inode("2167", &mut mfs).unwrap().is_some());
        assert!(inode.remove_child_inode("2167", &mut mfs).is_ok());
        assert!(inode.get_child_inode("2167", &mut mfs).unwrap().is_none());
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 4);

        assert!(inode.get_child_inode("1764", &mut mfs).unwrap().is_some());
        assert!(inode.remove_child_inode("1764", &mut mfs).is_ok());
        assert!(inode.get_child_inode("1764", &mut mfs).unwrap().is_none());
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 4);

        assert!(inode.get_child_inode("1500", &mut mfs).unwrap().is_some());
        assert!(inode.remove_child_inode("1500", &mut mfs).is_ok());
        assert!(inode.get_child_inode("1500", &mut mfs).unwrap().is_none());
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 3);

        assert!(inode.get_child_inode("1084", &mut mfs).unwrap().is_some());
        assert!(inode.remove_child_inode("1084", &mut mfs).is_ok());
        assert!(inode.get_child_inode("1084", &mut mfs).unwrap().is_none());
        assert_eq!(inode.leaf_block_count(&device).unwrap(), 1);
    }
}
