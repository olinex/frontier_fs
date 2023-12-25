// @author:    olinex
// @time:      2023/11/22

// self mods

use alloc::collections::BTreeSet;
use bit_field::BitField;
// use other mods
use sha2::{Digest, Sha256};
use spin::MutexGuard;

// use self mods
use super::ffs::FrontierFileSystem;
use super::inode::Inode;
use crate::configs::BLOCK_BYTE_SIZE;
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
        const IS_DIR = 1 << 30;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Fheader {
    next_leaf_indexes: [u32; HASH_GROUP_COUNT],
}
impl Fheader {
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
pub struct Fname {
    bytes: [u8; NAME_BYTE_SIZE],
    length: u8,
}
impl Fname {
    fn cal_hash(bytes: &[u8]) -> [u8; NAME_HASH_BYTE_SIZE] {
        let mut name_hash = [0; NAME_HASH_BYTE_SIZE];
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        name_hash.copy_from_slice(&hasher.finalize());
        name_hash
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
pub struct Fentry {
    /// the bitmap index of the inode
    inode_bitmap_index: u32,
    /// the glags that indicate file's meta infos
    flags: FileFlags,
    /// next hash byte in name hash
    next_hash_byte: u8,
}
impl Fentry {
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
    fn is_dir(&self) -> bool {
        self.flags.contains(FileFlags::IS_DIR)
    }

    /// Check if the file entry is valid
    fn is_valid(&self) -> bool {
        self.flags.contains(FileFlags::VALID)
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

pub struct Directory(Inode);
impl Directory {
    fn cal_fheader_start_offset(leaf_index: u32) -> u64 {
        leaf_index as u64 * BLOCK_BYTE_SIZE as u64
    }

    fn cal_fentry_start_offset(leaf_index: u32, hash_index: usize, item_index: usize) -> u64 {
        Self::cal_fheader_start_offset(leaf_index)
            + FHEADER_BYTE_SIZE as u64
            + ((hash_index as u64 * HASH_GROUP_ITEM_COUNT as u64 + item_index as u64)
                * (FENTRY_BYTE_SIZE + FNAME_BYTE_SIZE) as u64)
    }

    fn cal_fname_start_offset(leaf_index: u32, hash_index: usize, item_index: usize) -> u64 {
        Self::cal_fentry_start_offset(leaf_index, hash_index, item_index) + FENTRY_BYTE_SIZE as u64
    }

    fn cal_hash_index(byte: u8) -> usize {
        byte.get_bits(0..2) as usize
    }

    pub fn new(inode: Inode) -> Self {
        Self(inode)
    }

    pub fn initialize(
        &self,
        parent_inode_bitmap_index: u32,
        self_flags: FileFlags,
        parent_flags: FileFlags,
        fs: &mut MutexGuard<'_, FrontierFileSystem>,
    ) -> Result<()> {
        self.0.modify_disk_inode(|disk_inode| {
            self.0
                .to_byte_size(BLOCK_BYTE_SIZE as u64, disk_inode, fs)?;
            // insert self as child directory
            let hash_bytes = Fname::cal_name_hash(SELF_FNAME_STR);
            let hash_index = Self::cal_hash_index(hash_bytes[0]);
            let fentry = Fentry::new(self.0.inode_bitmap_index(), self_flags, hash_bytes[1]);
            let start_offset = Self::cal_fentry_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fentry.as_bytes(), self.0.device())?;
            let fname = Fname::new(SELF_FNAME_STR);
            let start_offset = Self::cal_fname_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fname.as_bytes(), self.0.device())?;
            // insert parent as child directory
            let hash_bytes = Fname::cal_name_hash(PARENT_FNAME_STR);
            let hash_index = Self::cal_hash_index(hash_bytes[0]);
            let fentry = Fentry::new(parent_inode_bitmap_index, parent_flags, hash_bytes[1]);
            let start_offset = Self::cal_fentry_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fentry.as_bytes(), self.0.device())?;
            let fname = Fname::new(SELF_FNAME_STR);
            let start_offset = Self::cal_fname_start_offset(0, hash_index, 0);
            disk_inode.write_at(start_offset, fname.as_bytes(), self.0.device())?;
            Ok(())
        })?
    }

    fn is_empty(&self) -> Result<bool> {
        let total_leaf_indexes = self.0.leaf_block_count()?;
        let mut fname = Fname::empty();
        let mut fentry = Fentry::empty();
        for leaf_index in 0..total_leaf_indexes {
            for hash_index in 0..HASH_GROUP_COUNT {
                for item_index in 0..HASH_GROUP_ITEM_COUNT {
                    let start_offset =
                        Self::cal_fname_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fname, start_offset)?;
                    let name = fname.to_str();
                    if name == SELF_FNAME_STR || name == PARENT_FNAME_STR {
                        continue;
                    }
                    let start_offset =
                        Self::cal_fentry_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fentry, start_offset)?;
                    if fentry.is_valid() {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    fn convert_to_inode(&self, fentry: &Fentry, fs: &mut MutexGuard<FrontierFileSystem>) -> Inode {
        let (disk_inode_block_id, disk_inode_block_offset) =
            fs.cal_disk_inode_position(fentry.inode_bitmap_index);
        Inode::new(
            fentry.inode_bitmap_index,
            disk_inode_block_id,
            disk_inode_block_offset,
            self.0.fs(),
            self.0.device(),
        )
    }

    fn read_child<T>(&self, child: &mut T, start_offset: u64) -> Result<()>
    where
        T: AsBytesMut,
    {
        let buffer = child.as_bytes_mut();
        self.0.read_disk_inode(|disk_inode| {
            match disk_inode.read_at(start_offset, buffer, self.0.device()) {
                Ok(size) if size == buffer.len() as u64 => Ok(()),
                Ok(_) => Err(FFSError::DataOutOfBounds),
                Err(e) => Err(e),
            }
        })?
    }

    fn write_child<T>(&self, child: &T, start_offset: u64) -> Result<()>
    where
        T: AsBytes,
    {
        let buffer = child.as_bytes();
        self.0.modify_disk_inode(|disk_inode| {
            match disk_inode.write_at(start_offset, buffer, self.0.device()) {
                Ok(size) if size == buffer.len() as u64 => Ok(()),
                Ok(_) => Err(FFSError::DataOutOfBounds),
                Err(e) => Err(e),
            }
        })?
    }

    fn increase_block(&self, fs: &mut MutexGuard<FrontierFileSystem>) -> Result<u32> {
        let origin_leaf_blocks = self.0.leaf_block_count()?;
        self.0.modify_disk_inode(|disk_inode| {
            self.0.to_byte_size(
                (origin_leaf_blocks + 1) as u64 * BLOCK_BYTE_SIZE as u64,
                disk_inode,
                fs,
            )
        })??;
        Ok(origin_leaf_blocks)
    }

    fn self_entry(&self) -> Result<(Fname, Fentry)> {
        Ok(self.get_child_entry(SELF_FNAME_STR)?.unwrap())
    }

    pub fn get_child_entry(&self, name: &str) -> Result<Option<(Fname, Fentry)>> {
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut hash_index = Self::cal_hash_index(hash_byte);
        let mut leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        for depth in 0..DENTRY_MAX_DEPTH {
            let next_hash_byte = hash[depth + 1];
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let start_offset =
                    Self::cal_fentry_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, start_offset)?;
                if !fentry.is_valid() {
                    return Ok(None);
                }
                if fentry.next_hash_byte != next_hash_byte {
                    continue;
                }
                let start_offset = Self::cal_fname_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fname, start_offset)?;
                if !fname.is_equal(name) {
                    continue;
                }
                return Ok(Some((fname, fentry)));
            }
            let start_offset = Self::cal_fheader_start_offset(leaf_index);
            self.read_child(&mut fheader, start_offset)?;
            hash_byte = next_hash_byte;
            hash_index = Self::cal_hash_index(hash_byte);
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index == 0 {
                return Ok(None);
            }
        }
        Ok(None)
    }

    pub fn create_child_entry(&self, name: &str, flags: FileFlags) -> Result<(Fname, Fentry)> {
        let mut fs = self.0.fs().lock();
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut hash_index = Self::cal_hash_index(hash_byte);
        let mut leaf_index = 0;
        let mut fentry = Fentry::empty();
        let mut fname = Fname::empty();
        let mut fheader = Fheader::empty();
        for depth in 0..DENTRY_MAX_DEPTH {
            let next_hash_byte = hash[depth + 1];
            for item_index in 0..HASH_GROUP_ITEM_COUNT {
                let fentry_start_offset =
                    Self::cal_fentry_start_offset(leaf_index, hash_index, item_index);
                let fname_start_offset =
                    Self::cal_fname_start_offset(leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, fentry_start_offset)?;
                if !fentry.is_valid() {
                    let inode_bitmap_index = fs.alloc_inode_bitmap_index()?;
                    fentry = Fentry::new(inode_bitmap_index, flags, next_hash_byte);
                    fname = Fname::new(name);
                    self.write_child(&mut fentry, fentry_start_offset)?;
                    self.write_child(&mut fname, fname_start_offset)?;
                    let inode = self.convert_to_inode(&fentry, &mut fs);
                    inode.modify_disk_inode(|disk_inode| disk_inode.initialize())?;
                    if flags.contains(FileFlags::IS_DIR) {
                        let (_, self_entry) = self.self_entry()?;
                        let dir = Directory::new(inode);
                        dir.initialize(
                            self.0.inode_bitmap_index(),
                            flags,
                            self_entry.flags,
                            &mut fs,
                        )?;
                    }
                    return Ok((fname, fentry));
                }
                if fentry.next_hash_byte != next_hash_byte {
                    continue;
                }
                self.read_child(&mut fname, fname_start_offset)?;
                if fname.is_equal(name) {
                    return Err(FFSError::DuplicatedFname(fentry.inode_bitmap_index));
                }
            }
            let fheader_start_offset = Self::cal_fheader_start_offset(leaf_index);
            self.read_child(&mut fheader, fheader_start_offset)?;
            hash_byte = next_hash_byte;
            hash_index = Self::cal_hash_index(hash_byte);
            leaf_index = fheader.next_leaf_indexes[hash_index];
            if leaf_index != 0 {
                continue;
            }
            if depth != (DENTRY_MAX_DEPTH - 1) {
                leaf_index = self.increase_block(&mut fs)?;
                fheader.next_leaf_indexes[hash_index] = leaf_index;
                self.write_child(&mut fheader, fheader_start_offset)?;
                continue;
            }
            break;
        }
        Err(FFSError::DataOutOfBounds)
    }

    pub fn remove_child_entry(&self, name: &str) -> Result<()> {
        if name == SELF_FNAME_STR || name == PARENT_FNAME_STR {
            return Err(FFSError::FnameDoesNotExist(self.0.inode_bitmap_index()));
        }
        let mut fs = self.0.fs().lock();
        let hash = Fname::cal_name_hash(name);
        let mut hash_byte = hash[0];
        let mut hash_index = Self::cal_hash_index(hash_byte);
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
                    Self::cal_fentry_start_offset(last_leaf_index, hash_index, item_index);
                let fname_start_offset =
                    Self::cal_fname_start_offset(last_leaf_index, hash_index, item_index);
                self.read_child(&mut fentry, fentry_start_offset)?;
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
                    self.read_child(&mut fname, fname_start_offset)?;
                    if !fname.is_equal(name) {
                        continue;
                    }
                    if fentry.is_dir()
                        && !Self::new(self.convert_to_inode(&fentry, &mut fs)).is_empty()?
                    {
                        return Err(FFSError::DeleteNonEmptyDirectory(fentry.inode_bitmap_index));
                    }
                    dst_fentry_start_offset = fentry_start_offset;
                    dst_fname_start_offset = fname_start_offset;
                    founded = true;
                }
            }
            let start_offset = Self::cal_fheader_start_offset(last_leaf_index);
            self.read_child(&mut fheader, start_offset)?;
            hash_byte = next_hash_byte;
            hash_index = Self::cal_hash_index(hash_byte);
            let current_leaf_index = fheader.next_leaf_indexes[hash_index];
            if current_leaf_index == 0 {
                break;
            }
            last_leaf_index = current_leaf_index;
        }
        if !founded {
            return Err(FFSError::FnameDoesNotExist(self.0.inode_bitmap_index()));
        }
        // dealloc the entry's disk inode
        self.read_child(&mut fentry, dst_fentry_start_offset)?;
        fs.dealloc_inode_bitmap_index(fentry.inode_bitmap_index)?;
        let inode = self.convert_to_inode(&fentry, &mut fs);
        inode.clear_as_file(&mut fs)?;
        // find the prossible existing child in the last leaf index which can relpace the deleted child
        if src_fentry_start_offset != 0 && src_fname_start_offset != 0 {
            self.read_child(&mut fentry, src_fentry_start_offset)?;
            self.read_child(&mut fname, src_fname_start_offset)?;
            self.write_child(&mut fentry, dst_fentry_start_offset)?;
            self.write_child(&mut fname, dst_fname_start_offset)?;
            self.write_child(&mut Fentry::empty(), src_fentry_start_offset)?;
            self.write_child(&mut Fname::empty(), src_fname_start_offset)?;
        } else {
            self.write_child(&mut Fentry::empty(), dst_fentry_start_offset)?;
            self.write_child(&mut Fname::empty(), dst_fname_start_offset)?;
        }
        // try to release the last leaf index if it is empty
        self.clear_empty_ending_leaf_indexes(&mut fs)
    }

    fn clear_empty_ending_leaf_indexes(
        &self,
        fs: &mut MutexGuard<FrontierFileSystem>,
    ) -> Result<()> {
        let total_leaf_indexes = self.0.leaf_block_count()?;
        let mut inused_leaf_indexes = total_leaf_indexes;
        let mut fentry = Fentry::empty();
        'outter: for leaf_index in (0..total_leaf_indexes).rev() {
            for hash_index in 0..HASH_GROUP_COUNT {
                for item_index in 0..HASH_GROUP_ITEM_COUNT {
                    let start_offset =
                        Self::cal_fentry_start_offset(leaf_index, hash_index, item_index);
                    self.read_child(&mut fentry, start_offset)?;
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
        self.0.modify_disk_inode(|disk_inode| {
            self.0.to_byte_size(
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
            let start_offset = Self::cal_fheader_start_offset(inused_leaf_index);
            let mut founded = false;
            self.read_child(&mut fheader, start_offset)?;
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
            self.write_child(&mut fheader, start_offset)?;
            if clear_leaf_indexes.len() == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, sync::Arc, vec};

    use super::super::ffs::FS;
    use super::super::FileSystem;
    use super::*;

    use crate::block::{BlockDevice, MockBlockDevice};

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
    fn test_dir_create_and_get_and_remove_child_entry() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        // let disk_inode = DiskInode::get(0, 0, &device).unwrap();
        let fs = FS::initialize(15, 1, &device).unwrap();
        let inode = fs.root_inode();
        let dir = Directory::new(inode);
        // test get and delete entry from empty directory
        assert!(dir.get_child_entry("test").is_ok_and(|i| i.is_none()));
        assert!(dir
            .remove_child_entry("test")
            .is_err_and(|e| e.is_fnamedoesnotexist()));
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
        // test insert and delete entry into empty directory
        assert!(dir
            .create_child_entry("test", FileFlags::empty())
            .is_ok_and(|i| i.0.to_str() == "test"
                && i.1.is_valid()
                && !i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert!(dir.get_child_entry("other").is_ok_and(|i| i.is_none()));
        assert!(dir
            .get_child_entry("test")
            .unwrap()
            .is_some_and(|i| i.0.to_str() == "test"
                && i.1.is_valid()
                && !i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
        assert!(dir.remove_child_entry("test").is_ok());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
        // test insert entry into a non-empty directory
        assert!(dir
            .create_child_entry("other", FileFlags::IS_DIR)
            .is_ok_and(|i| i.0.to_str() == "other"
                && i.1.is_valid()
                && i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert!(dir.get_child_entry("test").is_ok_and(|i| i.is_none()));
        assert!(dir
            .get_child_entry("other")
            .unwrap()
            .is_some_and(|i| i.0.to_str() == "other"
                && i.1.is_valid()
                && i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert!(dir.0.leaf_block_count().is_ok_and(|i| *i == 1));
        // test insert same hash byte fentry into directory
        // number in list have the same prefix hash byte 9f with "test"
        // those number name files will be stored in the leaf indexes [0, 0, 0, 0, 1, 2, 3, 2, 3]
        for (index, x) in vec![35, 114, 249, 655, 803, 1084, 1500, 1764, 2167]
            .iter()
            .enumerate()
        {
            assert!(dir
                .create_child_entry(x.to_string().as_str(), FileFlags::empty())
                .is_ok_and(|i| i.0.to_str() == x.to_string().as_str()
                    && i.1.is_valid()
                    && !i.1.is_dir()
                    && i.1.inode_bitmap_index == (2 + index as u32)));
        }
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("803").unwrap().is_some());
        assert!(dir.remove_child_entry("803").is_ok());
        assert!(dir.get_child_entry("803").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("2167").unwrap().is_some());
        assert!(dir.remove_child_entry("2167").is_ok());
        assert!(dir.get_child_entry("2167").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("1764").unwrap().is_some());
        assert!(dir.remove_child_entry("1764").is_ok());
        assert!(dir.get_child_entry("1764").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("1500").unwrap().is_some());
        assert!(dir.remove_child_entry("1500").is_ok());
        assert!(dir.get_child_entry("1500").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 3);

        assert!(dir.get_child_entry("1084").unwrap().is_some());
        assert!(dir.remove_child_entry("1084").is_ok());
        assert!(dir.get_child_entry("1084").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
    }
}
