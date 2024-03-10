// @author:    olinex
// @time:      2023/11/03
#![cfg_attr(not(test), no_std)]
#![feature(thin_box)]

// self mods
pub mod block;
pub mod configs;
pub mod error;
pub mod layout;
pub mod vfs;

// use other mods
#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate alloc;

extern crate bit_field;
extern crate spin;

// reexports
pub use error::{FFSError, Result};
use vfs::FileFlags;

bitflags! {
    #[derive(Clone, Copy)]
    pub struct OpenFlags: u32 {
        const READABLE = 1 << 0;
        const WRITABLE = 1 << 1;
        const APPEND = 1 << 2;
        const CREATE = 1 << 3;
        const TRUNCATE = 1 << 4;
        const DIRECTORY = 1 << 5;
        const RW = Self::READABLE.bits() | Self::WRITABLE.bits();
        const RDIR = Self::READABLE.bits() | Self::DIRECTORY.bits();
        const RWDIR = Self::RW.bits() | Self::DIRECTORY.bits();
    }
}
impl OpenFlags {
    pub fn is_readable(&self) -> bool {
        self.contains(OpenFlags::READABLE)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(OpenFlags::WRITABLE)
    }

    pub fn is_append(&self) -> bool {
        self.contains(OpenFlags::APPEND)
    }

    pub fn is_create(&self) -> bool {
        self.contains(OpenFlags::CREATE)
    }

    pub fn is_truncate(&self) -> bool {
        self.contains(OpenFlags::TRUNCATE)
    }

    pub fn is_directory(&self) -> bool {
        self.contains(OpenFlags::DIRECTORY)
    }
}
impl From<FileFlags> for OpenFlags {
    fn from(flags: FileFlags) -> Self {
        let mut open_flags = OpenFlags::empty();
        if flags.is_dir() {
            open_flags |= OpenFlags::RWDIR;
        }
        open_flags
    }
}
impl From<OpenFlags> for FileFlags {
    fn from(flags: OpenFlags) -> Self {
        let mut file_flags = FileFlags::VALID;
        if flags.is_directory() {
            file_flags |= FileFlags::DIR;
        }
        file_flags
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

pub trait AsBytesMut {
    fn as_bytes_mut(&mut self) -> &mut [u8];
}
