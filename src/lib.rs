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
        const EXEC = 1 << 0;
        const READ = 1 << 1;
        const WRITE = 1 << 2;
        const APPEND = 1 << 3;
        const CREATE = 1 << 4;
        const TRUNC = 1 << 5;
        const DIRECTORY = 1 << 6;
        const RW = Self::READ.bits() | Self::WRITE.bits();
        const RWX = Self::RW.bits() | Self::EXEC.bits();
        const RDIR = Self::READ.bits() | Self::DIRECTORY.bits();
        const RWDIR = Self::RW.bits() | Self::DIRECTORY.bits();
    }
}
impl OpenFlags {
    pub fn is_exec(&self) -> bool {
        self.contains(OpenFlags::EXEC)
    }

    pub fn is_read(&self) -> bool {
        self.contains(OpenFlags::READ)
    }

    pub fn is_write(&self) -> bool {
        self.contains(OpenFlags::WRITE)
    }

    pub fn is_append(&self) -> bool {
        self.contains(OpenFlags::APPEND)
    }

    pub fn is_create(&self) -> bool {
        self.contains(OpenFlags::CREATE)
    }

    pub fn is_trunc(&self) -> bool {
        self.contains(OpenFlags::TRUNC)
    }

    pub fn is_directory(&self) -> bool {
        self.contains(OpenFlags::DIRECTORY)
    }
}
impl From<FileFlags> for OpenFlags {
    fn from(flags: FileFlags) -> Self {
        let mut open_flags = OpenFlags::empty();
        if flags.is_executable() {
            open_flags |= OpenFlags::EXEC;
        }
        if flags.is_readable() {
            open_flags |= OpenFlags::READ;
        }
        if flags.is_writable() {
            open_flags |= OpenFlags::WRITE;
        }
        if flags.is_directory() {
            open_flags |= OpenFlags::DIRECTORY;
        }
        open_flags
    }
}
impl From<OpenFlags> for FileFlags {
    fn from(flags: OpenFlags) -> Self {
        let mut file_flags = FileFlags::VALID;
        if flags.is_exec() {
            file_flags |= FileFlags::EXECUTABLE;
        }
        if flags.is_read() {
            file_flags |= FileFlags::READABLE;
        }
        if flags.is_write() {
            file_flags |= FileFlags::WRITABLE;
        }
        if flags.is_directory() {
            file_flags |= FileFlags::DIRECTORY;
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
