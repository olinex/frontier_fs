// @author:    olinex
// @time:      2023/11/03
#![no_std]

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

bitflags! {
    pub struct OpenFlags: u32 {
        const RDONLY = 0;
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const CREATE = 1 << 9;
        const TRUNC = 1 << 10;
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

pub trait AsBytesMut {
    fn as_bytes_mut(&mut self) -> &mut [u8];
}
