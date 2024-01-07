// @author:    olinex
// @time:      2023/11/25

// self mods
mod ffs;
mod inode;

// use other mods

// use self mods

use alloc::boxed::Box;
use alloc::sync::Arc;
pub use ffs::*;
pub use inode::*;

use crate::block::BlockDevice;
use crate::Result;

pub enum InitMode {
    TotalBlocks(u32),
    TotalByteSize(u64),
}

pub trait FileSystem {
    fn root_inode(&self) -> Inode;
    fn initialize(mode: InitMode, iabc: u8, device: &Arc<dyn BlockDevice>) -> Result<Box<Self>>;
    fn open(device: &Arc<dyn BlockDevice>) -> Result<Box<Self>>;
}
