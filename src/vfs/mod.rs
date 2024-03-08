// @author:    olinex
// @time:      2023/11/25

// self mods
mod ffs;
mod inode;

// use other mods
use alloc::boxed::Box;
use alloc::sync::Arc;

// use self mods
use crate::block::BlockDeviceTracker;
use crate::Result;

// reexported
pub use ffs::*;
pub use inode::*;

pub enum InitMode {
    TotalBlocks(u32),
    TotalByteSize(u64),
}

pub trait FileSystem {
    fn root_inode(&self) -> Inode;
    fn initialize(mode: InitMode, iabc: u8, tracker: &Arc<BlockDeviceTracker>)
        -> Result<Box<Self>>;
    fn open(tracker: &Arc<BlockDeviceTracker>) -> Result<Box<Self>>;
}
