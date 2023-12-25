// @author:    olinex
// @time:      2023/11/25

// self mods
mod directory;
mod ffs;
mod inode;

// use other mods

// use self mods

use alloc::boxed::Box;
use alloc::sync::Arc;
pub use directory::*;
pub use ffs::*;
pub use inode::*;

use crate::block::BlockDevice;
use crate::Result;

pub trait FileSystem {
    fn root_inode(&self) -> Inode;
    fn initialize(total_blocks: u32, iabc: u8, device: &Arc<dyn BlockDevice>) -> Result<Box<Self>>;
    fn open(device: &Arc<dyn BlockDevice>) -> Result<Box<Self>>;
}
