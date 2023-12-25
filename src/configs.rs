// @author:    olinex
// @time:      2023/11/04

// self mods

// use other mods

// use self mods

pub const BLOCK_BYTE_SIZE: usize = 4096;
pub const BLOCK_BIT_SIZE: usize = BLOCK_BYTE_SIZE * 8;
pub const BLOCK_CACHE_COUNT: usize = 64;

/// Magic number for check the file system type
pub const FS_MAGIC: u32 = 0x3b800007;
